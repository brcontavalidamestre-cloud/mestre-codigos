"""Paid-sale archive and durable Telegram outbox for Loja Mestre only.
No passwords, Pix payloads, receipt tokens or code-access links leave the store.
"""
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from flask import Blueprint, abort, jsonify, redirect, request, session, send_from_directory

HOST='lojamestre.onrender.com'
FIELDS=('id','product_id','product_name','price','customer_name','customer_email','customer_phone','delivered_email','paid_at','created_at')


class TelegramFailure(Exception):
    def __init__(self,message,retry_after=30):
        super().__init__(message);self.retry_after=retry_after


def send_message(text):
    import requests
    token=os.environ.get('TELEGRAM_BOT_TOKEN','');chat=os.environ.get('TELEGRAM_CHAT_ID','')
    if not token or not re.fullmatch(r'-?\d+',chat):
        raise TelegramFailure('Bot ou destino ainda não configurado.',120)
    try:
        response=requests.post('https://api.telegram.org/bot'+token+'/sendMessage',json={
            'chat_id':chat,'text':str(text)[:4000], 'protect_content':True,
            'link_preview_options':{'is_disabled':True}},timeout=(5,15))
        data=response.json()
    except Exception:
        # Never propagate exception strings that may contain the token URL.
        raise TelegramFailure('Falha de conexão com o Telegram. Nova tentativa agendada.',60) from None
    if not data.get('ok'):
        code=data.get('error_code',response.status_code)
        if code==401:message='Credencial do bot recusada pelo Telegram.'
        elif code==403:message='O Telegram recusou o destino. Inicie o bot e verifique se ele não foi bloqueado.'
        elif code==429:message='Limite temporário do Telegram. Nova tentativa agendada.'
        else:message='O Telegram não aceitou o aviso (código '+str(code)+').'
        retry=int((data.get('parameters') or {}).get('retry_after') or 60)
        raise TelegramFailure(message,max(15,min(retry,3600)))
    return str(data['result']['message_id'])


def payment_time(value):
    try:return max(0,int(float(value or 0)))
    except (ValueError,TypeError,OverflowError):return 0


def paid_sale(order):
    sale={key:order.get(key) for key in FIELDS}
    sale['id']=str(order.get('id') or '')[:120]
    sale['paid_at']=payment_time(order.get('paid_at')) or None
    sale['delivery_status']='Entregue' if order.get('delivered_email') and order.get('delivered_password') else 'Aguardando entrega'
    return sale


def format_sale(sale):
    def clean(value,limit=120):return str(value or 'Não informado').replace('\n',' ').replace('\r',' ')[:limit]
    try:amount=Decimal(str(sale.get('price') or 0));amount=amount if amount.is_finite() else Decimal(0)
    except InvalidOperation:amount=Decimal(0)
    price=f'{amount:.2f}'.replace('.',',')
    timestamp=payment_time(sale.get('paid_at'))
    when=datetime.fromtimestamp(timestamp,timezone(timedelta(hours=-3))).strftime('%d/%m/%Y %H:%M:%S') if timestamp else 'Data não informada'
    return '\n'.join(['🛍️ NOVA COMPRA PAGA — LOJA MESTRE',
        'Pedido: '+clean(sale.get('id')),'Produto: '+clean(sale.get('product_name')),
        'Valor: R$ '+price,'Cliente: '+clean(sale.get('customer_name')),
        'Email do comprador: '+clean(sale.get('customer_email')),
        'Contato: '+clean(sale.get('customer_phone')),
        'Conta entregue: '+clean(sale.get('delivered_email')),
        'Pagamento confirmado: '+when+' (Brasília)',
        'Entrega: '+clean(sale.get('delivery_status')),
        'Histórico: https://lojamestre.onrender.com/admin/telegram-vendas'])


class TelegramSales:
    def __init__(self,data_dir,load_orders,sender=send_message,clock=time.time):
        self.path=os.path.join(data_dir,'telegram_sales.sqlite3');self.load_orders=load_orders
        self.sender=sender;self.clock=clock;self.wake=threading.Event();self.start_lock=threading.Lock();self.started=False

    @contextmanager
    def connect(self):
        os.makedirs(os.path.dirname(self.path),exist_ok=True)
        conn=sqlite3.connect(self.path,timeout=20);conn.row_factory=sqlite3.Row
        try:
            conn.executescript('''CREATE TABLE IF NOT EXISTS sales(
order_id TEXT PRIMARY KEY,payload TEXT NOT NULL,paid_at INTEGER,state TEXT NOT NULL,
attempts INTEGER NOT NULL DEFAULT 0,next_try REAL NOT NULL DEFAULT 0,
lease_until REAL NOT NULL DEFAULT 0,lease_key TEXT NOT NULL DEFAULT '',
telegram_message_id TEXT,sent_at REAL,last_error TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);''')
            os.chmod(self.path,0o600)
            yield conn
        finally:conn.close()

    def capture(self,orders):
        start=payment_time(os.environ.get('TELEGRAM_START_AT'))
        with self.connect() as conn:
            with conn:
                for order in orders:
                    if not isinstance(order,dict) or order.get('status')!='paid' or not order.get('id'):continue
                    sale=paid_sale(order);timestamp=sale['paid_at']
                    state='pending' if start and timestamp and timestamp>=start else 'historical'
                    # INSERT is idempotent. Updates never re-queue an already sent sale.
                    conn.execute('INSERT INTO sales(order_id,payload,paid_at,state) VALUES(?,?,?,?) ON CONFLICT(order_id) DO UPDATE SET payload=excluded.payload,paid_at=excluded.paid_at',
                                 (sale['id'],json.dumps(sale,ensure_ascii=False),timestamp,state))
        self.wake.set()

    def enabled(self):
        configured=bool(os.environ.get('TELEGRAM_BOT_TOKEN') and re.fullmatch(r'-?\d+',os.environ.get('TELEGRAM_CHAT_ID','')))
        if not configured:return False
        with self.connect() as conn:
            row=conn.execute("SELECT value FROM settings WHERE key='enabled'").fetchone()
        return row['value']=='1' if row else os.environ.get('TELEGRAM_NOTIFICATIONS_ENABLED','').lower() in ('1','true','yes')

    def set_enabled(self,value):
        with self.connect() as conn:
            with conn:conn.execute("INSERT INTO settings VALUES('enabled',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",('1' if value else '0',))
        self.wake.set()

    def claim(self):
        now=self.clock();key=secrets.token_hex(16)
        with self.connect() as conn:
            with conn:
                conn.execute('BEGIN IMMEDIATE')
                row=conn.execute("SELECT * FROM sales WHERE state IN ('pending','retry','sending') AND next_try<=? AND lease_until<=? ORDER BY paid_at,order_id LIMIT 1",(now,now)).fetchone()
                if not row:return None
                conn.execute("UPDATE sales SET state='sending',attempts=attempts+1,lease_key=?,lease_until=? WHERE order_id=?",(key,now+90,row['order_id']))
                return dict(row,lease_key=key,attempts=row['attempts']+1)

    def deliver_one(self):
        if not self.enabled():return False
        row=self.claim()
        if not row:return False
        oid=row['order_id'];now=self.clock()
        # Check current payment before sending; the archive itself is retained.
        order=next((o for o in self.load_orders() if isinstance(o,dict) and str(o.get('id'))==oid),None)
        if order and order.get('status')!='paid':
            with self.connect() as conn:
                with conn:conn.execute("UPDATE sales SET state='cancelled',lease_until=0,last_error='Pagamento não está mais confirmado.' WHERE order_id=? AND lease_key=?",(oid,row['lease_key']))
            return True
        try:
            mid=self.sender(format_sale(json.loads(row['payload'])))
        except Exception as error:
            safe=str(error) if isinstance(error,TelegramFailure) else 'Falha no envio. Nova tentativa agendada.'
            delay=max(getattr(error,'retry_after',30),min(3600,15*(2**min(row['attempts'],8))))
            with self.connect() as conn:
                with conn:conn.execute("UPDATE sales SET state='retry',next_try=?,lease_until=0,last_error=? WHERE order_id=? AND lease_key=?",(now+delay,safe[:300],oid,row['lease_key']))
            return True
        with self.connect() as conn:
            with conn:conn.execute("UPDATE sales SET state='sent',telegram_message_id=?,sent_at=?,lease_until=0,last_error='' WHERE order_id=? AND lease_key=?",(mid,self.clock(),oid,row['lease_key']))
        return True

    def status(self,query='',offset=0,limit=50):
        query=str(query).strip().lower()[:120]
        with self.connect() as conn:
            rows=list(conn.execute('SELECT * FROM sales ORDER BY COALESCE(paid_at,0) DESC,order_id'))
        counts={};items=[]
        for row in rows:
            counts[row['state']]=counts.get(row['state'],0)+1;sale=json.loads(row['payload'])
            searchable=' '.join(str(sale.get(k) or '') for k in ('id','customer_name','customer_email','product_name','delivered_email')).lower()
            if query and query not in searchable:continue
            items.append(dict(sale,notification_status=row['state'],attempts=row['attempts'],sent_at=row['sent_at'],last_error=row['last_error']))
        username=os.environ.get('TELEGRAM_BOT_USERNAME','lojamestre_vendas_bot')
        username=username if re.fullmatch(r'[A-Za-z0-9_]{5,32}',username) else ''
        return dict(enabled=self.enabled(),bot_configured=bool(os.environ.get('TELEGRAM_BOT_TOKEN')),
                    destination_configured=bool(os.environ.get('TELEGRAM_CHAT_ID')),bot_username=username,
                    counts=counts,total=len(items),items=items[offset:offset+limit],offset=offset,limit=limit,
                    start_at=payment_time(os.environ.get('TELEGRAM_START_AT')))

    def start(self):
        with self.start_lock:
            if self.started:return
            self.started=True
            threading.Thread(target=self.run,name='telegram-paid-sales',daemon=True).start()

    def run(self):
        while True:
            try:
                self.capture(self.load_orders())
                for _ in range(10):
                    if not self.deliver_one():break
                    time.sleep(1.1)
            except Exception:
                # Delivery and customer checkout never depend on this thread.
                pass
            self.wake.clear();self.wake.wait(20)


def register_telegram_sales(app,data_dir,load_orders):
    service=TelegramSales(data_dir,load_orders);bp=Blueprint('telegram_sales',__name__)
    @bp.before_request
    def admin_guard():
        if request.host.lower().split(':',1)[0]!=HOST:abort(404)
        if not session.get('logged_in'):
            if request.path=='/admin/telegram-vendas':return redirect('/login')
            return jsonify(success=False,message='Não autenticado.'),401
        if session.get('role')!='admin' or session.get('username')!='admin':
            return jsonify(success=False,message='Somente o admin principal pode gerenciar os avisos.'),403
        if request.method!='GET' and request.headers.get('Origin') not in (None,'https://'+HOST):
            return jsonify(success=False,message='Origem não permitida.'),403
    @bp.after_request
    def privacy(response):
        response.headers['Cache-Control']='no-store';response.headers['X-Robots-Tag']='noindex, nofollow';response.headers['Referrer-Policy']='no-referrer'
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        return response
    @bp.get('/admin/telegram-vendas')
    def page():return send_from_directory(app.static_folder,'telegram-sales.html')
    @bp.get('/api/admin/telegram-sales')
    def status():
        service.capture(load_orders())
        try:offset=max(0,int(request.args.get('offset',0)))
        except (ValueError,TypeError):offset=0
        return jsonify(success=True,**service.status(request.args.get('q',''),offset))
    @bp.post('/api/admin/telegram-sales/toggle')
    def toggle():
        data=request.get_json(silent=True) or {};value=data.get('enabled') if isinstance(data,dict) else None
        if not isinstance(value,bool):return jsonify(success=False,message='Informe ativar ou pausar.'),400
        if value and not (os.environ.get('TELEGRAM_BOT_TOKEN') and os.environ.get('TELEGRAM_CHAT_ID')):
            return jsonify(success=False,message='O bot e o destino precisam ser configurados primeiro.'),400
        service.set_enabled(value);return jsonify(success=True,message='Avisos ativados.' if value else 'Avisos pausados. As vendas continuam registradas.')
    @bp.post('/api/admin/telegram-sales/test')
    def test():
        try:send_message('✅ TESTE DE CONEXÃO — LOJA MESTRE\nA conexão com o Telegram foi verificada. Este aviso não representa uma venda.\nNovas compras com pagamento confirmado terão avisos automáticos quando o envio estiver ativado.')
        except TelegramFailure as error:return jsonify(success=False,message=str(error)),502
        return jsonify(success=True,message='Mensagem de teste enviada ao Telegram.')
    app.register_blueprint(bp)
    # With no bot configured the UI is still available, but no background
    # network activity occurs. Reconciliation is enabled with the integration.
    if os.environ.get('TELEGRAM_BOT_TOKEN') and os.environ.get('TELEGRAM_CHAT_ID'):service.start()
    return service
