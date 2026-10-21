"""Central-only stock view: authoritative store state plus durable paid-sale history.
This module never writes stock.json, never changes payment or delivery code, and
never makes a historical delivery available for sale.
"""
import copy
import hashlib
import http.cookiejar
import json
import os
import re
import sqlite3
import threading
import time
import urllib.request
from collections import defaultdict, deque
from flask import jsonify, request, session

CENTRAL_HOST = 'consulta-codigos-jr7z.onrender.com'
ORDER_FIELDS = ('id', 'status', 'product_id', 'paid_at', 'created_at', 'delivered_email',
                'delivered_password', 'delivered_note', 'assigned_user', 'assigned_user_name',
                'buyer_username', 'buyer_user_name', 'customer_email', 'customer_name')


def timestamp(value):
    try:
        return max(0, int(float(value or 0)))
    except (ValueError, TypeError, OverflowError):
        return 0


def identity(item):
    return (str(item.get('email') or '').strip().lower(),
            str(item.get('password') or '').strip(), str(item.get('note') or '').strip())


def sold_item(order):
    oid = str(order.get('id') or '')
    sold_at = timestamp(order.get('paid_at'))
    return {'id': 'sale-' + hashlib.sha256(oid.encode()).hexdigest()[:24],
            'email': str(order.get('delivered_email') or '').strip().lower(),
            'password': str(order.get('delivered_password') or ''),
            'note': str(order.get('delivered_note') or ''), 'used': True,
            'used_at': sold_at or None, 'sold_at': sold_at or None,
            'order_id': oid, 'delivered_to': order.get('customer_email') or '',
            'assigned_user': order.get('assigned_user') or order.get('buyer_username') or '',
            'assigned_user_name': order.get('assigned_user_name') or order.get('buyer_user_name') or '',
            'history_readonly': True, 'recovered_from_order': True}


def build_stock_view(product_id, local_items, remote_items, orders, fresh=True):
    """Pure reconciliation: one retained row per paid delivery, no stock mutation."""
    paid = [o for o in orders if isinstance(o, dict) and str(o.get('product_id')) == str(product_id)
            and o.get('status') == 'paid' and o.get('id') and o.get('delivered_email')]
    by_order = {str(o['id']): o for o in paid}
    by_credentials = defaultdict(list)
    for order in paid:
        key = (str(order.get('delivered_email') or '').strip().lower(), str(order.get('delivered_password') or '').strip())
        by_credentials[key].append(order)
    for values in by_credentials.values():
        values.sort(key=lambda o: timestamp(o.get('paid_at')), reverse=True)
    local = defaultdict(deque)
    for item in local_items:
        if isinstance(item, dict):
            local[identity(item)].append(item)
    represented, result = set(), []
    for raw in remote_items:
        if not isinstance(raw, dict):
            continue
        item = copy.deepcopy(raw)
        candidates = local.get(identity(item))
        original = candidates.popleft() if candidates else None
        item['remote_item_id'] = item.get('id')
        if original:
            item['id'] = original.get('id')
        else:
            item['history_readonly'] = True
        order = by_order.get(str(item.get('order_id') or ''))
        if item.get('used') and not order:
            key = identity(item)[:2]
            for candidate in by_credentials.get(key, []):
                if str(candidate['id']) not in represented:
                    order = candidate
                    break
        if order:
            sale = sold_item(order)
            item.update({k: v for k, v in sale.items() if k != 'id'})
            item['recovered_from_order'] = False
            # Prefer real payment time; keep a recorded stock-use time if absent.
            item['sold_at'] = timestamp(order.get('paid_at')) or timestamp(raw.get('used_at')) or None
            item['used_at'] = item['sold_at']
            represented.add(str(order['id']))
        elif item.get('used'):
            item['history_readonly'] = True
            item['sold_at'] = timestamp(item.get('used_at')) or None
        else:
            item['sync_uncertain'] = not fresh
        result.append(item)
    # Keep local-only entries visible, but never claim they are available in the store.
    for remaining in local.values():
        for original in remaining:
            item = copy.deepcopy(original)
            if item.get('used'):
                item['history_readonly'] = True
                item['sold_at'] = timestamp(item.get('used_at')) or None
                order = by_order.get(str(item.get('order_id') or ''))
                if order:
                    item['sold_at'] = timestamp(order.get('paid_at')) or item['sold_at']
                    item['used_at'] = item['sold_at']
                    represented.add(str(order['id']))
            else:
                item['sync_uncertain'] = True
                item['not_in_store'] = fresh
            result.append(item)
    # Missing/deleted sold rows are recovered from paid orders, never as available stock.
    for order in paid:
        if str(order['id']) not in represented:
            result.append(sold_item(order))
    result.sort(key=lambda i: (0 if i.get('used') else 1, -timestamp(i.get('sold_at') or i.get('used_at')), str(i.get('email') or '').lower()))
    return result


class StoreSnapshot:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip('/')
        self.username, self.password = username, password
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.lock = threading.Lock()
        self.cached = None
        self.next_check = 0
        self.failed = False

    def request_json(self, path, body=None):
        req = urllib.request.Request(self.base_url + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Content-Type': 'application/json', 'User-Agent': 'central-stock-ledger/1.0'})
        with self.opener.open(req, timeout=12) as response:
            if 'application/json' not in response.headers.get('Content-Type', ''):
                raise ValueError('Store session expired')
            return json.load(response)

    def get(self):
        with self.lock:
            now = time.monotonic()
            if self.cached is not None and now < self.next_check and not self.failed:
                return copy.deepcopy(self.cached)
            if now < self.next_check:
                raise ValueError('Store temporarily unavailable')
            try:
                try:
                    payload = self.request_json('/api/admin/backup/export')
                except Exception:
                    if not self.username or not self.password:
                        raise ValueError('Stock synchronization credentials not configured')
                    login = self.request_json('/api/auth/login', {'username': self.username, 'password': self.password})
                    if not login.get('success'):
                        raise ValueError('Store authentication failed')
                    payload = self.request_json('/api/admin/backup/export')
                data = payload.get('data')
                if not isinstance(data, dict) or not isinstance(data.get('stock'), dict) or not isinstance(data.get('orders'), (list, dict)):
                    raise ValueError('Invalid store snapshot')
                # Discard users, licenses, subscriptions and payment credentials.
                stock = data['stock']
                orders = data['orders']
                if isinstance(orders, dict):
                    orders = list(orders.values())
                orders = [{k: o.get(k) for k in ORDER_FIELDS} for o in orders if isinstance(o, dict)
                          and o.get('status') == 'paid' and o.get('id') and o.get('delivered_email')]
                self.cached = {'stock': stock, 'orders': orders, 'updated_at': int(time.time())}
                self.next_check = time.monotonic() + 5
                self.failed = False
                return copy.deepcopy(self.cached)
            except Exception:
                self.next_check = time.monotonic() + 5
                self.failed = True
                raise


class SalesArchive:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def connect(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=15)
        conn.execute('CREATE TABLE IF NOT EXISTS sales (id TEXT PRIMARY KEY,payload TEXT NOT NULL)')
        conn.execute('CREATE TABLE IF NOT EXISTS snapshot (id INTEGER PRIMARY KEY,payload TEXT NOT NULL,updated_at INTEGER NOT NULL)')
        conn.commit()
        os.chmod(self.path, 0o600)
        return conn

    def capture(self, snapshot):
        with self.lock:
            conn = self.connect()
            try:
                with conn:
                    for order in snapshot['orders']:
                        conn.execute('INSERT INTO sales(id,payload) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload',
                                     (str(order['id']), json.dumps(order, ensure_ascii=False)))
                    conn.execute('INSERT INTO snapshot(id,payload,updated_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at',
                                 (json.dumps(snapshot['stock'], ensure_ascii=False), snapshot['updated_at']))
            finally:
                conn.close()

    def read(self):
        conn = self.connect()
        try:
            orders = [json.loads(r[0]) for r in conn.execute('SELECT payload FROM sales')]
            row = conn.execute('SELECT payload,updated_at FROM snapshot WHERE id=1').fetchone()
            return {'orders': orders, 'stock': json.loads(row[0]) if row else {}, 'updated_at': row[1] if row else 0}
        finally:
            conn.close()


def register_stock_ledger(app, data_dir, load_stock, load_products, store_url):
    source = StoreSnapshot(store_url, os.environ.get('LOJA_STOCK_SYNC_USERNAME', ''), os.environ.get('LOJA_STOCK_SYNC_PASSWORD', ''))
    archive = SalesArchive(os.path.join(data_dir, 'store_sales_archive.sqlite3'))

    @app.before_request
    def central_stock_history():
        if request.host.lower().split(':', 1)[0] != CENTRAL_HOST or request.method != 'GET':
            return None
        match = re.fullmatch(r'/api/admin/loja/estoque/([^/]+)', request.path)
        products_request = request.path == '/api/admin/loja/produtos'
        if not match and not products_request:
            return None
        if not session.get('logged_in') or session.get('role') != 'admin':
            return None  # Preserve the existing route's authentication.
        warning = ''
        try:
            snapshot = source.get()
            archive.capture(snapshot)
            fresh = True
        except Exception:
            fresh = False
            warning = 'Não foi possível atualizar a loja agora. Exibindo o último histórico salvo; a disponibilidade pode estar desatualizada.'
        saved = archive.read()
        local = load_stock()
        def view(pid):
            return build_stock_view(pid, local.get(pid, []), saved['stock'].get(pid, []), saved['orders'], fresh)
        metadata = {'stock_source': 'lojamestre', 'as_of': saved['updated_at'], 'sync_warning': warning}
        if match:
            items = view(match.group(1))
            result = {'success': True, 'items': items, **metadata}
        else:
            products = copy.deepcopy(load_products())
            for product in products:
                items = view(product['id'])
                product['available'] = sum(1 for item in items if not item.get('used') and not item.get('sync_uncertain'))
                product['delivered'] = sum(1 for item in items if item.get('used'))
                product['total'] = len(items)
            result = {'success': True, 'products': products, **metadata}
        response = jsonify(result)
        response.headers['Cache-Control'] = 'no-store'
        return response
