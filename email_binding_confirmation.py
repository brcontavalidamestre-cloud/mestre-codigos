import hashlib
import os
import re
import secrets
import smtplib
import ssl
import time
from email.message import EmailMessage

from flask import abort, jsonify, request, session

from email_delegation import HOST, norm


def register_binding_confirmation(app, store, load_users, load_subs, save_subs, quarantine):
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def send(address, token):
        server = os.environ.get('BINDING_SMTP_SERVER')
        username = os.environ.get('BINDING_SMTP_USER')
        password = os.environ.get('BINDING_SMTP_PASS')
        if not server or not username or not password:
            raise RuntimeError('SMTP not configured')
        msg = EmailMessage()
        msg['From'], msg['To'], msg['Subject'] = username, address, 'Confirme seu endereço — Central dos Códigos'
        msg.set_content(f'Abra https://{HOST}/confirmar-email#{token} e entre na conta do cliente para confirmar. O pedido vence em 30 minutos. Se não reconhecer, ignore esta mensagem.')
        context = ssl.create_default_context()
        port = int(os.environ.get('BINDING_SMTP_PORT', '465'))
        if port == 465:
            with smtplib.SMTP_SSL(server, port, timeout=8, context=context) as smtp:
                smtp.login(username, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(server, port, timeout=8) as smtp:
                smtp.starttls(context=context)
                smtp.login(username, password)
                smtp.send_message(msg)

    def prepare(admin, client, emails, partial=False):
        now = int(time.time())
        groups = {key: [] for key in ('registered', 'blocked', 'already_pending', 'limited', 'send_failed', 'confirmation_sent')}
        if not partial and len(emails) > 5:
            return jsonify(success=False, message='Envie até 5 novos e-mails por tentativa.'), 400
        with store.connect() as conn:
            conn.execute('DELETE FROM pending_email_bindings WHERE expires<=?', (now,))
            registered = {norm(s.get('email')) for s in load_subs() if isinstance(s, dict)} | set(store.permissions())
            pending = {row['email'] for row in conn.execute('SELECT email FROM pending_email_bindings')}
            capacity = max(0, min(5, 10 - conn.execute('SELECT COUNT(*) FROM pending_email_bindings WHERE admin=?', (admin,)).fetchone()[0]))
            jobs = []
            for address in emails:
                if quarantine.is_blocked(address):
                    groups['blocked'].append(address)
                elif address in registered:
                    groups['registered'].append(address)
                elif address in pending:
                    groups['already_pending'].append(address)
                elif len(jobs) >= capacity:
                    groups['limited'].append(address)
                else:
                    jobs.append((address, secrets.token_urlsafe(32)))
            if not partial and len(jobs) != len(emails):
                status = 409 if any(groups[key] for key in ('registered', 'blocked', 'already_pending')) else 429
                return jsonify(success=False, message='Um dos endereços já está cadastrado, bloqueado ou pendente.' if status == 409 else 'Limite de pedidos pendentes atingido.'), status
            conn.executemany('INSERT INTO pending_email_bindings VALUES(?,?,?,?,?)', [(a, admin, client, digest(t), now+1800) for a,t in jobs])
            conn.commit()
        failed = []
        for address, token in jobs:
            try:
                app.config.get('BINDING_CONFIRMATION_SEND', send)(address, token)
            except Exception:
                failed.append(address)
        if failed:
            with store.connect() as conn:
                conn.executemany('DELETE FROM pending_email_bindings WHERE email=? AND admin=?', [(a, admin) for a in failed])
                conn.commit()
        groups['send_failed'] = failed
        groups['confirmation_sent'] = [address for address, _ in jobs if address not in failed]
        sent = len(groups['confirmation_sent'])
        message = (f'{sent} confirmação(ões) enviada(s). O vínculo só será ativado após a confirmação.' if sent
                   else 'Nenhuma confirmação nova foi enviada.')
        payload = dict(success=bool(sent), pending=sent, skipped=len(failed), message=message)
        if partial:
            payload['batch_results'] = groups
        return jsonify(payload), 202 if sent else (503 if failed else 409)

    app.config['EMAIL_POOL_PREPARE_CONFIRMATION'] = prepare

    @app.get('/confirmar-email')
    def binding_confirmation_page():
        if request.host.lower().split(':',1)[0] != HOST:
            abort(404)
        response = app.send_static_file('confirmar-email.html')
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    @app.post('/api/confirmar-email')
    def confirm_binding():
        if request.host.lower().split(':',1)[0] != HOST:
            abort(404)
        if request.headers.get('Origin') not in (None, 'https://'+HOST):
            abort(403)
        client = norm(session.get('username'))
        if not session.get('logged_in') or session.get('role') != 'client':
            return jsonify(success=False, message='Entre na conta do cliente para confirmar.'), 401
        data = request.get_json(silent=True) or {}
        token = data.get('token', '') if isinstance(data, dict) else ''
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            abort(404)
        with store.serialized(), store.connect() as conn:
            record = conn.execute('SELECT * FROM pending_email_bindings WHERE digest=? AND client=? AND expires>?', (digest(token),client,time.time())).fetchone()
            if not record:
                return jsonify(success=False, message='Confirmação inválida, vencida ou de outra conta.'), 404
            address, admin = record['email'], record['admin']
            users = load_users()
            target = users.get(client, {})
            subs = load_subs()
            if (users.get(admin, {}).get('role') != 'admin' or target.get('role') != 'client'
                    or norm(target.get('created_by')) != admin or quarantine.is_blocked(address)
                    or address in store.permissions()
                    or address in app.config.get('EMAIL_REGISTRATION_LINKS', set)()
                    or any(norm(s.get('email')) == address for s in subs if isinstance(s, dict))):
                return jsonify(success=False, message='Não é possível confirmar este vínculo.'), 409
            now = int(time.time())
            subs.append(dict(email=address, assigned_user=client, assigned_user_name=target.get('name') or client,
                             created_at=now,start_at=now,expires_at=now+3650*86400,dur_days=3650,show_in_panel=False,
                             plataforma='Conta vinculada',valor=0,verified_inbox_only=True, self_verified_binding=True))
            if save_subs(subs) is False:
                conn.rollback()
                return jsonify(success=False, message='Não foi possível salvar; tente novamente.'), 503
            conn.execute('DELETE FROM pending_email_bindings WHERE email=?', (address,))
            conn.commit()
        invalidate = app.config.get('EMAIL_POOL_BINDINGS_CHANGED')
        if invalidate:
            invalidate({client})
        return jsonify(success=True, message='E-mail confirmado e vinculado à sua conta.')
