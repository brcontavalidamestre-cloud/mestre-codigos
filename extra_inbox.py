import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from flask import abort, jsonify, request, session, send_from_directory

HOST = 'consulta-codigos-jr7z.onrender.com'
COOKIE = '__Secure-central-inbox'
LIFETIME = 8 * 3600


def register_extra_inbox(app, data_dir, scope, collect):
    path = os.path.join(data_dir, 'central_extra_inbox.sqlite3')

    def db():
        con = sqlite3.connect(path, timeout=5)
        con.execute('CREATE TABLE IF NOT EXISTS inbox (email TEXT PRIMARY KEY, owner TEXT NOT NULL, password TEXT NOT NULL, token TEXT, expires INTEGER NOT NULL DEFAULT 0)')
        return con

    def digest(value):
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    def central():
        if request.host.lower().split(':', 1)[0] != HOST:
            abort(404)

    def csrf():
        if request.headers.get('Origin') != 'https://' + HOST:
            abort(403)

    def current(con):
        token = request.cookies.get(COOKIE, '')
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            return None
        return con.execute('SELECT email, owner FROM inbox WHERE token=? AND expires>?', (digest(token), int(time.time()))).fetchone()

    @app.after_request
    def extra_inbox_headers(response):
        if request.path == '/bandeja-extra' or request.path.startswith(('/bandeja-extra/', '/api/admin/extra-inbox')):
            response.headers['Cache-Control'] = 'no-store'
            response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    @app.post('/api/admin/extra-inbox')
    def manage_extra_inbox():
        central()
        csrf()
        if not (session.get('logged_in') and session.get('username') == 'admin' and session.get('role') == 'admin'):
            return jsonify(success=False, message='Ação exclusiva do administrador principal.'), 403
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(success=False, message='Dados inválidos.'), 400
        address = str(data.get('email') or '').strip().lower()
        if len(address) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', address):
            return jsonify(success=False, message='Informe um e-mail válido.'), 400
        if data.get('revoke') is True:
            with closing(db()) as con, con:
                con.execute('DELETE FROM inbox WHERE email=?', (address,))
            return jsonify(success=True, message='Acesso extra removido.')
        owner = scope(address)
        if not owner:
            return jsonify(success=False, message='O endereço precisa estar autorizado, fora da quarentena e vinculado a um único cliente.'), 409
        password = secrets.token_urlsafe(24)
        with closing(db()) as con, con:
            con.execute('INSERT INTO inbox(email, owner, password) VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET owner=excluded.owner,password=excluded.password,token=NULL,expires=0', (address, owner, digest(password)))
        return jsonify(success=True, email=address, password=password, url='https://' + HOST + '/bandeja-extra'), 201

    @app.get('/bandeja-extra')
    def extra_inbox_page():
        central()
        return send_from_directory(app.static_folder, 'extra-inbox.html')

    @app.post('/bandeja-extra/login')
    def extra_inbox_login():
        central()
        csrf()
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(success=False, message='Dados inválidos.'), 400
        address = str(data.get('email') or '').strip().lower()
        password = str(data.get('password') or '').strip()
        if len(address) <= 254 and re.fullmatch(r'[A-Za-z0-9_-]{32}', password):
            with closing(db()) as con, con:
                row = con.execute('SELECT owner, password FROM inbox WHERE email=?', (address,)).fetchone()
                if row and hmac.compare_digest(row[1], digest(password)) and scope(address) == row[0]:
                    token = secrets.token_urlsafe(32)
                    updated = con.execute('UPDATE inbox SET token=?, expires=? WHERE email=? AND password=?', (digest(token), int(time.time()) + LIFETIME, address, row[1])).rowcount
                    if updated:
                        response = jsonify(success=True)
                        response.set_cookie(COOKIE, token, max_age=LIFETIME, secure=True, httponly=True, samesite='Strict', path='/bandeja-extra')
                        return response
        return jsonify(success=False, message='Não foi possível entrar. Confira o endereço completo e use a senha gerada na Caixa de Entrada Admin para este e-mail.'), 401

    @app.post('/bandeja-extra/logout')
    def extra_inbox_logout():
        central()
        csrf()
        with closing(db()) as con, con:
            token = request.cookies.get(COOKIE, '')
            if re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
                con.execute('UPDATE inbox SET token=NULL, expires=0 WHERE token=?', (digest(token),))
        response = jsonify(success=True)
        response.delete_cookie(COOKIE, path='/bandeja-extra', secure=True, httponly=True, samesite='Strict')
        return response

    @app.get('/bandeja-extra/messages')
    def extra_inbox_messages():
        central()
        with closing(db()) as con:
            user = current(con)
        if not user or scope(user[0]) != user[1]:
            return jsonify(success=False, message='Entre para ver a sua bandeja.'), 401
        address, owner = user
        if request.args.get('status') == '1':
            return jsonify(success=True, email=address)
        items, errors = collect(owner, address)
        now = time.time()
        safe = [dict(platform=row['platform'], date_ts=row['date_ts']) for row in items
                if row.get('email') == address and row.get('recipients') == [address] and now - 900 <= row.get('date_ts', 0) <= now]
        with closing(db()) as con:
            if current(con) != user or scope(address) != owner:
                return jsonify(success=False, message='O acesso foi encerrado.'), 401
        return jsonify(success=True, email=address, items=safe, partial=bool(errors))
