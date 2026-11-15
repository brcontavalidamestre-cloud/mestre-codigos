"""Central-only email quarantine. Persistent, shared by all worker processes."""
import hashlib
import hmac
import os
import re
import sqlite3
import time
from functools import wraps
from flask import Blueprint, abort, has_request_context, jsonify, redirect, request, session, send_from_directory

HOST = 'consulta-codigos-jr7z.onrender.com'
MESSAGE = 'Esse email está na lista que não pode receber códigos.'
CONSULT_PATHS = {'/api/get-code', '/api/admin/get-code', '/api/verify-reset-pin',
                 '/api/netflix-link/code', '/api/netflix-link/access'}
INBOX_PATHS = {'/api/live-inbox/messages', '/api/admin/live-inbox/messages'}


class QuarantineStore:
    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, 'quarantine.sqlite3')

    def connect(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute('CREATE TABLE IF NOT EXISTS blocked_emails (email TEXT PRIMARY KEY,created_at INTEGER NOT NULL,created_by TEXT NOT NULL)')
        conn.commit()
        os.chmod(self.path, 0o600)
        return conn

    def entries(self):
        conn = self.connect()
        try:
            return [dict(row) for row in conn.execute('SELECT email,created_at,created_by FROM blocked_emails ORDER BY created_at DESC,email')]
        finally:
            conn.close()

    def emails(self):
        return {row['email'] for row in self.entries()}

    @staticmethod
    def matches(email, blocked):
        email = str(email or '').strip().lower()
        if email in blocked:
            return True
        local, sep, domain = email.partition('@')
        # Quarantining a base address also blocks its +tag aliases, but one
        # specific alias never blocks unrelated aliases of the same account.
        return bool(sep and '+' in local and local.split('+', 1)[0] + '@' + domain in blocked)

    def is_blocked(self, email):
        if not has_request_context() or request.host.lower().split(':', 1)[0] != HOST:
            return False
        return self.matches(email, self.emails())

    def add(self, emails, username):
        conn = self.connect()
        try:
            with conn:
                before = conn.total_changes
                conn.executemany('INSERT OR IGNORE INTO blocked_emails(email,created_at,created_by) VALUES(?,?,?)',
                                 [(email, int(time.time()), username) for email in emails])
                return conn.total_changes - before
        finally:
            conn.close()

    def remove(self, email):
        conn = self.connect()
        try:
            with conn:
                return conn.execute('DELETE FROM blocked_emails WHERE email=?', (email,)).rowcount > 0
        finally:
            conn.close()


def register_quarantine(app, store, data_dir, pending_resets, load_subscriptions=None, save_subscriptions=None, load_users=None, remote_search=None):
    from quarantine_registry import QuarantineRegistry
    registry = QuarantineRegistry(store, data_dir, load_subscriptions, save_subscriptions, load_users, remote_search)
    bp = Blueprint('quarantine', __name__)

    def host_allowed():
        return request.host.lower().split(':', 1)[0] == HOST

    def admin_only(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not host_allowed():
                abort(404)
            if not session.get('logged_in'):
                if request.path == '/admin/quarentena':
                    return redirect('/login')
                return jsonify(success=False, message='Não autenticado.'), 401
            if session.get('username') != 'admin' or session.get('role') != 'admin':
                return jsonify(success=False, message='Somente o administrador principal pode gerenciar a quarentena.'), 403
            if request.method != 'GET' and request.headers.get('Origin') not in (None, 'https://' + HOST):
                abort(403)
            return fn(*args, **kwargs)
        return wrapped

    @bp.before_request
    def check_host():
        if not host_allowed():
            abort(404)

    @bp.after_request
    def private(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Robots-Tag'] = 'noindex, nofollow'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        return response

    @bp.get('/api/internal/quarantine')
    def shared_quarantine():
        expected = os.environ.get('QUARANTINE_SYNC_TOKEN', '')
        received = request.headers.get('X-Quarantine-Token', '')
        if not expected or not hmac.compare_digest(expected, received):
            return jsonify(success=False, message='Acesso não autorizado.'), 403
        return jsonify(success=True, emails=sorted(store.emails()))

    @bp.get('/admin/quarentena')
    @admin_only
    def page():
        return send_from_directory(app.static_folder, 'quarantine.html')

    @bp.get('/api/admin/quarantine/search')
    @admin_only
    def search_registrations():
        query = str(request.args.get('q') or '').strip()[:254]
        return jsonify(success=True, **registry.search_all(query))

    @bp.route('/api/admin/quarantine', methods=['GET', 'POST'])
    @admin_only
    def entries():
        if request.method == 'GET':
            return jsonify(success=True, items=store.entries())
        data = request.get_json(silent=True) or {}
        raw = data.get('emails', '') if isinstance(data, dict) else ''
        if isinstance(raw, list):
            raw = '\n'.join(str(value) for value in raw)
        if not isinstance(raw, str) or len(raw) > 60000:
            return jsonify(success=False, message='Informe até 200 emails por vez.'), 400
        tokens = [v.lower() for v in re.split(r'[\s,;]+', raw.strip()) if v]
        emails = list(dict.fromkeys(tokens))
        if not emails or len(emails) > 200:
            return jsonify(success=False, message='Informe de 1 a 200 emails por vez.'), 400
        invalid = [em for em in emails if len(em) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', em)]
        if invalid:
            return jsonify(success=False, message='Corrija os emails inválidos antes de adicionar: ' + ', '.join(invalid[:10])), 400
        try:
            result = registry.quarantine(emails)
        except Exception:
            app.logger.exception('Quarantine registration cleanup failed')
            return jsonify(success=False, quarantined=True,
                           message='O bloqueio foi solicitado, mas não foi possível concluir a remoção dos vínculos e links. Atualize a lista e tente adicionar novamente para concluir.'), 503
        for key, value in list(pending_resets.items()):
            if isinstance(value, dict) and store.matches(value.get('email'), set(emails)):
                pending_resets.pop(key, None)
        return jsonify(success=True, **result,
                       message=f"{result['added']} email(s) adicionado(s) à quarentena. {result['existing']} já estava(m) na lista. "
                               f"{result['removed_bindings']} vínculo(s) removido(s) e {result['removed_links']} link(s) excluído(s).")

    @bp.post('/api/admin/quarantine/remove')
    @admin_only
    def remove():
        data = request.get_json(silent=True) or {}
        email = str(data.get('email', '')).strip().lower() if isinstance(data, dict) else ''
        if not store.remove(email):
            return jsonify(success=False, message='Email não encontrado na quarentena.'), 404
        return jsonify(success=True, message='Email retirado da quarentena. Vínculos e links excluídos não são restaurados automaticamente.')

    def request_email():
        path = request.path
        if path.startswith('/api/netflix-link/'):
            auth = request.headers.get('Authorization', '')
            token = auth[7:] if auth.startswith('Bearer ') else ''
            path_db = os.path.join(data_dir, 'netflix_links.sqlite3')
            if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token) or not os.path.isfile(path_db):
                return ''
            conn = sqlite3.connect('file:' + path_db + '?mode=ro', uri=True, timeout=15)
            try:
                row = conn.execute('SELECT email FROM links WHERE digest=?', (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
                return row[0] if row else ''
            finally:
                conn.close()
        data = request.get_json(silent=True) or {}
        email = str(data.get('email', '')).strip().lower() if isinstance(data, dict) else ''
        if not email:
            email = str(request.args.get('email', '')).strip().lower()
        if path == '/api/verify-reset-pin':
            pending = pending_resets.get(session.get('username')) or {}
            return pending.get('email') or email
        return email

    def blocked_response():
        response = jsonify(success=False, quarantined=True, message=MESSAGE, items=[], results=[], count=0)
        response.status_code = 403
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.before_request
    def block_consultation():
        if host_allowed() and request.path in CONSULT_PATHS:
            email = request_email()
            if email and store.is_blocked(email):
                return blocked_response()
        return None

    @app.after_request
    def enforce_final_response(response):
        if not host_allowed():
            return response
        if request.path == '/admin' and response.status_code == 200 and session.get('logged_in') and session.get('role') == 'admin' and session.get('username') == 'admin':
            response.direct_passthrough = False
            page = response.get_data(as_text=True)
            entry = '<a id="quarantine-launch" href="/admin/quarentena" style="display:block;margin:16px 0;padding:22px;border:2px solid #f59e0b;border-radius:16px;color:#fde68a;background:#291b16;text-decoration:none;font-size:1.15rem;font-weight:800;">🛑 Quarentena — bloquear consulta de emails</a>'
            response.set_data(page.replace('<div class="main">', '<div class="main">' + entry, 1))
            response.headers['Cache-Control'] = 'no-store'
        if request.path in CONSULT_PATHS:
            email = request_email()
            if email and store.is_blocked(email):
                return blocked_response()
        if request.path not in INBOX_PATHS or not response.is_json or response.status_code != 200:
            return response
        data = response.get_json(silent=True)
        if not isinstance(data, dict) or not data.get('success'):
            return response
        blocked = store.emails()
        def hits(value):
            if isinstance(value, list):
                return any(hits(v) for v in value)
            if isinstance(value, dict):
                return any(hits(value.get(k)) for k in ('email', 'allowed_email', 'recipients'))
            return store.matches(value, blocked)
        original = data.get('items') or []
        data['items'] = [item for item in original if not hits(item)]
        data['count'] = len(data['items'])
        emails = data.get('emails') or data.get('allowed') or []
        quarantined = [email for email in emails if hits(email)]
        if quarantined or len(original) != len(data['items']):
            data['quarantined_emails'] = quarantined
            data['quarantine_message'] = MESSAGE
            data['message'] = MESSAGE
        response.set_data(app.json.dumps(data))
        response.headers['Cache-Control'] = 'no-store'
        return response

    app.register_blueprint(bp)
