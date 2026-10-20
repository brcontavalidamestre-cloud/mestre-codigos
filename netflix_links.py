"""Isolated bearer links for Netflix; enabled on the central host only."""
import hashlib
import html
import quopri
from contextvars import ContextVar
from email.utils import getaddresses
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from functools import wraps
from urllib.parse import urlparse
from flask import Blueprint, abort, jsonify, request, session, send_from_directory, redirect

HOST = 'consulta-codigos-jr7z.onrender.com'
NETFLIX_PLATFORMS = ('netflix', 'netflix-login', 'netflix-temp', 'netflix-residence')
strict_email_context = ContextVar('netflix_link_exact_email', default=None)


def exact_email_match(msg, html_body, target):
    target = target.strip().lower()
    headers = []
    for name in ('To', 'Cc', 'Bcc', 'Delivered-To', 'X-Original-To', 'X-Forwarded-To'):
        headers.extend(str(v) for v in (msg.get_all(name) or []))
    if target in {address.strip().lower() for _, address in getaddresses(headers)}:
        return True
    texts = [html_body or '']
    for part in msg.walk():
        if part.get_content_type() in ('text/plain', 'text/html'):
            payload = part.get_payload(decode=True)
            if payload:
                try:
                    texts.append(payload.decode(part.get_content_charset() or 'utf-8', errors='ignore'))
                except LookupError:
                    texts.append(payload.decode('utf-8', errors='ignore'))
    for text in texts:
        text = quopri.decodestring(text.encode('utf-8')).decode('utf-8', errors='ignore')
        text = html.unescape(text).lower()
        # Forwarded mail may keep the original recipient only inside its body.
        # Accept recipient-labelled lines, never an arbitrary email mention.
        text = re.sub(r'<(?:br\b[^>]*|/p|/div|/tr)>', '\n', text)
        text = re.sub(r'</?[a-z][a-z0-9]*(?:\s[^>]*?)?/?>', '', text)
        for line in text.splitlines():
            if not re.match(r'^\s*(?:>\s*)?(?:to|para|destinat[aá]rio|delivered-to|x-original-to)\s*:', line):
                continue
            addresses = re.findall(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}", line)
            if target in addresses:
                return True
    return False


def register_netflix_links(app, data_dir, search):
    bp = Blueprint('netflix_links', __name__)
    db_path = os.path.join(data_dir, 'netflix_links.sqlite3')

    @contextmanager
    def db():
        os.makedirs(data_dir, exist_ok=True)
        conn = sqlite3.connect(db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute('''CREATE TABLE IF NOT EXISTS links (
                email TEXT PRIMARY KEY, token TEXT NOT NULL,
                digest TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL, last_query REAL NOT NULL DEFAULT 0)''')
            os.chmod(db_path, 0o600)
            with conn:
                yield conn
        finally:
            conn.close()

    def host_allowed():
        # Do not use a caller-supplied X-Forwarded-Host for authorization.
        return request.host.lower().split(':', 1)[0] == HOST

    @bp.before_request
    def isolated_host():
        if not host_allowed():
            abort(404)

    def admin_only(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not host_allowed():
                abort(404)
            if not session.get('logged_in') and request.path == '/admin/netflix-links':
                return redirect('/login')
            if not session.get('logged_in') or session.get('role') != 'admin' or session.get('username') != 'admin':
                return jsonify(success=False, message='Somente o administrador principal pode gerenciar estes links.'), 403
            if request.method != 'GET' and request.headers.get('Origin') not in (None, 'https://' + HOST):
                abort(403)
            return fn(*args, **kwargs)
        return wrapped

    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def row_payload(row):
        return {'email': row['email'], 'url': 'https://' + HOST + '/netflix#' + row['token'],
                'created_at': row['created_at'], 'updated_at': row['updated_at']}

    def authorized_row(conn):
        if not host_allowed():
            abort(404)
        auth = request.headers.get('Authorization', '')
        token = auth[7:] if auth.startswith('Bearer ') else ''
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            return None
        return conn.execute('SELECT * FROM links WHERE digest=?', (digest(token),)).fetchone()

    @bp.after_request
    def private_response(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Robots-Tag'] = 'noindex, nofollow'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        return response

    @app.after_request
    def central_admin_entry(response):
        if host_allowed() and request.path == '/admin':
            response.headers['Cache-Control'] = 'no-store, max-age=0'
            response.headers.pop('ETag', None)
            response.headers.pop('Last-Modified', None)
            if response.status_code == 200 and session.get('logged_in') and session.get('role') == 'admin' and session.get('username') == 'admin':
                response.direct_passthrough = False
                page = response.get_data(as_text=True)
                entry = '<a id="nfl-nav-link" href="/admin/netflix-links" style="display:block;margin:16px 0;padding:22px;border:2px solid #ed4168;border-radius:16px;color:#ffd3de;background:#291327;text-decoration:none;font-size:1.15rem;font-weight:800;">🔗 Links Netflix — criar e gerenciar</a>'
                page = page.replace('<div class="main">', '<div class="main">' + entry, 1)
                response.set_data(page)
        return response

    @bp.get('/admin/netflix-links')
    @admin_only
    def admin_panel():
        return send_from_directory(app.static_folder, 'netflix-links-panel.html')

    @bp.route('/api/admin/netflix-links', methods=['GET', 'POST'])
    @admin_only
    def admin_links():
        if request.method == 'GET':
            with db() as conn:
                rows = conn.execute('SELECT * FROM links ORDER BY updated_at DESC, email').fetchall()
            return jsonify(success=True, items=[row_payload(r) for r in rows])
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(success=False, message='Informe a lista de emails.'), 400
        batch = 'emails' in data
        raw = data.get('emails') if batch else data.get('email', '')
        if isinstance(raw, list):
            raw = '\n'.join(str(value) for value in raw)
        if not isinstance(raw, str) or len(raw) > 60000:
            return jsonify(success=False, message='Informe até 200 emails por vez.'), 400
        candidates = [s.strip().lower() for s in re.split(r'[\s,;]+', raw) if s.strip()]
        unique = list(dict.fromkeys(candidates))
        if not batch and len(unique) != 1:
            return jsonify(success=False, message='Informe um email válido ou use o cadastro em lote.'), 400
        if len(unique) > 200:
            return jsonify(success=False, message='O limite é de 200 emails por vez.'), 400
        invalid = [s for s in unique if len(s) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', s)]
        valid = [s for s in unique if s not in invalid]
        if not valid:
            return jsonify(success=False, message='Informe ao menos um email válido.', invalid_emails=invalid), 400
        generated, existing = [], 0
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            now = int(time.time())
            for email in valid:
                row = conn.execute('SELECT * FROM links WHERE email=?', (email,)).fetchone()
                if row:
                    if not batch:
                        return jsonify(success=False, message='Este email já possui um link. Use Redefinir link.', item=row_payload(row)), 409
                    existing += 1
                    result = row_payload(row)
                    result['created'] = False
                else:
                    token = secrets.token_urlsafe(32)
                    conn.execute('INSERT INTO links(email,token,digest,created_at,updated_at) VALUES(?,?,?,?,?)',
                                 (email, token, digest(token), now, now))
                    row = conn.execute('SELECT * FROM links WHERE email=?', (email,)).fetchone()
                    result = row_payload(row)
                    result['created'] = True
                generated.append(result)
        if not batch:
            return jsonify(success=True, item=generated[0]), 201
        return jsonify(success=True, items=generated, created=len(generated)-existing,
                       existing=existing, duplicates=len(candidates)-len(unique), invalid_emails=invalid), 200

    @bp.post('/api/admin/netflix-links/reset')
    @admin_only
    def admin_reset():
        email = str((request.get_json(silent=True) or {}).get('email', '')).strip().lower()
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            token = secrets.token_urlsafe(32)
            result = conn.execute('UPDATE links SET token=?,digest=?,updated_at=?,last_query=0 WHERE email=?',
                                  (token, digest(token), int(time.time()), email))
            if not result.rowcount:
                return jsonify(success=False, message='Email não cadastrado.'), 404
            row = conn.execute('SELECT * FROM links WHERE email=?', (email,)).fetchone()
        return jsonify(success=True, item=row_payload(row))

    @bp.post('/api/admin/netflix-links/delete')
    @admin_only
    def admin_delete():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(success=False, message='Informe o email que deseja excluir.'), 400
        email = str(data.get('email', '')).strip().lower()
        if not email:
            return jsonify(success=False, message='Informe o email que deseja excluir.'), 400
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            result = conn.execute('DELETE FROM links WHERE email=?', (email,))
            if not result.rowcount:
                return jsonify(success=False, message='Email não cadastrado.'), 404
        return jsonify(success=True, email=email, message='Email e link excluídos. O acesso por esse link foi bloqueado.')

    @bp.get('/netflix')
    def client_page():
        if not host_allowed():
            abort(404)
        return send_from_directory(app.static_folder, 'netflix-link.html')

    @bp.get('/api/netflix-link/access')
    def client_access():
        with db() as conn:
            row = authorized_row(conn)
        if not row:
            return jsonify(success=False, message='Link inválido ou redefinido. Solicite o link atual ao administrador.'), 403
        return jsonify(success=True, email=row['email'])

    @bp.post('/api/netflix-link/reset')
    def client_reset():
        # Deny old client pages too; only the authenticated principal admin resets.
        return jsonify(success=False, message='Somente o administrador pode redefinir este link.'), 403

    @bp.post('/api/netflix-link/code')
    def client_code():
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row = authorized_row(conn)
            if not row:
                return jsonify(success=False, message='Link inválido ou redefinido.'), 403
            supplied = request.get_json(silent=True) or {}
            if not isinstance(supplied, dict):
                return jsonify(success=False, message='Consulta inválida.'), 400
            for override in (supplied.get('email'), request.args.get('email')):
                if override is not None and str(override).strip().lower() != row['email']:
                    return jsonify(success=False, message='Este link permite consultar somente o email cadastrado.'), 403
            now = time.time()
            if now - row['last_query'] < 12:
                return jsonify(success=False, message='Aguarde alguns segundos antes de atualizar.'), 429
            conn.execute('UPDATE links SET last_query=? WHERE email=?', (now, row['email']))
        try:
            # Email and platforms come only from server state, never from request JSON.
            marker = strict_email_context.set(row['email'])
            try:
                code, link, platform, error = search(row['email'], list(NETFLIX_PLATFORMS))
            finally:
                strict_email_context.reset(marker)
        except Exception:
            return jsonify(success=False, message='Não foi possível consultar agora. Tente novamente.'), 503
        # A reset during IMAP lookup must revoke even the in-flight response.
        with db() as conn:
            current = authorized_row(conn)
        if not current:
            return jsonify(success=False, message='Este link foi redefinido. Use o novo link.'), 403
        if platform not in NETFLIX_PLATFORMS and (code or link):
            return jsonify(success=False, message='Nenhum código Netflix encontrado.'), 200
        if code:
            return jsonify(success=True, code=str(code), platform=platform)
        if link:
            parsed = urlparse(link)
            hostname = (parsed.hostname or '').lower()
            if parsed.scheme == 'https' and (hostname == 'netflix.com' or hostname.endswith('.netflix.com')):
                return jsonify(success=True, link=link, platform=platform)
        if error and not str(error).lower().startswith('nenhum email encontrado'):
            return jsonify(success=False, message='Não foi possível consultar a caixa agora. Tente novamente.'), 503
        return jsonify(success=True, message='Nenhum código Netflix recente encontrado. Solicite o código na Netflix e atualize aqui.')

    app.register_blueprint(bp)
