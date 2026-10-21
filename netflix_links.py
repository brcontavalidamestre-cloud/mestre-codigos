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
from threading import Lock
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
from flask import Blueprint, abort, jsonify, request, session, send_from_directory, redirect, g

HOST = 'consulta-codigos-jr7z.onrender.com'
NETFLIX_PLATFORMS = ('netflix', 'netflix-login', 'netflix-temp', 'netflix-residence', 'password-reset')
NETFLIX_FILTER_LABELS = {
    'netflix': 'Código de acesso',
    'netflix-login': 'Acesso início',
    'netflix-temp': 'Acesso temporário',
    'netflix-residence': 'Atualização de residência',
    'password-reset': 'Redefinir senha',
}
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
    schema_ready = False
    schema_lock = Lock()
    dummy_hash = generate_password_hash(secrets.token_urlsafe(24))

    @contextmanager
    def db():
        nonlocal schema_ready
        os.makedirs(data_dir, exist_ok=True)
        conn = sqlite3.connect(db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            if not schema_ready:
                with schema_lock:
                    if not schema_ready:
                        with conn:
                            conn.execute('BEGIN IMMEDIATE')
                            conn.execute('''CREATE TABLE IF NOT EXISTS links (
                                email TEXT PRIMARY KEY, token TEXT NOT NULL,
                                digest TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL,
                                updated_at INTEGER NOT NULL, last_query REAL NOT NULL DEFAULT 0,
                                owner TEXT NOT NULL DEFAULT '')''')
                            if 'owner' not in {r['name'] for r in conn.execute('PRAGMA table_info(links)')}:
                                conn.execute("ALTER TABLE links ADD COLUMN owner TEXT NOT NULL DEFAULT ''")
                            conn.execute('''CREATE TABLE IF NOT EXISTS netflix_admins (
                                id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                                name TEXT NOT NULL, password_hash TEXT NOT NULL,
                                created_at INTEGER NOT NULL, version INTEGER NOT NULL DEFAULT 1,
                                active INTEGER NOT NULL DEFAULT 1)''')
                            conn.execute('CREATE INDEX IF NOT EXISTS links_owner_idx ON links(owner)')
                            conn.execute('''CREATE TABLE IF NOT EXISTS netflix_login_attempts (
                                key TEXT PRIMARY KEY, attempts INTEGER NOT NULL, expires INTEGER NOT NULL)''')
                        os.chmod(db_path, 0o600)
                        schema_ready = True
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

    def principal():
        return bool(session.get('logged_in') and session.get('role') == 'admin' and session.get('username') == 'admin')

    def actor():
        if principal():
            return {'principal': True, 'id': '', 'username': 'admin', 'name': 'Administrador principal'}
        account_id = session.get('netflix_admin_id')
        if not account_id or int(session.get('netflix_admin_expires') or 0) <= int(time.time()):
            return None
        with db() as conn:
            row = conn.execute('SELECT id,username,name,version,active FROM netflix_admins WHERE id=?', (account_id,)).fetchone()
        if not row or not row['active'] or row['version'] != session.get('netflix_admin_version'):
            return None
        return {'principal': False, 'id': row['id'], 'username': row['username'], 'name': row['name']}

    def manager_only(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not host_allowed():
                abort(404)
            current = actor()
            if not current:
                if request.path == '/admin/netflix-links':
                    return redirect('/netflix-admin/login')
                return jsonify(success=False, message='Entre com seu acesso exclusivo de Links Netflix.'), 403
            if request.method != 'GET' and request.headers.get('Origin') not in (None, 'https://' + HOST):
                abort(403)
            g.netflix_manager = current
            return fn(*args, **kwargs)
        return wrapped

    def owns(row):
        return bool(row and (g.netflix_manager['principal'] or row['owner'] == g.netflix_manager['id']))

    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def row_payload(row):
        return {'email': row['email'], 'url': 'https://' + HOST + '/netflix#' + row['token'],
                'created_at': row['created_at'], 'updated_at': row['updated_at'],
                'manager': row['manager'] if 'manager' in row.keys() else ('admin' if not row['owner'] else '')}

    def collect_client_results(email):
        items = []
        seen = set()
        service_errors = []
        for platform_key in NETFLIX_PLATFORMS:
            try:
                code, link, matched_platform, error = search(email, [platform_key])
            except Exception as exc:
                service_errors.append(str(exc))
                continue
            matched_platform = matched_platform or platform_key
            if matched_platform != platform_key and matched_platform not in NETFLIX_PLATFORMS:
                continue
            label = NETFLIX_FILTER_LABELS.get(platform_key, platform_key)
            if code:
                value = str(code).strip()
                marker = ('code', platform_key, value)
                if value and marker not in seen:
                    seen.add(marker)
                    items.append({'platform': platform_key, 'label': label, 'type': 'code', 'value': value})
                continue
            if link:
                parsed = urlparse(link)
                hostname = (parsed.hostname or '').lower()
                if parsed.scheme == 'https' and (hostname == 'netflix.com' or hostname.endswith('.netflix.com')):
                    marker = ('link', platform_key, link)
                    if marker not in seen:
                        seen.add(marker)
                        items.append({'platform': platform_key, 'label': label, 'type': 'link', 'value': link})
                continue
            if error and not str(error).lower().startswith('nenhum email encontrado'):
                service_errors.append(str(error))
        return items, service_errors

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

    @bp.get('/netflix-admin/login')
    def manager_login_page():
        return send_from_directory(app.static_folder, 'netflix-admin-login.html')

    @bp.get('/api/netflix-admin/me')
    def manager_me():
        current = actor()
        if not current:
            return jsonify(success=False, message='Não autenticado.'), 403
        return jsonify(success=True, **current)

    @bp.post('/api/netflix-admin/login')
    def manager_login():
        if request.headers.get('Origin') not in (None, 'https://' + HOST):
            abort(403)
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(success=False, message='Dados inválidos.'), 400
        username = str(data.get('username', '')).strip().lower()[:80]
        password = str(data.get('password', ''))
        if not username or not password or len(password) > 256:
            return jsonify(success=False, message='Informe usuário e senha válidos.'), 400
        now = int(time.time())
        key = hashlib.sha256(username.encode()).hexdigest()
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute('DELETE FROM netflix_login_attempts WHERE expires<=?', (now,))
            attempts = conn.execute('SELECT attempts FROM netflix_login_attempts WHERE key=?', (key,)).fetchone()
            if attempts and attempts['attempts'] >= 10:
                return jsonify(success=False, message='Muitas tentativas. Aguarde 15 minutos.'), 429
            conn.execute('''INSERT INTO netflix_login_attempts(key,attempts,expires) VALUES(?,1,?)
                ON CONFLICT(key) DO UPDATE SET attempts=attempts+1''', (key, now+900))
            row = conn.execute('SELECT * FROM netflix_admins WHERE username=?', (username,)).fetchone()
        valid = check_password_hash(row['password_hash'] if row else dummy_hash, password)
        if not row or not row['active'] or not valid:
            return jsonify(success=False, message='Usuário ou senha inválidos.'), 401
        with db() as conn:
            conn.execute('DELETE FROM netflix_login_attempts WHERE key=?', (key,))
        session.clear()
        session.update(netflix_admin_id=row['id'], netflix_admin_version=row['version'], netflix_admin_expires=now+8*3600)
        return jsonify(success=True, redirect='/admin/netflix-links')

    @bp.post('/api/netflix-admin/logout')
    def manager_logout():
        if request.headers.get('Origin') not in (None, 'https://' + HOST):
            abort(403)
        for key in ('netflix_admin_id', 'netflix_admin_version', 'netflix_admin_expires'):
            session.pop(key, None)
        return jsonify(success=True)

    @bp.route('/api/admin/netflix-link-admins', methods=['GET', 'POST'])
    @admin_only
    def principal_manage_accounts():
        if request.method == 'GET':
            with db() as conn:
                rows = conn.execute('SELECT id,username,name,created_at,active FROM netflix_admins ORDER BY created_at DESC,username').fetchall()
            return jsonify(success=True, items=[dict(r) for r in rows], login_url='https://' + HOST + '/netflix-admin/login')
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(success=False, message='Dados inválidos.'), 400
        username = str(data.get('username', '')).strip().lower()
        name = str(data.get('name', '')).strip()[:80] or username
        password = str(data.get('password', ''))
        if not re.fullmatch(r'[a-z0-9_.-]{3,40}', username) or username == 'admin':
            return jsonify(success=False, message='Use um usuário de 3 a 40 letras, números, ponto, traço ou sublinhado. O nome admin é reservado.'), 400
        if not 8 <= len(password) <= 128:
            return jsonify(success=False, message='A senha deve ter de 8 a 128 caracteres.'), 400
        password_hash = generate_password_hash(password)
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            if conn.execute('SELECT id FROM netflix_admins WHERE username=?', (username,)).fetchone():
                return jsonify(success=False, message='Esse usuário já está cadastrado.'), 409
            account_id = secrets.token_hex(16)
            conn.execute('INSERT INTO netflix_admins(id,username,name,password_hash,created_at) VALUES(?,?,?,?,?)',
                         (account_id, username, name, password_hash, int(time.time())))
        return jsonify(success=True, username=username, id=account_id, login_url='https://' + HOST + '/netflix-admin/login'), 201

    @bp.post('/api/admin/netflix-link-admins/update')
    @admin_only
    def principal_update_account():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(success=False, message='Dados inválidos.'), 400
        account_id = str(data.get('id', ''))
        password = data.get('password')
        active = data.get('active')
        if password is None and active is None:
            return jsonify(success=False, message='Informe a nova senha ou o status.'), 400
        if password is not None and (not isinstance(password, str) or not 8 <= len(password) <= 128):
            return jsonify(success=False, message='A senha deve ter de 8 a 128 caracteres.'), 400
        if active is not None and not isinstance(active, bool):
            return jsonify(success=False, message='Status inválido.'), 400
        password_hash = generate_password_hash(password) if password is not None else None
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT id FROM netflix_admins WHERE id=?', (account_id,)).fetchone()
            if not row:
                return jsonify(success=False, message='Administrador não encontrado.'), 404
            if password_hash:
                conn.execute('UPDATE netflix_admins SET password_hash=? WHERE id=?', (password_hash, account_id))
            if active is not None:
                conn.execute('UPDATE netflix_admins SET active=? WHERE id=?', (int(active), account_id))
            conn.execute('UPDATE netflix_admins SET version=version+1 WHERE id=?', (account_id,))
        return jsonify(success=True, message='Acesso atualizado. As sessões anteriores foram encerradas.')

    @bp.get('/admin/netflix-links')
    @manager_only
    def admin_panel():
        return send_from_directory(app.static_folder, 'netflix-links-panel.html')

    @bp.route('/api/admin/netflix-links', methods=['GET', 'POST'])
    @manager_only
    def admin_links():
        if request.method == 'GET':
            with db() as conn:
                if g.netflix_manager['principal']:
                    rows = conn.execute("SELECT l.*,coalesce(a.username,'admin') AS manager FROM links l LEFT JOIN netflix_admins a ON a.id=l.owner ORDER BY l.updated_at DESC,l.email").fetchall()
                else:
                    rows = conn.execute('SELECT l.*,? AS manager FROM links l WHERE owner=? ORDER BY updated_at DESC,email', (g.netflix_manager['username'], g.netflix_manager['id'])).fetchall()
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
        generated, existing, conflicts = [], 0, []
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            now = int(time.time())
            for email in valid:
                row = conn.execute('SELECT * FROM links WHERE email=?', (email,)).fetchone()
                if row:
                    if not owns(row):
                        if not batch:
                            return jsonify(success=False, message='Este email já está cadastrado em outro acesso. Não é possível usar o link.'), 409
                        conflicts.append(email)
                        continue
                    if not batch:
                        return jsonify(success=False, message='Este email já possui um link. Use Redefinir link.', item=row_payload(row)), 409
                    existing += 1
                    result = row_payload(row)
                    result['created'] = False
                else:
                    token = secrets.token_urlsafe(32)
                    conn.execute('INSERT INTO links(email,token,digest,created_at,updated_at,owner) VALUES(?,?,?,?,?,?)',
                                 (email, token, digest(token), now, now, g.netflix_manager['id']))
                    row = conn.execute('SELECT * FROM links WHERE email=?', (email,)).fetchone()
                    result = row_payload(row)
                    result['created'] = True
                generated.append(result)
        if not batch:
            return jsonify(success=True, item=generated[0]), 201
        return jsonify(success=True, items=generated, created=len(generated)-existing,
                       existing=existing, duplicates=len(candidates)-len(unique), invalid_emails=invalid, conflict_emails=conflicts), 200

    @bp.post('/api/admin/netflix-links/reset')
    @manager_only
    def admin_reset():
        email = str((request.get_json(silent=True) or {}).get('email', '')).strip().lower()
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            current = conn.execute('SELECT * FROM links WHERE email=?', (email,)).fetchone()
            if not owns(current):
                return jsonify(success=False, message='Email não cadastrado neste acesso.'), 404
            token = secrets.token_urlsafe(32)
            result = conn.execute('UPDATE links SET token=?,digest=?,updated_at=?,last_query=0 WHERE email=?',
                                  (token, digest(token), int(time.time()), email))
            if not result.rowcount:
                return jsonify(success=False, message='Email não cadastrado.'), 404
            row = conn.execute('SELECT * FROM links WHERE email=?', (email,)).fetchone()
        return jsonify(success=True, item=row_payload(row))

    @bp.post('/api/admin/netflix-links/delete')
    @manager_only
    def admin_delete():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(success=False, message='Informe o email que deseja excluir.'), 400
        email = str(data.get('email', '')).strip().lower()
        if not email:
            return jsonify(success=False, message='Informe o email que deseja excluir.'), 400
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            current = conn.execute('SELECT * FROM links WHERE email=?', (email,)).fetchone()
            if not owns(current):
                return jsonify(success=False, message='Email não cadastrado neste acesso.'), 404
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
                results, errors = collect_client_results(row['email'])
            finally:
                strict_email_context.reset(marker)
        except Exception:
            return jsonify(success=False, message='Não foi possível consultar agora. Tente novamente.'), 503
        # A reset during IMAP lookup must revoke even the in-flight response.
        with db() as conn:
            current = authorized_row(conn)
        if not current:
            return jsonify(success=False, message='Este link foi redefinido. Use o novo link.'), 403
        if results:
            payload = {'success': True, 'results': results}
            first = results[0]
            payload['platform'] = first['platform']
            if first['type'] == 'code':
                payload['code'] = first['value']
            else:
                payload['link'] = first['value']
            return jsonify(**payload)
        if errors:
            return jsonify(success=False, message='Não foi possível consultar a caixa agora. Tente novamente.'), 503
        return jsonify(success=True, message='Nenhum código Netflix recente encontrado. Solicite o código na Netflix e atualize aqui.')

    app.register_blueprint(bp)
