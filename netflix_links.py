"""Isolated bearer access links for streaming services (Netflix, Disney+).

Enabled on the central host only. Each service keeps its own table rows
(composite primary key ``email + service``) so one email can hold a Netflix
link and a Disney+ link at the same time, with independent tokens.
"""
import hashlib
import html
import os
import quopri
import re
import secrets
import shutil
import sqlite3
import time
from contextlib import contextmanager
from contextvars import ContextVar
from email.utils import getaddresses
from functools import partial, wraps
from threading import Lock
from urllib.parse import urlparse

from flask import Blueprint, abort, g, jsonify, redirect, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

HOST = 'consulta-codigos-jr7z.onrender.com'

SERVICES = {
    'netflix': {
        'name': 'Netflix',
        'path': '/netflix',
        'api': 'netflix-link',
        'page': 'netflix-link.html',
        'platforms': ('netflix', 'netflix-login', 'netflix-temp', 'netflix-residence', 'password-reset'),
        'labels': {
            'netflix': 'Código de acesso Netflix',
            'netflix-login': 'Código de início de sessão',
            'netflix-temp': 'Acesso temporário',
            'netflix-residence': 'Confirmação de residência',
            'password-reset': 'Redefinição de senha',
        },
        'allowed_hosts': ('netflix.com',),
        'empty_message': 'Nenhum código ou link Netflix recente encontrado. '
                         'Faça a solicitação na Netflix e atualize aqui.',
        'entry': '🔗 Links Netflix — criar e gerenciar',
        'entry_style': 'border:2px solid #ed4168;color:#ffd3de;background:#291327;',
        'hint': 'somente para códigos Netflix',
    },
    'disney': {
        'name': 'Disney+',
        'path': '/disney',
        'api': 'disney-link',
        'page': 'disney-link.html',
        'platforms': ('disney', 'disney-residence'),
        'labels': {
            'disney': 'Código de acesso Disney+',
            'disney-residence': 'Confirmação de residência Disney+',
        },
        'allowed_hosts': ('disneyplus.com', 'disney.com'),
        'empty_message': 'Nenhum código ou link Disney+ recente encontrado. '
                         'Faça a solicitação no Disney+ e atualize aqui.',
        'entry': '🏰 Links Disney+ — criar e gerenciar',
        'entry_style': 'border:2px solid #1f7ae0;color:#cfe4ff;background:#0e1b33;',
        'hint': 'somente para códigos Disney+',
    },
}

DEFAULT_SERVICE = 'netflix'
SERVICE_ORDER = ('netflix', 'disney')

# Backwards-compatible module level names (older imports still work).
NETFLIX_PLATFORMS = SERVICES['netflix']['platforms']
NETFLIX_FILTER_LABELS = SERVICES['netflix']['labels']

strict_email_context = ContextVar('netflix_link_exact_email', default=None)


def normalize_service(value):
    """Return a known service key, falling back to the default one."""
    text = str(value or '').strip().lower()
    return text if text in SERVICES else DEFAULT_SERVICE


def _link_host_allowed(link, allowed_hosts):
    try:
        parsed = urlparse(html.unescape(str(link)))
        hostname = (parsed.hostname or '').lower()
        safe = parsed.scheme == 'https' and any(
            hostname == host or hostname.endswith('.' + host) for host in allowed_hosts
        )
        safe = safe and not parsed.username and not parsed.password and parsed.port in (None, 443)
    except ValueError:
        return False
    return safe


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


def register_links(app, data_dir, search, search_alls=None):
    """Register the isolated link module.

    ``search_alls`` maps a service key to a batch search callable
    ``(email, platforms) -> (results, errors)``. Missing services fall back to
    the single-result ``search`` callable.
    """
    search_alls = dict(search_alls or {})
    bp = Blueprint('netflix_links', __name__)
    db_path = os.path.join(data_dir, 'netflix_links.sqlite3')
    schema_ready = False
    schema_lock = Lock()
    dummy_hash = generate_password_hash(secrets.token_urlsafe(24))

    def create_links_table(conn):
        conn.execute('''CREATE TABLE IF NOT EXISTS links (
            email TEXT NOT NULL, service TEXT NOT NULL DEFAULT 'netflix',
            token TEXT NOT NULL, digest TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
            last_query REAL NOT NULL DEFAULT 0, owner TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (email, service))''')

    def rebuild_links_table(conn, columns):
        # Keep a byte copy of the live database right before touching the table.
        if os.path.isfile(db_path):
            try:
                shutil.copy2(db_path, db_path + '.pre-service-migration.bak')
            except OSError:
                pass
        conn.execute('DROP TABLE IF EXISTS links_legacy')
        conn.execute('ALTER TABLE links RENAME TO links_legacy')
        create_links_table(conn)
        owner = "coalesce(owner,'')" if 'owner' in columns else "''"
        last_query = 'coalesce(last_query,0)' if 'last_query' in columns else '0'
        conn.execute(f'''INSERT INTO links(email,service,token,digest,created_at,updated_at,last_query,owner)
            SELECT email,'netflix',token,digest,created_at,updated_at,{last_query},{owner}
            FROM links_legacy''')
        conn.execute('DROP TABLE links_legacy')

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
                            info = list(conn.execute('PRAGMA table_info(links)'))
                            if not info:
                                create_links_table(conn)
                            else:
                                columns = {row[1] for row in info}
                                primary = [row[1] for row in info if row[5]]
                                if 'service' not in columns or primary != ['email', 'service']:
                                    rebuild_links_table(conn, columns)
                            conn.execute('''CREATE TABLE IF NOT EXISTS netflix_admins (
                                id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                                name TEXT NOT NULL, password_hash TEXT NOT NULL,
                                created_at INTEGER NOT NULL, version INTEGER NOT NULL DEFAULT 1,
                                active INTEGER NOT NULL DEFAULT 1)''')
                            conn.execute('CREATE INDEX IF NOT EXISTS links_owner_idx ON links(owner)')
                            conn.execute('CREATE INDEX IF NOT EXISTS links_service_idx ON links(service)')
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
                return jsonify(success=False, message='Entre com seu acesso exclusivo de Links de Acesso.'), 403
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
        cfg = SERVICES[normalize_service(row['service'] if 'service' in row.keys() else DEFAULT_SERVICE)]
        return {'email': row['email'], 'service': normalize_service(row['service']),
                'service_name': cfg['name'],
                'url': 'https://' + HOST + cfg['path'] + '#' + row['token'],
                'created_at': row['created_at'], 'updated_at': row['updated_at'],
                'manager': row['manager'] if 'manager' in row.keys() else ('admin' if not row['owner'] else '')}

    def authorized_row(conn, service):
        if not host_allowed():
            abort(404)
        auth = request.headers.get('Authorization', '')
        token = auth[7:] if auth.startswith('Bearer ') else ''
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            return None
        return conn.execute('SELECT * FROM links WHERE digest=? AND service=?',
                            (digest(token), service)).fetchone()

    def requested_service(payload=None):
        source = payload if isinstance(payload, dict) else {}
        return normalize_service(source.get('service') or request.args.get('service'))

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
                bars = ''
                for name in SERVICE_ORDER:
                    cfg = SERVICES[name]
                    bars += (
                        '<a id="nfl-nav-link-' + name + '" href="/admin/netflix-links?service=' + name + '" '
                        'style="display:block;margin:16px 0;padding:22px;border-radius:16px;'
                        'text-decoration:none;font-size:1.15rem;font-weight:800;' + cfg['entry_style'] + '">'
                        + cfg['entry'] + '</a>'
                    )
                page = page.replace('<div class="main">', '<div class="main">' + bars, 1)
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
                ON CONFLICT(key) DO UPDATE SET attempts=attempts+1''', (key, now + 900))
            row = conn.execute('SELECT * FROM netflix_admins WHERE username=?', (username,)).fetchone()
        valid = check_password_hash(row['password_hash'] if row else dummy_hash, password)
        if not row or not row['active'] or not valid:
            return jsonify(success=False, message='Usuário ou senha inválidos.'), 401
        with db() as conn:
            conn.execute('DELETE FROM netflix_login_attempts WHERE key=?', (key,))
        session.clear()
        session.update(netflix_admin_id=row['id'], netflix_admin_version=row['version'], netflix_admin_expires=now + 8 * 3600)
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
            service = requested_service()
            with db() as conn:
                if g.netflix_manager['principal']:
                    rows = conn.execute(
                        "SELECT l.*,coalesce(a.username,'admin') AS manager FROM links l "
                        "LEFT JOIN netflix_admins a ON a.id=l.owner WHERE l.service=? "
                        "ORDER BY l.updated_at DESC,l.email", (service,)).fetchall()
                else:
                    rows = conn.execute(
                        'SELECT l.*,? AS manager FROM links l WHERE owner=? AND service=? '
                        'ORDER BY updated_at DESC,email',
                        (g.netflix_manager['username'], g.netflix_manager['id'], service)).fetchall()
            return jsonify(success=True, service=service, service_name=SERVICES[service]['name'],
                           items=[row_payload(r) for r in rows])
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(success=False, message='Informe a lista de emails.'), 400
        service = requested_service(data)
        cfg = SERVICES[service]
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
                row = conn.execute('SELECT * FROM links WHERE email=? AND service=?', (email, service)).fetchone()
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
                    conn.execute(
                        'INSERT INTO links(email,service,token,digest,created_at,updated_at,owner) VALUES(?,?,?,?,?,?,?)',
                        (email, service, token, digest(token), now, now, g.netflix_manager['id']))
                    row = conn.execute('SELECT * FROM links WHERE email=? AND service=?', (email, service)).fetchone()
                    result = row_payload(row)
                    result['created'] = True
                generated.append(result)
        if not batch:
            return jsonify(success=True, service=service, item=generated[0]), 201
        return jsonify(success=True, service=service, service_name=cfg['name'], items=generated,
                       created=len(generated) - existing, existing=existing,
                       duplicates=len(candidates) - len(unique), invalid_emails=invalid,
                       conflict_emails=conflicts), 200

    @bp.post('/api/admin/netflix-links/reset')
    @manager_only
    def admin_reset():
        data = request.get_json(silent=True) or {}
        service = requested_service(data)
        email = str((data or {}).get('email', '')).strip().lower()
        # Reativa um link ja entregue ao cliente: em vez de gerar outro token,
        # reaproveita o token informado para o mesmo email e servico.
        keep = str(data.get('token') or '').strip()
        if keep and not re.fullmatch(r'[A-Za-z0-9_-]{43}', keep):
            return jsonify(success=False, message='O link informado não tem o formato esperado.'), 400
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            current = conn.execute('SELECT * FROM links WHERE email=? AND service=?', (email, service)).fetchone()
            if not owns(current):
                return jsonify(success=False, message='Email não cadastrado neste acesso.'), 404
            if keep:
                other = conn.execute(
                    'SELECT email FROM links WHERE digest=? AND NOT (email=? AND service=?)',
                    (digest(keep), email, service)).fetchone()
                if other:
                    return jsonify(success=False, message='Este link já está em uso por outro email.'), 409
                token = keep
            else:
                token = secrets.token_urlsafe(32)
            result = conn.execute(
                'UPDATE links SET token=?,digest=?,updated_at=?,last_query=0 WHERE email=? AND service=?',
                (token, digest(token), int(time.time()), email, service))
            if not result.rowcount:
                return jsonify(success=False, message='Email não cadastrado.'), 404
            row = conn.execute('SELECT * FROM links WHERE email=? AND service=?', (email, service)).fetchone()
        return jsonify(success=True, item=row_payload(row))

    @bp.post('/api/admin/netflix-links/delete')
    @manager_only
    def admin_delete():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(success=False, message='Informe o email que deseja excluir.'), 400
        service = requested_service(data)
        email = str(data.get('email', '')).strip().lower()
        if not email:
            return jsonify(success=False, message='Informe o email que deseja excluir.'), 400
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            current = conn.execute('SELECT * FROM links WHERE email=? AND service=?', (email, service)).fetchone()
            if not owns(current):
                return jsonify(success=False, message='Email não cadastrado neste acesso.'), 404
            result = conn.execute('DELETE FROM links WHERE email=? AND service=?', (email, service))
            if not result.rowcount:
                return jsonify(success=False, message='Email não cadastrado.'), 404
        return jsonify(success=True, email=email, service=service,
                       message='Email e link excluídos. O acesso por esse link foi bloqueado.')

    def client_page(service):
        if not host_allowed():
            abort(404)
        return send_from_directory(app.static_folder, SERVICES[service]['page'])

    def client_access(service):
        cfg = SERVICES[service]
        with db() as conn:
            row = authorized_row(conn, service)
        if not row:
            return jsonify(success=False, message='Link inválido ou redefinido. Solicite o link atual ao administrador.'), 403
        return jsonify(success=True, email=row['email'], service=service, service_name=cfg['name'],
                       filters=[{'key': p, 'label': cfg['labels'][p]} for p in cfg['platforms']])

    def client_reset(service):
        # Deny old client pages too; only the authenticated principal admin resets.
        return jsonify(success=False, message='Somente o administrador pode redefinir este link.'), 403

    def client_code(service):
        cfg = SERVICES[service]
        platforms = cfg['platforms']
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row = authorized_row(conn, service)
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
            conn.execute('UPDATE links SET last_query=? WHERE email=? AND service=?',
                         (now, row['email'], service))
        collector = search_alls.get(service)
        try:
            # Email and platforms come only from server state, never from request JSON.
            marker = strict_email_context.set(row['email'])
            try:
                if collector is not None:
                    raw_results, errors = collector(row['email'], list(platforms))
                else:
                    code, link, platform, error = search(row['email'], list(platforms))
                    raw_results = [{'code': code, 'link': link, 'platform': platform}] if code or link else []
                    errors = [error] if error and not str(error).lower().startswith('nenhum email encontrado') else []
            finally:
                strict_email_context.reset(marker)
        except Exception:
            return jsonify(success=False, message='Não foi possível consultar agora. Tente novamente.'), 503
        # A reset during IMAP lookup must revoke even the in-flight response.
        with db() as conn:
            current = authorized_row(conn, service)
        if not current:
            return jsonify(success=False, message='Este link foi redefinido. Use o novo link.'), 403
        results = []
        seen = set()
        for item in raw_results or []:
            platform = item.get('platform')
            if platform not in platforms or platform in seen:
                continue
            label = cfg['labels'][platform]
            if item.get('code'):
                results.append({'platform': platform, 'label': label, 'type': 'code', 'value': str(item['code'])})
                seen.add(platform)
            elif item.get('link') and _link_host_allowed(item['link'], cfg['allowed_hosts']):
                results.append({'platform': platform, 'label': label, 'type': 'link',
                                'value': html.unescape(str(item['link']))})
                seen.add(platform)
        if results:
            results.sort(key=lambda item: platforms.index(item['platform']))
            first = results[0]
            payload = {'success': True, 'results': results, 'platform': first['platform'],
                       'service': service, 'service_name': cfg['name']}
            payload['code' if first['type'] == 'code' else 'link'] = first['value']
            if errors:
                payload['warning'] = 'Algumas caixas não puderam ser consultadas. Você pode tentar atualizar novamente.'
            return jsonify(**payload)
        if errors:
            return jsonify(success=False, message='Não foi possível consultar a caixa agora. Tente novamente.'), 503
        return jsonify(success=True, results=[], service=service, message=cfg['empty_message'])

    for service in SERVICE_ORDER:
        cfg = SERVICES[service]
        bp.add_url_rule(cfg['path'], endpoint='client_page_' + service,
                        view_func=partial(client_page, service=service), methods=['GET'])
        bp.add_url_rule('/api/' + cfg['api'] + '/access', endpoint='client_access_' + service,
                        view_func=partial(client_access, service=service), methods=['GET'])
        bp.add_url_rule('/api/' + cfg['api'] + '/reset', endpoint='client_reset_' + service,
                        view_func=partial(client_reset, service=service), methods=['POST'])
        bp.add_url_rule('/api/' + cfg['api'] + '/code', endpoint='client_code_' + service,
                        view_func=partial(client_code, service=service), methods=['POST'])

    app.register_blueprint(bp)


# Backwards-compatible alias for older call sites.
register_netflix_links = register_links
