"""Isolated bearer links for Netflix; enabled on the central host only."""
import hashlib
import tempfile
from cryptography.fernet import Fernet, InvalidToken
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
    'netflix': 'Código de acesso Netflix',
    'netflix-login': 'Código de início de sessão',
    'netflix-temp': 'Acesso temporário',
    'netflix-residence': 'Confirmação de residência',
    'password-reset': 'Redefinição de senha',
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


def register_netflix_links(app, data_dir, search, search_all=None):
    bp = Blueprint('netflix_links', __name__)
    db_path = os.path.join(data_dir, 'netflix_links.sqlite3')
    schema_ready = False
    schema_lock = Lock()
    dummy_hash = generate_password_hash(secrets.token_urlsafe(24))

    def status_cipher():
        path=os.path.join(data_dir,'.restricted-status-copy.key')
        try:
            with open(path,'rb') as handle: return Fernet(handle.read())
        except FileNotFoundError:
            fd,tmp=tempfile.mkstemp(dir=data_dir)
            try:
                with os.fdopen(fd,'wb') as handle:
                    handle.write(Fernet.generate_key());handle.flush();os.fsync(handle.fileno())
                try: os.link(tmp,path)
                except FileExistsError: pass
            finally: os.unlink(tmp)
        with open(path,'rb') as handle: return Fernet(handle.read())

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
                            conn.execute('''CREATE TABLE IF NOT EXISTS restricted_email_directory (
                                email TEXT PRIMARY KEY, account_id TEXT NOT NULL,
                                FOREIGN KEY(account_id) REFERENCES netflix_admins(id))''')
                            conn.execute('CREATE INDEX IF NOT EXISTS restricted_directory_owner ON restricted_email_directory(account_id)')
                            conn.execute('''CREATE TABLE IF NOT EXISTS restricted_status_links (email TEXT PRIMARY KEY, owner TEXT NOT NULL, digest TEXT UNIQUE NOT NULL, expires INTEGER NOT NULL, version INTEGER NOT NULL, checked INTEGER NOT NULL DEFAULT 0)''')
                            if 'sealed_token' not in {r['name'] for r in conn.execute('PRAGMA table_info(restricted_status_links)')}:
                                conn.execute('ALTER TABLE restricted_status_links ADD COLUMN sealed_token BLOB')
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
        if request.endpoint in {'netflix_links.client_page', 'netflix_links.client_access',
                                'netflix_links.client_reset', 'netflix_links.client_code',
                                'netflix_links.admin_links', 'netflix_links.admin_reset', 'netflix_links.admin_delete'}:
            return jsonify(success=False, message='A consulta por links antigos de código foi desativada.'), 410

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
        panel_actor = app.config.get('EMAIL_POOL_PANEL_LINK_ACTOR')
        if panel_actor:
            current = panel_actor()
            if current:
                return current
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

    def authorized_row(conn):
        if not host_allowed():
            abort(404)
        auth = request.headers.get('Authorization', '')
        token = auth[7:] if auth.startswith('Bearer ') else ''
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            return None
        row = conn.execute('SELECT * FROM links WHERE digest=?', (digest(token),)).fetchone()
        access_guard = app.config.get('EMAIL_POOL_LINK_ACCESS')
        return row if row and (not access_guard or access_guard(row)) else None

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
            if response.status_code == 200 and session.get('logged_in') and session.get('role') == 'admin' and actor():
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

    @bp.get('/api/netflix-admin/email-directory')
    @manager_only
    def directory_list():
        current = g.netflix_manager
        with db() as conn:
            if current['principal']:
                rows = conn.execute('SELECT d.email,a.username,EXISTS(SELECT 1 FROM restricted_status_links l WHERE l.email=d.email AND l.owner=d.account_id) AS has_status_link FROM restricted_email_directory d JOIN netflix_admins a ON a.id=d.account_id ORDER BY d.email').fetchall()
                accounts = conn.execute('SELECT username FROM netflix_admins ORDER BY username').fetchall()
            else:
                rows = conn.execute('SELECT d.email,a.username,EXISTS(SELECT 1 FROM restricted_status_links l WHERE l.email=d.email AND l.owner=d.account_id) AS has_status_link FROM restricted_email_directory d JOIN netflix_admins a ON a.id=d.account_id WHERE d.account_id=? AND a.active=1 ORDER BY d.email', (current['id'],)).fetchall()
                accounts = []
        return jsonify(success=True, principal=current['principal'], items=[dict(r) for r in rows], accounts=[r['username'] for r in accounts]), 200, {'Cache-Control':'no-store'}

    @bp.post('/api/netflix-admin/email-directory')
    @admin_only
    def directory_change():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(success=False,message='Dados inválidos.'),400
        username = data.get('username')
        raw = data.get('emails')
        action = data.get('action')
        if not isinstance(username,str) or not isinstance(raw,str) or len(raw)>55000 or action not in ('assign','remove'):
            return jsonify(success=False,message='Dados inválidos.'),400
        emails = sorted(set(re.split(r'[\s,;]+',raw.strip().lower())))
        if not 1<=len(emails)<=200 or any(len(e)>254 or not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+",e) for e in emails):
            return jsonify(success=False,message='Informe de 1 a 200 emails válidos.'),400
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            account = conn.execute('SELECT id FROM netflix_admins WHERE username=?',(username,)).fetchone()
            if not account:
                return jsonify(success=False,message='Acesso restrito não encontrado.'),404
            owner = account['id']
            if action=='assign':
                conflicts=[]
                for addr in emails:
                    existing=conn.execute('SELECT a.username,d.account_id FROM restricted_email_directory d JOIN netflix_admins a ON a.id=d.account_id WHERE d.email=?',(addr,)).fetchone()
                    if existing and existing['account_id']!=owner:
                        conflicts.append(addr+' — '+existing['username'])
                if conflicts:
                    return jsonify(success=False,message='Remova os vínculos anteriores antes de transferir:\n'+'\n'.join(conflicts)),409
                conn.executemany('INSERT OR IGNORE INTO restricted_email_directory(email,account_id) VALUES(?,?)',[(e,owner) for e in emails])
            else:
                conn.executemany('DELETE FROM restricted_email_directory WHERE email=? AND account_id=?',[(e,owner) for e in emails])
                conn.executemany('DELETE FROM restricted_status_links WHERE email=? AND owner=?',[(e,owner) for e in emails])
        return jsonify(success=True)

    @bp.post('/api/netflix-admin/status-link')
    @manager_only
    def create_status_link():
        current = g.netflix_manager
        if current['principal'] or current.get('kind') == 'panel':
            return jsonify(message='Use o acesso restrito.'),403
        data = request.get_json(silent=True) or {}
        addr = data.get('email') if isinstance(data,dict) else None
        if not isinstance(addr,str) or len(addr)>254:
            return jsonify(message='Informe um email válido.'),400
        addr = addr.strip().lower()
        blocked = app.config.get('RESTRICTED_STATUS_BLOCKED')
        if not blocked:
            return jsonify(message='Serviço indisponível.'),503
        token = secrets.token_urlsafe(32)
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT a.version FROM restricted_email_directory d JOIN netflix_admins a ON a.id=d.account_id WHERE d.email=? AND d.account_id=? AND a.active=1',(addr,current['id'])).fetchone()
            if not row or row['version']!=session.get('netflix_admin_version') or blocked(addr):
                return jsonify(message='Email não autorizado ou em quarentena.'),403
            inserted=conn.execute('INSERT OR IGNORE INTO restricted_status_links(email,owner,digest,expires,version,checked,sealed_token) VALUES (?,?,?,?,?,0,?)',(addr,current['id'],digest(token),0,row['version'],status_cipher().encrypt(token.encode()))).rowcount
            if not inserted:
                return jsonify(message='Já existe um link. Use Redefinir ou Apagar na sua lista.'),409
        return jsonify(success=True,url='https://'+HOST+'/status-mensagem#'+token)

    @bp.post('/api/netflix-admin/status-link/manage')
    @manager_only
    def manage_status_link():
        current = g.netflix_manager
        if current.get('kind') == 'panel':
            return jsonify(message='Sem permissão para gerenciar este link.'),403
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or data.get('action') not in ('copy','reset','delete') or not isinstance(data.get('email'),str) or len(data['email'])>254:
            return jsonify(message='Dados inválidos.'),400
        addr=data['email'].strip().lower()
        reset=data['action']=='reset'
        token=secrets.token_urlsafe(32) if reset else None
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row=conn.execute('SELECT l.owner,l.digest,l.sealed_token,l.version AS link_version,a.version,a.active FROM restricted_status_links l JOIN restricted_email_directory d ON d.email=l.email AND d.account_id=l.owner JOIN netflix_admins a ON a.id=l.owner WHERE l.email=? AND (?=1 OR (l.owner=? AND a.active=1 AND a.version=?))',(addr,int(current['principal']),current['id'],session.get('netflix_admin_version'))).fetchone()
            if not row: return jsonify(message='Link não encontrado.'),404
            if data['action']=='copy':
                blocked=app.config.get('RESTRICTED_STATUS_BLOCKED')
                if not row['active'] or row['link_version']!=row['version'] or not blocked or blocked(addr):
                    return jsonify(message='Link indisponível.'),403
                try:
                    original=status_cipher().decrypt(row['sealed_token']).decode() if row['sealed_token'] else ''
                except (OSError,ValueError,InvalidToken):
                    original=''
                if not original or digest(original)!=row['digest']:
                    return jsonify(message='A URL deste link antigo não pode ser recuperada. Use o link que já foi compartilhado ou redefina para criar um novo.'),409
                return jsonify(success=True,url='https://'+HOST+'/status-mensagem#'+original)
            if reset:
                blocked=app.config.get('RESTRICTED_STATUS_BLOCKED')
                if not row['active'] or not blocked or blocked(addr):
                    return jsonify(message='Acesso indisponível ou email em quarentena.'),403
                conn.execute('UPDATE restricted_status_links SET digest=?,expires=0,version=?,checked=0,sealed_token=? WHERE email=?',(digest(token),row['version'],status_cipher().encrypt(token.encode()),addr))
            else:
                conn.execute('DELETE FROM restricted_status_links WHERE email=?',(addr,))
        return jsonify(success=True,**({'url':'https://'+HOST+'/status-mensagem#'+token} if reset else {}))

    @bp.get('/status-mensagem')
    def status_link_page():
        return send_from_directory(app.static_folder,'restricted-status.html')

    @bp.route('/api/message-status', methods=['GET','POST'])
    def read_status_link():
        if request.headers.get('Origin') not in (None,'https://'+HOST): abort(403)
        auth = request.headers.get('Authorization','')
        if not re.fullmatch(r'Bearer [A-Za-z0-9_-]{43}',auth): abort(404)
        blocked = app.config.get('RESTRICTED_STATUS_BLOCKED')
        lookup = app.config.get('RESTRICTED_STATUS_LOOKUP')
        if not blocked or not lookup:
            return jsonify(status='unavailable',received_at=None),503
        key=digest(auth[7:])
        def valid(conn):
            row=conn.execute('SELECT l.email,l.checked FROM restricted_status_links l JOIN restricted_email_directory d ON d.email=l.email AND d.account_id=l.owner JOIN netflix_admins a ON a.id=l.owner AND a.version=l.version WHERE l.digest=? AND a.active=1',(key,)).fetchone()
            return row if row and not blocked(row['email']) else None
        if request.method == 'GET':
            with db() as conn:
                row=valid(conn)
            if not row: return jsonify(status='blocked'),404
            return jsonify(email=row['email'])
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row=valid(conn)
            if not row: return jsonify(status='blocked',received_at=None),404
            now=int(time.time())
            remaining=20-(now-row['checked'])
            if remaining>0: return jsonify(status='retry',received_at=None),429,{'Retry-After':str(min(20,remaining))}
            conn.execute('UPDATE restricted_status_links SET checked=? WHERE digest=?',(now,key))
        result=lookup(row['email'])
        with db() as conn:
            if not valid(conn): return jsonify(status='blocked',received_at=None),404
        from restricted_message_status import STATUS_FILTERS
        filters={key:result.get('filters',{})[key] for key in STATUS_FILTERS if key in result.get('filters',{})}
        return jsonify(status=result['status'],received_at=result['received_at'], **({'filters':filters} if filters else {}))

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
                    rows = conn.execute("SELECT l.*,CASE WHEN l.owner LIKE 'panel:%' THEN substr(l.owner,7) ELSE coalesce(a.username,'admin') END AS manager FROM links l LEFT JOIN netflix_admins a ON a.id=l.owner ORDER BY l.updated_at DESC,l.email").fetchall()
                else:
                    rows = conn.execute('SELECT l.*,? AS manager FROM links l WHERE owner=? ORDER BY updated_at DESC,email', (g.netflix_manager['username'], g.netflix_manager['id'])).fetchall()
            visible = app.config.get('EMAIL_POOL_VISIBLE_LINK')
            if visible:
                rows = [row for row in rows if visible(row['email'], g.netflix_manager)]
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
                    owner_picker = app.config.get('EMAIL_POOL_LINK_OWNER')
                    owner = owner_picker(email, g.netflix_manager) if owner_picker else g.netflix_manager['id']
                    conn.execute('INSERT INTO links(email,token,digest,created_at,updated_at,owner) VALUES(?,?,?,?,?,?)',
                                 (email, token, digest(token), now, now, owner))
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
            owner_picker = app.config.get('EMAIL_POOL_LINK_OWNER')
            reserved = app.config.get('EMAIL_POOL_RESERVED_EMAIL')
            owner = owner_picker(email, g.netflix_manager) if owner_picker and reserved and reserved(email) else current['owner']
            result = conn.execute('UPDATE links SET token=?,digest=?,updated_at=?,last_query=0,owner=? WHERE email=?',
                                  (token, digest(token), int(time.time()), owner, email))
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
        return jsonify(success=True, email=row['email'], filters=[{'key': p, 'label': NETFLIX_FILTER_LABELS[p]} for p in NETFLIX_PLATFORMS])

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
                if search_all is not None:
                    raw_results, errors = search_all(row['email'], list(NETFLIX_PLATFORMS))
                else:
                    code, link, platform, error = search(row['email'], list(NETFLIX_PLATFORMS))
                    raw_results = [{'code': code, 'link': link, 'platform': platform}] if code or link else []
                    errors = [error] if error and not str(error).lower().startswith('nenhum email encontrado') else []
            finally:
                strict_email_context.reset(marker)
        except Exception:
            return jsonify(success=False, message='Não foi possível consultar agora. Tente novamente.'), 503
        # A reset during IMAP lookup must revoke even the in-flight response.
        with db() as conn:
            current = authorized_row(conn)
        if not current:
            return jsonify(success=False, message='Este link foi redefinido. Use o novo link.'), 403
        results = []
        seen = set()
        for item in raw_results:
            platform = item.get('platform')
            if platform not in NETFLIX_PLATFORMS or platform in seen:
                continue
            label = NETFLIX_FILTER_LABELS[platform]
            if item.get('code'):
                results.append({'platform': platform, 'label': label, 'type': 'code', 'value': str(item['code'])})
                seen.add(platform)
            elif item.get('link'):
                try:
                    link = html.unescape(str(item['link']))
                    parsed = urlparse(link)
                    hostname = (parsed.hostname or '').lower()
                    safe = parsed.scheme == 'https' and (hostname == 'netflix.com' or hostname.endswith('.netflix.com'))
                    safe = safe and not parsed.username and not parsed.password and parsed.port in (None, 443)
                except ValueError:
                    safe = False
                if safe:
                    results.append({'platform': platform, 'label': label, 'type': 'link', 'value': link})
                    seen.add(platform)
        if results:
            results.sort(key=lambda item: NETFLIX_PLATFORMS.index(item['platform']))
            first = results[0]
            payload = {'success': True, 'results': results, 'platform': first['platform']}
            payload['code' if first['type'] == 'code' else 'link'] = first['value']
            if errors:
                payload['warning'] = 'Algumas caixas não puderam ser consultadas. Você pode tentar atualizar novamente.'
            return jsonify(**payload)
        if errors:
            return jsonify(success=False, message='Não foi possível consultar a caixa agora. Tente novamente.'), 503
        return jsonify(success=True, results=[], message='Nenhum código ou link Netflix recente encontrado. Faça a solicitação na Netflix e atualize aqui.')

    app.register_blueprint(bp)
