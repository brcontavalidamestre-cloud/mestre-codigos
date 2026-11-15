"""Explicit, persistent per-subadmin email permissions on the central host only.
Delegation never changes user accounts. Unlink retains the email and metadata.
"""
import fcntl
import json
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from functools import wraps
from flask import Blueprint, abort, g, jsonify, redirect, request, session, send_from_directory

HOST = 'consulta-codigos-jr7z.onrender.com'
DENIED = 'Você só pode alterar os emails da lista que o admin principal liberou para você.'


def norm(value):
    return str(value or '').strip().lower()


class EmailPoolStore:
    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, 'email_admin_permissions.sqlite3')
        self.lock_path = os.path.join(data_dir, '.email-registration.lock')
        self.lock = threading.RLock()

    @contextmanager
    def connect(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.executescript('''CREATE TABLE IF NOT EXISTS permissions(email TEXT PRIMARY KEY,admin_user TEXT NOT NULL,created_at INTEGER NOT NULL,created_by TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,created_at INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);''')
        os.chmod(self.path, 0o600)
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def serialized(self):
        os.makedirs(os.path.dirname(self.path),exist_ok=True)
        with self.lock, open(self.lock_path, 'a') as handle:
            os.chmod(self.lock_path, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def permissions(self):
        with self.connect() as conn:
            return {row['email']: dict(row) for row in conn.execute('SELECT * FROM permissions')}

    def bootstrap(self, subscriptions, users):
        # Legacy bindings have no reliable author provenance. Never turn
        # historical/self-added emails into permissions without principal approval.
        with self.serialized(), self.connect() as conn:
            conn.execute("INSERT OR IGNORE INTO metadata VALUES('principal_defined_only','1')")
            conn.commit()

    def audit(self, actor, action, payload):
        with self.connect() as conn:
            conn.execute('INSERT INTO events(created_at,actor,action,payload) VALUES(?,?,?,?)',
                         (int(time.time()),actor,action,json.dumps(payload,ensure_ascii=False)))
            conn.commit()


def register_email_delegation(app, data_dir, load_subscriptions, save_subscriptions, load_users, quarantine):
    store = EmailPoolStore(data_dir)
    store.bootstrap(load_subscriptions(), load_users())
    bp = Blueprint('email_delegation', __name__)

    def central():
        return request.host.lower().split(':', 1)[0] == HOST

    def actor():
        if not session.get('logged_in') or session.get('role') != 'admin':
            return ''
        username = norm(session.get('username'))
        return username if (load_users().get(username) or {}).get('role') == 'admin' else ''

    def admin_only(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not central():
                abort(404)
            if not actor():
                if request.path == '/admin/emails-subadmins' and not session.get('logged_in'):
                    return redirect('/login')
                return jsonify(success=False,message='Acesso restrito ao administrador.'),403
            if request.method != 'GET' and request.headers.get('Origin') not in (None,'https://'+HOST):
                return jsonify(success=False,message='Origem não permitida.'),403
            return fn(*args,**kwargs)
        return wrapped

    def clients_of(username, users):
        return {name for name,user in users.items() if norm(user.get('created_by')) == username and user.get('role','client') == 'client'}

    def source_allowed(email, username, users, subscriptions):
        own_clients = clients_of(username,users)
        return all(not norm(sub.get('assigned_user')) or norm(sub.get('assigned_user')) in own_clients|{username}
                   for sub in subscriptions if isinstance(sub,dict) and norm(sub.get('email')) == email)

    def can_manage(email, username=None):
        username = username or actor();email = norm(email)
        if not username:
            return False
        if username == 'admin':
            return True
        row = store.permissions().get(email)
        return bool(row and row['admin_user'] == username and source_allowed(email,username,load_users(),load_subscriptions()))

    def parse(raw):
        if isinstance(raw,list):
            raw = '\n'.join(str(v) for v in raw)
        if not isinstance(raw,str) or len(raw)>60000:
            raise ValueError('Informe uma lista de até 200 emails.')
        emails = list(dict.fromkeys(norm(v) for v in re.split(r'[\s,;]+',raw) if v.strip()))
        if not emails or len(emails)>200 or any(len(e)>254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',e) for e in emails):
            raise ValueError('Informe de 1 a 200 emails válidos. Nenhuma alteração foi aplicada.')
        return emails

    @bp.get('/admin/emails-subadmins')
    @admin_only
    def page():
        return send_from_directory(app.static_folder,'email-delegation.html')

    @bp.get('/api/admin/email-pool')
    @admin_only
    def listing():
        username = actor();principal = username == 'admin';users = load_users()
        selected = norm(request.args.get('admin_user')) if principal else username
        admins = [dict(username=name,name=user.get('name') or name) for name,user in users.items() if name!='admin' and user.get('role')=='admin'] if principal else []
        if principal and selected and selected not in {r['username'] for r in admins}:
            return jsonify(success=False,message='Subadmin não encontrado.'),404
        subscriptions = load_subscriptions();items = []
        for email,permission in store.permissions().items():
            if (selected and permission['admin_user']!=selected) or (not principal and permission['admin_user']!=username):
                continue
            records = [s for s in subscriptions if isinstance(s,dict) and norm(s.get('email'))==email]
            assigned = sorted({norm(s.get('assigned_user')) for s in records if norm(s.get('assigned_user'))})
            can = source_allowed(email,permission['admin_user'],users,subscriptions)
            items.append(dict(email=email,admin_user=permission['admin_user'],created_at=permission['created_at'],
                              assigned_users=assigned,assigned_names=[(users.get(u) or {}).get('name') or u for u in assigned],
                              can_manage=can,quarantined=quarantine.is_blocked(email)))
        items.sort(key=lambda item:(item['admin_user'],item['email']))
        clients = [dict(username=name,name=(users.get(name) or {}).get('name') or name) for name in sorted(clients_of(selected,users))] if selected else []
        direct_emails = sorted({norm(s.get('email')) for s in subscriptions if isinstance(s,dict) and selected and norm(s.get('assigned_user'))==selected and norm(s.get('email'))}) if principal else []
        return jsonify(success=True,principal=principal,admin_user=selected,admins=admins,items=items,clients=clients,direct_emails=direct_emails)

    @bp.post('/api/admin/email-pool/grant')
    @admin_only
    def grant():
        if actor()!='admin':
            return jsonify(success=False,message='Somente o admin principal pode alterar a lista permitida.'),403
        data = request.get_json(silent=True) or {}
        if not isinstance(data,dict):
            return jsonify(success=False,message='Dados inválidos.'),400
        target = norm(data.get('admin_user'));users = load_users()
        if target=='admin' or (users.get(target) or {}).get('role')!='admin':
            return jsonify(success=False,message='Selecione um subadmin válido.'),400
        try:
            emails = parse(data.get('emails'))
        except ValueError as error:
            return jsonify(success=False,message=str(error)),400
        with store.serialized():
            existing = store.permissions();subscriptions = load_subscriptions()
            conflicts = [email for email in emails if (email in existing and existing[email]['admin_user']!=target) or not source_allowed(email,target,users,subscriptions)]
            if conflicts:
                return jsonify(success=False,message='Há emails de outra lista ou vinculados a outro responsável. Remova a permissão ou o vínculo anterior antes de liberar.',conflict_emails=conflicts),409
            with store.connect() as conn:
                for email in emails:
                    conn.execute('INSERT OR IGNORE INTO permissions VALUES(?,?,?,?)',(email,target,int(time.time()),'admin'))
                conn.commit()
            store.audit('admin','grant',{'admin_user':target,'emails':emails})
        return jsonify(success=True,message=f'{len(emails)} email(s) na lista permitida de {target}.')

    @bp.post('/api/admin/email-pool/revoke')
    @admin_only
    def revoke():
        if actor()!='admin':
            return jsonify(success=False,message='Somente o admin principal pode alterar a lista permitida.'),403
        data = request.get_json(silent=True) or {};email = norm(data.get('email')) if isinstance(data,dict) else ''
        with store.serialized(), store.connect() as conn:
            deleted = conn.execute('DELETE FROM permissions WHERE email=?',(email,)).rowcount
            conn.commit()
            if deleted:
                store.audit('admin','revoke',{'email':email})
        return jsonify(success=True,message='Permissão removida. O vínculo atual e o cliente foram preservados.')

    def mutation_guard(kind, kwargs, data):
        if kind not in ('panel-batch','panel-create','panel-renew','remove','delete-user'):
            return None
        username = actor()
        if not central() or username=='admin':
            return None
        if not username:
            return jsonify(success=False,message='Acesso restrito ao administrador.'),403
        if kind=='delete-user':
            return jsonify(success=False,message='Subadmins não podem excluir usuários. Você pode apenas transferir os emails da sua lista.'),403
        if kind not in ('panel-batch','panel-create','panel-renew','remove'):
            return None
        try:
            emails = parse(data.get('emails') if kind=='panel-batch' else data.get('email') if kind=='panel-create' else kwargs.get('email'))
        except ValueError as error:
            return jsonify(success=False,message=str(error)),400
        if any(not can_manage(email,username) for email in emails):
            return jsonify(success=False,message=DENIED),403
        if kind in ('panel-batch','panel-create'):
            target = norm(data.get('assigned_user'));users = load_users()
            if target not in clients_of(username,users):
                return jsonify(success=False,message='Selecione um cliente criado pelo seu próprio admin.'),403
            if any(quarantine.is_blocked(email) for email in emails):
                return jsonify(success=False,message='Esse email está na lista que não pode receber códigos.'),403
            g.email_pool_claims = {'actor':username,'emails':emails,'target':target}
        if kind=='remove':
            email = emails[0];subs = load_subscriptions();matched = [s for s in subs if isinstance(s,dict) and norm(s.get('email'))==email]
            if not matched:
                return jsonify(success=False,message='Email não encontrado.'),404
            previous = [norm(s.get('assigned_user')) for s in matched]
            for sub in matched:
                sub['assigned_user']='';sub['assigned_user_name']=''
            if save_subscriptions(subs) is False:
                return jsonify(success=False,message='Não foi possível salvar a remoção do vínculo.'),503
            store.audit(username,'unlink',{'email':email,'previous_users':previous})
            return jsonify(success=True,message='Vínculo removido. O email continua na sua lista e pode ser vinculado a outro cliente.')
        return None

    app.config['EMAIL_POOL_MUTATION_GUARD'] = mutation_guard
    app.config['EMAIL_POOL_CAN_MANAGE'] = can_manage

    @app.before_request
    def protect_user_admin_routes():
        if not central() or not session.get('logged_in') or session.get('role')!='admin' or actor()=='admin':
            return None
        if request.path.startswith('/api/admin/backup/'):
            return jsonify(success=False,message='Somente o admin principal pode importar ou exportar backups.'),403
        if request.endpoint=='api_admin_user_direct_link' and request.method=='POST':
            target = norm((request.view_args or {}).get('username'));username = actor()
            if target!=username and target not in clients_of(username,load_users()):
                return jsonify(success=False,message='Sem permissão para acessar este usuário.'),403

    @app.after_request
    def remember_explicit_assignments(response):
        if not central() or not response.is_json or not 200<=response.status_code<300:
            return response
        result = response.get_json(silent=True) or {}
        if not isinstance(result,dict) or not result.get('success'):
            return response
        claims = getattr(g,'email_pool_claims',None)
        if claims:
            store.audit(claims['actor'],'bind',claims)
        # Future emails explicitly linked by the principal directly to a
        # subadmin also become part of that admin's permission list.
        if actor()=='admin' and request.method=='POST' and request.endpoint in ('api_admin_import_vinculos_emails','api_admin_add_subscription'):
            data = request.get_json(silent=True) or {};target = norm(data.get('assigned_user'));users = load_users()
            if target!='admin' and (users.get(target) or {}).get('role')=='admin':
                try:
                    requested=set(parse(data.get('emails') if request.endpoint=='api_admin_import_vinculos_emails' else data.get('email')))
                except ValueError:
                    requested=set()
                with store.serialized(),store.connect() as conn:
                    for sub in load_subscriptions():
                        if isinstance(sub,dict) and norm(sub.get('assigned_user'))==target and norm(sub.get('email')) in requested:
                            email = norm(sub.get('email'))
                            conn.execute('INSERT INTO permissions VALUES(?,?,?,?) ON CONFLICT(email) DO UPDATE SET admin_user=excluded.admin_user,created_at=excluded.created_at,created_by=excluded.created_by',(email,target,int(time.time()),'admin'))
                    conn.commit()
        if request.path.startswith('/api/admin/email-pool'):
            response.headers['Cache-Control']='no-store'
        return response

    app.register_blueprint(bp)
    return store
