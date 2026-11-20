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
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending_email_bindings(email TEXT PRIMARY KEY,admin TEXT NOT NULL,client TEXT NOT NULL,digest TEXT UNIQUE NOT NULL,expires INTEGER NOT NULL);''')
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

    def panel_link_actor():
        username=actor()
        if username and username!='admin':
            return dict(principal=False,id='panel:'+username,username=username,
                        name=(load_users().get(username) or {}).get('name') or username,kind='panel')
        return None

    def shared_link_allowed(email):
        permission=store.permissions().get(norm(email));username=actor()
        if not permission or not username:return False
        return bool((username=='admin' or permission['admin_user']==username) and
                    source_allowed(norm(email),permission['admin_user'],load_users(),load_subscriptions()))

    def link_owner(email,current):
        permission=store.permissions().get(norm(email))
        return 'panel:'+permission['admin_user'] if permission else current['id']

    def visible_link(email,current):
        if current['principal']:return True
        permission=store.permissions().get(norm(email))
        if current.get('kind')=='panel':
            return bool(permission and permission['admin_user']==current['username'] and source_allowed(norm(email),current['username'],load_users(),load_subscriptions()))
        return not permission

    def revoke_link(email):
        path=os.path.join(data_dir,'netflix_links.sqlite3')
        if os.path.isfile(path):
            with sqlite3.connect(path,timeout=15) as conn:
                exists=conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='links'").fetchone()
                if exists:conn.execute('DELETE FROM links WHERE email=?',(norm(email),));conn.commit()

    app.config['EMAIL_POOL_RESERVED_LIST']=lambda:sorted(store.permissions())
    app.config['EMAIL_POOL_OWNER_ASSIGNMENT_OK']=lambda email,owner:source_allowed(norm(email),owner,load_users(),load_subscriptions())
    app.config['EMAIL_POOL_PANEL_LINK_ACTOR']=panel_link_actor
    app.config['EMAIL_POOL_LINK_CAN_SHARE']=shared_link_allowed
    app.config['EMAIL_POOL_LINK_OWNER']=link_owner
    app.config['EMAIL_POOL_VISIBLE_LINK']=visible_link

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
                              can_manage=can,can_assign=can and all(user==permission['admin_user'] for user in assigned),
                              assignment_state='reserved' if assigned==[permission['admin_user']] else 'unlinked' if not assigned else 'client',
                              quarantined=quarantine.is_blocked(email)))
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
                revoke_link(email)
                store.audit('admin','revoke',{'email':email})
        return jsonify(success=True,message='Permissão removida. O vínculo atual e o cliente foram preservados.')

    def mutation_guard(kind, kwargs, data):
        if kind not in ('panel-batch','panel-create','panel-renew','remove','delete-user','link-create','link-reset','link-remove'):
            return None
        username = actor()
        if kind=='link-remove' and username!='admin':
            if not central() or not username:
                return jsonify(success=False,message='Somente o subadmin responsável ou o admin principal pode excluir este email e link.'),403
            try:emails=parse(data.get('email'))
            except ValueError as error:return jsonify(success=False,message=str(error)),400
            if len(emails)!=1:
                return jsonify(success=False,message='Informe somente um email por exclusão.'),400
            email=emails[0]
            if not can_manage(email,username):
                return jsonify(success=False,message=DENIED),403
            path=os.path.join(data_dir,'netflix_links.sqlite3')
            if os.path.isfile(path):
                with sqlite3.connect(path,timeout=15) as conn:
                    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='links'").fetchone():
                        row=conn.execute('SELECT owner FROM links WHERE email=?',(email,)).fetchone()
                        if row and row[0]!='panel:'+username:
                            return jsonify(success=False,message='Este link não pertence ao seu admin.'),403
            subs=load_subscriptions();previous=[]
            for sub in subs:
                if isinstance(sub,dict) and norm(sub.get('email'))==email:
                    previous.append(norm(sub.get('assigned_user')))
            # Revoke bearer access first. If JSON persistence fails, retrying the
            # same request completes the unlink even though the link is gone.
            revoke_link(email)
            for sub in subs:
                if isinstance(sub,dict) and norm(sub.get('email'))==email:
                    sub['assigned_user']='';sub['assigned_user_name']=''
            if any(previous) and save_subscriptions(subs) is False:
                return jsonify(success=False,message='O link foi invalidado, mas não foi possível remover o vínculo. Clique em excluir novamente para concluir.'),503
            invalidate=app.config.get('EMAIL_POOL_BINDINGS_CHANGED')
            if invalidate:invalidate(set(previous)|{username})
            store.audit(username,'delete-client-link',{'email':email,'previous_users':previous})
            return jsonify(success=True,email=email,message='Email removido do cliente e link excluído. O usuário foi preservado e o email continua na sua lista permitida.')
        if kind in ('link-create','link-reset'):
            # Dedicated legacy link sessions never inherit a panel user's identity.
            if username=='admin':return None
            if not username:
                if kind=='link-reset' and not store.permissions().get(norm(data.get('email'))):return None
                return jsonify(success=False,message='Para gerar links, entre com o subadmin do painel e use somente os emails liberados pelo admin principal.'),403
            try:emails=parse(data.get('emails',data.get('email')) if kind=='link-create' else data.get('email'))
            except ValueError as error:return jsonify(success=False,message=str(error)),400
            if any(not can_manage(email,username) or quarantine.is_blocked(email) for email in emails):
                return jsonify(success=False,message='Você só pode gerar ou redefinir links dos emails que o admin principal liberou na sua lista.'),403
            return None
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
        missing = [email for email in emails if not can_manage(email,username)]
        if missing:
            prepare = app.config.get('EMAIL_POOL_PREPARE_CONFIRMATION')
            if kind == 'panel-batch' and prepare and len(missing) == len(emails):
                target = norm(data.get('assigned_user'))
                if target not in clients_of(username,load_users()):
                    return jsonify(success=False,message='Selecione um cliente que você gerencia.'),403
                return prepare(username,target,emails)
            return jsonify(success=False,message=DENIED),403
        if kind in ('panel-batch','panel-create'):
            target = norm(data.get('assigned_user'));users = load_users()
            if target not in clients_of(username,users):
                return jsonify(success=False,message='Selecione um cliente criado pelo seu próprio admin.'),403
            if any(quarantine.is_blocked(email) for email in emails):
                return jsonify(success=False,message='Esse email está na lista que não pode receber códigos.'),403
            # Reservations belong to the subadmin, not to another customer.
            # Apply the entire validated batch once while the shared registration
            # lock is held by email_uniqueness. No pre-unlink or duplicate row.
            subs=load_subscriptions();by_email={}
            for index,sub in enumerate(subs):
                if isinstance(sub,dict):by_email.setdefault(norm(sub.get('email')),[]).append(index)
            conflicts=[]
            for email in emails:
                indices=by_email.get(email,[])
                if len(indices)>1 or any(norm(subs[index].get('assigned_user')) not in ('',username,target) for index in indices):
                    conflicts.append(email)
            link_path=os.path.join(data_dir,'netflix_links.sqlite3')
            if os.path.isfile(link_path):
                with sqlite3.connect(link_path,timeout=15) as conn:
                    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='links'").fetchone():
                        for email in emails:
                            row=conn.execute('SELECT owner FROM links WHERE email=?',(email,)).fetchone()
                            if row and row[0]!='panel:'+username:conflicts.append(email)
            if conflicts:
                return jsonify(success=False,duplicate=True,created=0,updated=0,skipped=0,conflict_emails=sorted(set(conflicts)),
                    message='Este email já está vinculado a outro cliente ou acesso. Remova o vínculo antigo antes de continuar.'),409
            now=int(time.time());created=updated=unchanged=0;previous={}
            for email in emails:
                indices=by_email.get(email,[])
                if indices:
                    sub=subs[indices[0]];prior=norm(sub.get('assigned_user'));previous[email]=prior
                    if prior==target:unchanged+=1
                    else:
                        sub['assigned_user']=target;sub['assigned_user_name']=users[target].get('name') or target
                        updated+=1
                else:
                    days=3650 if kind=='panel-batch' else 30
                    try:days=max(1,int(data.get('dur_days') or days))
                    except (ValueError,TypeError):pass
                    try:value=float(str(data.get('valor') or 0).replace(',','.'))
                    except (ValueError,TypeError):value=0
                    sub=dict(email=email,assigned_user=target,assigned_user_name=users[target].get('name') or target,
                        created_at=now,start_at=now,expires_at=now+days*86400,dur_days=days,show_in_panel=False,
                        plataforma=str(data.get('plataforma') or 'Conta vinculada')[:40],cliente=str(data.get('cliente') or '')[:80],
                        telefone=str(data.get('telefone') or '')[:30],senha=str(data.get('senha') or '')[:80],
                        valor=value,renew_pix_txid=None,renew_count=0)
                    if kind=='panel-create' and data.get('expires_date'):
                        try:
                            from datetime import datetime
                            sub['expires_at']=int(datetime.strptime(str(data['expires_date']),'%Y-%m-%d').replace(hour=23,minute=59,second=59).timestamp())
                        except (ValueError,TypeError):
                            return jsonify(success=False,message='Data de vencimento inválida. Nenhum vínculo foi alterado.'),400
                    subs.append(sub);created+=1;previous[email]=''
            if (created or updated) and save_subscriptions(subs) is False:
                return jsonify(success=False,message='Não foi possível salvar o vínculo. Tente novamente.'),503
            g.email_pool_claims={'actor':username,'emails':emails,'target':target,'previous_users':previous}
            invalidate=app.config.get('EMAIL_POOL_BINDINGS_CHANGED')
            if invalidate:invalidate(set(previous.values())|{username,target})
            message=f'Emails vinculados com sucesso ao cliente {users[target].get("name") or target}.'
            payload=dict(success=True,message=message,assigned_user=target,assigned_user_name=users[target].get('name') or target,
                created=created,updated=updated,unchanged=unchanged,skipped=0,invalid=0,duplicates=0,conflict_emails=[],total=len(emails))
            if kind=='panel-create':payload['subscription']=next(sub for sub in subs if isinstance(sub,dict) and norm(sub.get('email'))==emails[0])
            return jsonify(payload)
        if kind=='remove':
            email = emails[0];subs = load_subscriptions();matched = [s for s in subs if isinstance(s,dict) and norm(s.get('email'))==email]
            if not matched:
                return jsonify(success=False,message='Email não encontrado.'),404
            previous = [norm(s.get('assigned_user')) for s in matched]
            revoke_link(email)
            for sub in matched:
                sub['assigned_user']='';sub['assigned_user_name']=''
            if save_subscriptions(subs) is False:
                return jsonify(success=False,message='Não foi possível salvar a remoção do vínculo.'),503
            store.audit(username,'unlink',{'email':email,'previous_users':previous})
            return jsonify(success=True,message='Vínculo removido. O email continua na sua lista e pode ser vinculado a outro cliente.')
        return None

    def partial_batch(data, existing_links, original):
        username = actor()
        if not username:
            return jsonify(success=False, message='A conta da sessão não tem mais o perfil de administrador. Entre novamente com sua conta de administrador.'), 403
        if 'admin_session' in data and norm(data['admin_session']) != username:
            return jsonify(success=False, message='A conta ativa mudou desde que você abriu o formulário. Reabra o painel com a conta de administrador que gerencia esse cliente.'), 403
        target = norm(data.get('assigned_user'))
        users = load_users()
        if target not in users or (username != 'admin' and target not in clients_of(username, users)):
            return jsonify(success=False, message='Selecione um usuário que você pode gerenciar.'), 403
        raw = data.get('emails')
        if isinstance(raw, str):
            raw = raw.splitlines()
        if not isinstance(raw, list) or len(raw) > 200 or sum(len(str(item)) for item in raw) > 60000:
            return jsonify(success=False, message='Informe uma lista de até 200 emails.'), 400
        groups = {key: [] for key in ('linked', 'registered', 'blocked', 'invalid', 'retry')}
        seen = set()
        by_email = {}
        for sub in load_subscriptions():
            if isinstance(sub, dict):
                by_email.setdefault(norm(sub.get('email')), []).append(sub)
        permissions = store.permissions()
        blocked = quarantine.emails()
        with store.connect() as conn:
            pending = {row['email'] for row in conn.execute('SELECT email FROM pending_email_bindings WHERE expires>?', (time.time(),))}
        groups['already_pending'] = []
        direct, confirm = [], []
        for item in raw:
            email = norm(item)
            if not email or email in seen:
                continue
            seen.add(email)
            rows = by_email.get(email, [])
            reservation = permissions.get(email)
            reserved_here = reservation and reservation['admin_user'] == (target if username == 'admin' else username)
            if not isinstance(item, str) or len(email) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
                groups['invalid'].append(email)
            elif quarantine.matches(email, blocked):
                groups['blocked'].append(email)
            elif (email in existing_links or len(rows) > 1 or any(norm(row.get('assigned_user')) for row in rows)
                  or (reservation and not reserved_here) or (rows and username != 'admin' and not reserved_here)):
                groups['registered'].append(email)
            elif email in pending:
                groups['already_pending'].append(email)
            elif username == 'admin' or reserved_here:
                direct.append(email)
            else:
                confirm.append(email)

        details = {}
        if username == 'admin':
            for email in groups['registered']:
                owners = sorted({norm(row.get('assigned_user')) for row in by_email.get(email, []) if norm(row.get('assigned_user'))})
                details[email] = {'assigned_users': owners, 'has_link': email in existing_links}
        if direct:
            # The uniqueness wrapper holds the same registration lock used by
            # confirmation and delegation. Preserve it across classification and save.
            data['emails'] = direct
            try:
                result = app.make_response(original() if username == 'admin' else mutation_guard('panel-batch', {}, data))
            finally:
                data['emails'] = raw
            if result.status_code == 200 and (result.get_json(silent=True) or {}).get('success'):
                groups['linked'] = direct
                invalidate = app.config.get('EMAIL_POOL_BINDINGS_CHANGED')
                if invalidate and username == 'admin':
                    invalidate({target})
            else:
                groups['retry'] = direct
        prepare = app.config.get('EMAIL_POOL_PREPARE_CONFIRMATION')
        if confirm and prepare:
            response = app.make_response(prepare(username, target, confirm, partial=True))
            for key, addresses in (response.get_json(silent=True) or {}).get('batch_results', {}).items():
                groups.setdefault(key, []).extend(addresses)
        elif confirm:
            groups['retry'].extend(confirm)
        linked = len(groups['linked'])
        sent = len(groups.get('confirmation_sent', []))
        return jsonify(success=bool(linked or sent), created=linked, pending=sent, batch_results=groups,
                       conflicts=details, message='Resultado da vinculação em lote.'), (200 if linked else 202 if sent else 503 if groups['retry'] or groups.get('send_failed') else 409)

    app.config['EMAIL_POOL_PARTIAL_BATCH'] = partial_batch
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
                if 'batch_results' in result:
                    requested = set(result['batch_results']['linked'])
                else:
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
