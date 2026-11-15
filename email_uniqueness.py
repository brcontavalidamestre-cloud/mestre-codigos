"""Central-only uniqueness across panel subscriptions and individual Netflix links.
Serialize participating mutations across Gunicorn processes without changing the
existing JSON or SQLite schemas. Existing duplicate rows are never deleted.
"""
import fcntl
import os
import re
import sqlite3
import threading
import time
from functools import wraps
from flask import g, jsonify, request, session

HOST = 'consulta-codigos-jr7z.onrender.com'
DUPLICATE_MESSAGE = 'Este email já está cadastrado nos links ou no painel. Não é permitido duplicar. Somente o administrador principal pode remover o cadastro existente.'
REMOVE_MESSAGE = 'Somente o administrador principal pode remover emails e vínculos.'


def register_email_uniqueness(app, data_dir, load_subscriptions):
    lock = threading.RLock()
    lock_path = os.path.join(data_dir, '.email-registration.lock')
    links_path = os.path.join(data_dir, 'netflix_links.sqlite3')

    def principal():
        return bool(session.get('logged_in') and session.get('role') == 'admin' and session.get('username') == 'admin')

    def panel_admin():
        return bool(session.get('logged_in') and session.get('role') == 'admin')

    def link_manager():
        if principal():
            return True
        panel_actor = app.config.get('EMAIL_POOL_PANEL_LINK_ACTOR')
        if panel_actor and panel_actor():
            return True
        if not session.get('netflix_admin_id') or int(session.get('netflix_admin_expires') or 0) <= int(time.time()):
            return False
        if not os.path.isfile(links_path):
            return False
        conn = sqlite3.connect('file:' + links_path + '?mode=ro', uri=True, timeout=15)
        try:
            row = conn.execute('SELECT version,active FROM netflix_admins WHERE id=?', (session['netflix_admin_id'],)).fetchone()
            return bool(row and row[1] and row[0] == session.get('netflix_admin_version'))
        finally:
            conn.close()

    def links():
        if not os.path.isfile(links_path):
            return set()
        conn = sqlite3.connect('file:' + links_path + '?mode=ro', uri=True, timeout=15)
        try:
            return {str(row[0]).strip().lower() for row in conn.execute('SELECT email FROM links')}
        finally:
            conn.close()

    def conflict(emails):
        emails = list(dict.fromkeys(emails))
        message = DUPLICATE_MESSAGE
        if app.config.get('EMAIL_POOL_MUTATION_GUARD') and panel_admin() and not principal():
            message = 'Este email já está cadastrado nos links ou no painel. Remova o vínculo antigo antes de vincular a outro cliente. Você só pode remover vínculos dos emails da sua lista permitida; links individuais só podem ser excluídos pelo admin principal.'
        return jsonify(success=False, duplicate=True, message=message,
                       duplicate_emails=emails, created=0, updated=0, items=[]), 409

    def wrap_endpoint(endpoint, kind):
        original = app.view_functions.get(endpoint)
        if original is None:
            return

        @wraps(original)
        def guarded(*args, **kwargs):
            if request.host.lower().split(':', 1)[0] != HOST or request.method not in ('POST', 'DELETE', 'PUT'):
                return original(*args, **kwargs)
            authenticated = link_manager() if kind.startswith('link') else panel_admin()
            if kind == 'internal':
                # The original route validates the internal credential; check it
                # here too so an unauthenticated caller cannot enumerate emails.
                authenticated = request.headers.get('X-Loja-Proxy-Token') == app.config.get('EMAIL_UNIQUENESS_INTERNAL_TOKEN')
            if not authenticated:
                return original(*args, **kwargs)
            if request.headers.get('Origin') not in (None, 'https://' + HOST):
                return jsonify(success=False, message='Origem não permitida.'), 403
            os.makedirs(data_dir, exist_ok=True)
            with lock, open(lock_path, 'a', encoding='utf-8') as handle:
                os.chmod(lock_path, 0o600)
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    data = request.get_json(silent=True) or {}
                    data = data if isinstance(data, dict) else {}
                    permission_guard = app.config.get('EMAIL_POOL_MUTATION_GUARD')
                    if permission_guard:
                        guarded_response = permission_guard(kind, kwargs, data)
                        if guarded_response is not None:
                            return guarded_response
                    if kind in ('remove', 'link-remove') and not principal():
                        return jsonify(success=False, message=REMOVE_MESSAGE), 403
                    subscriptions = [s for s in load_subscriptions() if isinstance(s, dict) and s.get('email')]
                    panel_emails = {str(s['email']).strip().lower() for s in subscriptions}
                    if kind in ('link-create', 'panel-create', 'panel-batch', 'internal'):
                        all_links = links()
                        if kind == 'link-create':
                            raw = data.get('emails', data.get('email', ''))
                        elif kind == 'panel-batch':
                            raw = data.get('emails', [])
                        else:
                            raw = data.get('email', '')
                        if isinstance(raw, list):
                            raw = '\n'.join(str(v) for v in raw)
                        if not isinstance(raw, str) or len(raw) > 60000:
                            return jsonify(success=False, message='Informe uma lista válida de emails.'), 400
                        candidates = [s.lower().strip() for s in re.split(r'[\s,;]+', raw) if s.strip()]
                        if kind == 'link-create':
                            share = app.config.get('EMAIL_POOL_LINK_CAN_SHARE')
                            repeated = [email for email in candidates if email in all_links or (email in panel_emails and not (share and share(email)))]
                        elif kind == 'internal':
                            # Paid-delivery retries are idempotent for the same
                            # already-bound customer, but can never steal a link.
                            target = str(data.get('assigned_user') or '').strip().lower()
                            repeated = [email for email in candidates if email in all_links]
                            for email in candidates:
                                owners = [str(s.get('assigned_user') or '').strip().lower() for s in subscriptions if str(s['email']).strip().lower() == email]
                                if len(owners) > 1 or (owners and owners[0] and owners[0] != target):
                                    repeated.append(email)
                        else:
                            # An unlinked delegated record retains its metadata;
                            # claiming it updates the SAME row, never duplicates it.
                            claims = getattr(g, 'email_pool_claims', None)
                            delegated = set(claims['emails']) if claims else set()
                            available = {email for email in delegated if sum(1 for s in subscriptions if str(s['email']).strip().lower()==email)==1 and all(not str(s.get('assigned_user') or '').strip() for s in subscriptions if str(s['email']).strip().lower()==email)} if kind == 'panel-batch' else set()
                            repeated = [email for email in candidates if email in all_links or (email in panel_emails and email not in available)]
                        if repeated:
                            return conflict(repeated)
                    if kind == 'delete-user' and not principal():
                        user = str(kwargs.get('username') or '').strip().lower()
                        if any(str(s.get('assigned_user') or '').strip().lower() == user for s in subscriptions):
                            return jsonify(success=False, message='Este usuário possui emails vinculados. Somente o administrador principal pode removê-los.'), 403
                    return original(*args, **kwargs)
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        app.view_functions[endpoint] = guarded

    for endpoint, kind in (
        ('netflix_links.admin_links', 'link-create'),
        ('netflix_links.admin_delete', 'link-remove'),
        ('netflix_links.admin_reset', 'link-reset'),
        ('api_admin_import_vinculos_emails', 'panel-batch'),
        ('api_admin_add_subscription', 'panel-create'),
        ('api_admin_delete_vinculo_email', 'remove'),
        ('api_admin_delete_subscription', 'remove'),
        ('api_admin_renew_subscription', 'panel-renew'),
        ('api_internal_loja_vinculo', 'internal'),
        ('api_delete_user', 'delete-user'),
    ):
        wrap_endpoint(endpoint, kind)
