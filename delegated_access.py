"""Enforce exclusive pool ownership across queries, inbox caches and bearer links."""
import html
import quopri
import re
from delegated_recipients import recipients
from flask import g, has_request_context, jsonify, request, session

HOST='consulta-codigos-jr7z.onrender.com'
MESSAGE='Este email é exclusivo do admin responsável e dos clientes vinculados a ele.'
QUERY_PATHS={'/api/get-code','/api/admin/get-code','/api/verify-reset-pin','/api/instaddr/browser-search','/api/instaddr/browser-fetch'}
INBOX_PATHS={'/api/live-inbox/messages','/api/admin/live-inbox/messages','/api/admin/live-inbox/allowed'}


def register_delegated_access(app,pool_store,load_users,load_subscriptions,pending_resets):
    def central():return has_request_context() and request.host.lower().split(':',1)[0]==HOST
    def permissions(fresh=False):
        if not has_request_context():return pool_store.permissions()
        if fresh or not hasattr(g,'delegated_permissions'):g.delegated_permissions=pool_store.permissions()
        return g.delegated_permissions
    def users():
        if not hasattr(g,'delegated_users'):g.delegated_users=load_users()
        return g.delegated_users
    def consult_allowed(email,username=None):
        email=str(email or '').strip().lower();permission=permissions().get(email)
        username=str(username or session.get('username') or '').strip().lower()
        account=users().get(username) or {}
        # Free admin consultation is unrestricted only for the principal.
        # Other admins require an exact, principal-defined pool permission.
        if central() and request.path=='/api/admin/get-code' and account.get('role')=='admin' and username!='admin':
            return bool(permission and permission['admin_user']==username)
        if not permission:return True
        owner=permission['admin_user']
        if username=='admin' and account.get('role')=='admin':return True
        if username==owner and account.get('role')=='admin':return True
        if account.get('role')!='client' or account.get('created_by')!=owner:return False
        assigned=[s for s in load_subscriptions() if isinstance(s,dict) and str(s.get('email') or '').strip().lower()==email]
        return bool(assigned and all(str(s.get('assigned_user') or '').strip().lower()==username for s in assigned))
    def reserved(email):return permissions().get(str(email or '').strip().lower())
    def link_allowed(row):
        permissions(fresh=True)
        permission=reserved(row['email'])
        if permission:
            assignment_ok=app.config.get('EMAIL_POOL_OWNER_ASSIGNMENT_OK')
            valid=row['owner']=='panel:'+permission['admin_user'] and (not assignment_ok or assignment_ok(row['email'],permission['admin_user']))
            if session.get('logged_in'):
                username=str(session.get('username') or '').strip().lower();account=users().get(username) or {}
                same_group=username in ('admin',permission['admin_user']) or (account.get('role')=='client' and account.get('created_by')==permission['admin_user'])
                valid=valid and same_group
        else:
            # A revoked pool permission can never revive an old delegated token.
            valid=not str(row['owner']).startswith('panel:')
        if valid and central():g.delegated_link_email=row['email']
        return valid
    def message_allowed(msg,body=''):
        if not central():return True
        found=recipients(msg,body);rules=permissions()
        g.delegated_recipient_checks=getattr(g,'delegated_recipient_checks',set())|found.intersection(rules)
        for email in found.intersection(rules):
            if getattr(g,'delegated_link_email',None)==email:continue
            if not consult_allowed(email):return False
        return True
    app.config['EMAIL_POOL_CONSULT_ALLOWED']=consult_allowed
    app.config['EMAIL_POOL_RESERVED_EMAIL']=reserved
    app.config['EMAIL_POOL_LINK_ACCESS']=link_allowed
    app.config['EMAIL_POOL_MESSAGE_ALLOWED']=message_allowed

    def query_email():
        data=request.get_json(silent=True) or {};data=data if isinstance(data,dict) else {}
        value=data.get('email') or request.args.get('email') or ''
        if request.path=='/api/verify-reset-pin':
            entry=pending_resets.get(session.get('username')) or {};value=entry.get('email') or value
        return str(value).strip().lower()
    def denied():return jsonify(success=False,message=MESSAGE,delegated=True,items=[],results=[],count=0),403

    @app.before_request
    def exclusive_queries():
        if not central() or request.path not in QUERY_PATHS:return None
        g.delegated_query_email=query_email()
        if not consult_allowed(g.delegated_query_email):return denied()
        if request.path=='/api/admin/get-code' and session.get('role')=='admin' and session.get('username')!='admin':
            from netflix_links import strict_email_context
            g.delegated_admin_exact_token=strict_email_context.set(g.delegated_query_email)

    @app.teardown_request
    def clear_admin_exact_context(error=None):
        token=getattr(g,'delegated_admin_exact_token',None)
        if token is not None:
            from netflix_links import strict_email_context
            strict_email_context.reset(token)
            del g.delegated_admin_exact_token

    @app.after_request
    def exclusive_responses(response):
        if not central():return response
        if request.path in QUERY_PATHS:
            permissions(fresh=True)
            if hasattr(g,'delegated_users'):del g.delegated_users
            if not consult_allowed(getattr(g,'delegated_query_email',None) or query_email()) or any(not consult_allowed(email) for email in getattr(g,'delegated_recipient_checks',set())):return app.make_response(denied())
        if request.path not in INBOX_PATHS or not response.is_json or response.status_code!=200:return response
        data=response.get_json(silent=True)
        if not isinstance(data,dict) or not data.get('success'):return response
        permissions(fresh=True)
        def allowed_item(item):
            if not isinstance(item,dict):return True
            emails=[]
            for key in ('email','allowed_email','recipient_email'):
                if item.get(key):emails.append(item[key])
            emails.extend(item.get('recipients') or [])
            return all(consult_allowed(email) for email in emails)
        if 'items' in data:data['items']=[item for item in data['items'] if allowed_item(item)];data['count']=len(data['items'])
        for key in ('emails','allowed'):
            if isinstance(data.get(key),list):data[key]=[email for email in data[key] if consult_allowed(email)]
        if isinstance(data.get('entries'),list):data['entries']=[item for item in data['entries'] if allowed_item(item)]
        response.set_data(app.json.dumps(data));response.headers['Cache-Control']='no-store'
        return response
