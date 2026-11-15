"""JMP read-only enforcement of the principal administrator's quarantine."""
import json
import os
import urllib.request
from flask import g, jsonify, request, session

HOST='jmp-codigos.onrender.com'
MESSAGE='Esse email está na lista que não pode receber códigos.'
QUERIES={'/api/get-code','/api/admin/get-code','/api/verify-reset-pin'}
INBOXES={'/api/live-inbox/messages','/api/admin/live-inbox/messages'}


def blocked(email, emails):
    email=str(email or '').strip().lower()
    if email in emails:return True
    local,sep,domain=email.partition('@')
    return bool(sep and '+' in local and local.split('+',1)[0]+'@'+domain in emails)


def register_jmp_quarantine(app, pending_resets):
    def snapshot():
        if hasattr(g,'jmp_quarantine_emails'):return g.jmp_quarantine_emails
        token=os.environ.get('QUARANTINE_SYNC_TOKEN','')
        if not token:raise RuntimeError('Quarantine synchronization unavailable')
        req=urllib.request.Request('https://consulta-codigos-jr7z.onrender.com/api/internal/quarantine',headers={'X-Quarantine-Token':token})
        with urllib.request.urlopen(req,timeout=8) as response:data=json.load(response)
        if not data.get('success') or not isinstance(data.get('emails'),list):raise RuntimeError('Invalid quarantine response')
        g.jmp_quarantine_emails={str(email).strip().lower() for email in data['emails']}
        return g.jmp_quarantine_emails

    def error(message,status=403):
        response=jsonify(success=False,quarantined=status==403,message=message,items=[],results=[],count=0)
        response.status_code=status;response.headers['Cache-Control']='no-store';return response

    def email():
        data=request.get_json(silent=True) or {};data=data if isinstance(data,dict) else {}
        value=data.get('email') or request.args.get('email') or ''
        if request.path=='/api/verify-reset-pin':
            entry=pending_resets.get(session.get('username')) or {}
            value=entry.get('email') or value
        return value

    @app.before_request
    def enforce_query():
        if request.host.lower().split(':',1)[0]!=HOST or request.path not in QUERIES|INBOXES:return None
        if not session.get('logged_in'):return None
        try:
            emails=snapshot()
        except Exception:
            g.jmp_quarantine_failed=True
            return error('Não foi possível verificar a quarentena agora. Tente novamente em instantes.',503)
        if request.path in QUERIES and blocked(email(),emails):return error(MESSAGE)

    @app.after_request
    def filter_response(response):
        if request.host.lower().split(':',1)[0]!=HOST or request.path not in QUERIES|INBOXES:return response
        if getattr(g,'jmp_quarantine_failed',False) or not session.get('logged_in'):return response
        try:
            # Recheck after a slow lookup so a newly quarantined email cannot
            # leak an in-flight result. No cross-request caching is used.
            if request.path in QUERIES:
                if hasattr(g,'jmp_quarantine_emails'):del g.jmp_quarantine_emails
                if blocked(email(),snapshot()):return error(MESSAGE)
                return response
            if not response.is_json or response.status_code!=200:return response
            data=response.get_json(silent=True)
            if not isinstance(data,dict) or not data.get('success'):return response
            emails=snapshot()
            def hits(value):
                if isinstance(value,list):return any(hits(v) for v in value)
                if isinstance(value,dict):return any(hits(value.get(key)) for key in ('email','allowed_email','recipients'))
                return blocked(value,emails)
            old=data.get('items') or []
            data['items']=[item for item in old if not hits(item)];data['count']=len(data['items'])
            affected=[em for em in data.get('emails',data.get('allowed',[])) if hits(em)]
            if affected or len(old)!=len(data['items']):
                data.update(quarantined_emails=affected,quarantine_message=MESSAGE,message=MESSAGE)
            response.set_data(app.json.dumps(data));response.headers['Cache-Control']='no-store';return response
        except Exception:
            return error('Não foi possível verificar a quarentena agora. Tente novamente em instantes.',503)
