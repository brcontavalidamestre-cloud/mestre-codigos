"""Read-only, authenticated registration search for the principal quarantine UI."""
import hmac
import os
from flask import abort, jsonify, request

HOST = 'jmp-codigos.onrender.com'


def register_jmp_registry(app, load_subscriptions, load_users):
    @app.get('/api/internal/quarantine/registrations')
    def quarantine_registrations():
        if request.host.lower().split(':', 1)[0] != HOST:
            abort(404)
        expected = os.environ.get('QUARANTINE_SYNC_TOKEN', '')
        received = request.headers.get('X-Quarantine-Token', '')
        if not expected or not hmac.compare_digest(expected, received):
            response = jsonify(success=False, message='Acesso não autorizado.')
            response.status_code = 403
        else:
            query = str(request.args.get('q') or '').strip().lower()[:254]
            rows = []
            if len(query) >= 2:
                users = load_users()
                if isinstance(users, list):
                    users = {str(user.get('username') or ''): user for user in users if isinstance(user, dict)}
                users = users if isinstance(users, dict) else {}
                for sub in load_subscriptions():
                    if not isinstance(sub, dict):
                        continue
                    email = str(sub.get('email') or '').strip().lower()
                    if query not in email:
                        continue
                    username = str(sub.get('assigned_user') or '')
                    user = users.get(username) or {}
                    user = user if isinstance(user, dict) else {}
                    rows.append(dict(email=email, client=username or 'Sem cliente vinculado',
                                     client_name=str(sub.get('assigned_user_name') or user.get('name') or sub.get('cliente') or username),
                                     manager=str(user.get('created_by') or '')))
                rows.sort(key=lambda row: (row['email'] != query, row['email'], row['client']))
            response = jsonify(success=True, items=rows[:200], total=len(rows), limited=len(rows) > 200)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Robots-Tag'] = 'noindex, nofollow'
        return response
