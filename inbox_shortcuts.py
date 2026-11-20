"""Central inbox navigation links. A link never grants authentication."""
import os
import re
import secrets
import sqlite3
from contextlib import closing
from flask import jsonify, request, session

HOST = 'consulta-codigos-jr7z.onrender.com'


def register_inbox_shortcuts(app, data_dir, load_users, load_subscriptions, quarantine):
    path = os.path.join(data_dir, 'inbox_shortcuts.sqlite3')

    def connect():
        conn = sqlite3.connect(path, timeout=5)
        conn.execute('CREATE TABLE IF NOT EXISTS shortcuts (email TEXT PRIMARY KEY, owner TEXT NOT NULL, binding TEXT NOT NULL, slug TEXT UNIQUE NOT NULL)')
        return conn

    def binding(address):
        matches = [row for row in load_subscriptions() if isinstance(row, dict) and str(row.get('email') or '').strip().lower() == address]
        if len(matches) != 1:
            return None
        row = matches[0]
        owner = str(row.get('assigned_user') or '').strip().lower()
        if (load_users().get(owner) or {}).get('role') != 'client' or quarantine.is_blocked(address):
            return None
        return owner, str(row.get('created_at') or 0) + ':' + str(row.get('start_at') or 0)

    def resolve(slug, username):
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', slug) or session.get('role') != 'client':
            return None
        with closing(connect()) as conn:
            row = conn.execute('SELECT email, owner, binding FROM shortcuts WHERE slug=? AND owner=?', (slug, username)).fetchone()
        if row and binding(row[0]) == row[1:]:
            return row[0]
        return None

    app.config['INBOX_SHORTCUT_RESOLVE'] = resolve

    @app.post('/api/admin/inbox-shortcuts')
    def manage_inbox_shortcut():
        def reply(status=200, **fields):
            response = jsonify(**fields)
            response.headers['Cache-Control'] = 'no-store'
            return response, status

        if request.host.lower().split(':', 1)[0] != HOST:
            return reply(404, success=False)
        if (not session.get('logged_in') or session.get('role') != 'admin' or session.get('username') != 'admin'
                or request.headers.get('Origin') not in (None, 'https://' + HOST)):
            return reply(403, success=False, message='Somente o administrador principal pode gerenciar os atalhos.')
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return reply(400, success=False, message='Dados inválidos.')
        address = str(data.get('email') or '').strip().lower()
        action = data.get('action')
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', address) or len(address) > 254 or action not in ('copy', 'rotate', 'remove'):
            return reply(400, success=False, message='Endereço ou ação inválida.')
        current = binding(address) if action != 'remove' else None
        if action != 'remove' and not current:
            return reply(409, success=False, message='O e-mail precisa estar vinculado a um cliente e fora da quarentena.')
        with closing(connect()) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            if action == 'remove':
                conn.execute('DELETE FROM shortcuts WHERE email=?', (address,))
                return reply(success=True)
            row = conn.execute('SELECT slug, owner, binding FROM shortcuts WHERE email=?', (address,)).fetchone()
            if action == 'copy' and row and row[1:] == current:
                slug = row[0]
            else:
                slug = secrets.token_urlsafe(32)
                conn.execute('INSERT OR REPLACE INTO shortcuts VALUES (?, ?, ?, ?)', (address, *current, slug))
            return reply(success=True, slug=slug)
