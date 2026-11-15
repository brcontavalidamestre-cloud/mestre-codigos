"""Principal-admin quarantine search and local registration cleanup.
No mailbox messages, user accounts, orders or stock are modified.
"""
import fcntl
import json
import os
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from contextlib import contextmanager


def search_jmp_registrations(query):
    token = os.environ.get('QUARANTINE_SYNC_TOKEN', '')
    if not token:
        raise RuntimeError('JMP registry authentication unavailable')
    url = 'https://jmp-codigos.onrender.com/api/internal/quarantine/registrations?' + urllib.parse.urlencode({'q': query})
    req = urllib.request.Request(url, headers={'X-Quarantine-Token': token, 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=8) as response:
        data = json.loads(response.read(1048577))
    if not isinstance(data, dict) or not data.get('success') or not isinstance(data.get('items'), list):
        raise RuntimeError('Invalid JMP registry response')
    return data


class QuarantineRegistry:
    def __init__(self, store, data_dir, load_subscriptions, save_subscriptions, load_users, remote_search=None):
        self.store = store
        self.remote_search = remote_search
        self.data_dir = data_dir
        self.load_subscriptions = load_subscriptions or (lambda: [])
        self.save_subscriptions = save_subscriptions
        self.load_users = load_users or (lambda: {})
        self.links_path = os.path.join(data_dir, 'netflix_links.sqlite3')
        self.lock = threading.RLock()

    @contextmanager
    def serialized(self):
        os.makedirs(self.data_dir, exist_ok=True)
        with self.lock, open(os.path.join(self.data_dir, '.email-registration.lock'), 'a') as handle:
            os.chmod(handle.name, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def links(self):
        if not os.path.isfile(self.links_path):
            return []
        conn = sqlite3.connect('file:' + self.links_path + '?mode=ro', uri=True, timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            columns = {r[1] for r in conn.execute('PRAGMA table_info(links)')}
            if not columns:
                return []
            owner = 'owner' if 'owner' in columns else "'' AS owner"
            managers = {}
            if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='netflix_admins'").fetchone():
                managers = {r['id']: dict(r) for r in conn.execute('SELECT id,username,name FROM netflix_admins')}
            result = []
            for row in conn.execute('SELECT email,created_at,updated_at,' + owner + ' FROM links'):
                item = dict(row)
                manager = managers.get(item['owner']) or {}
                item['manager'] = manager.get('username') or ('admin' if not item['owner'] else item['owner'])
                item['manager_name'] = manager.get('name') or item['manager']
                result.append(item)
            return result
        finally:
            conn.close()

    def search(self, query):
        query = str(query or '').strip().lower()
        if len(query) < 2:
            return [], 0
        users = self.load_users()
        if isinstance(users, list):
            users = {str(u.get('username') or ''): u for u in users if isinstance(u, dict)}
        users = users if isinstance(users, dict) else {}
        blocked = self.store.emails()
        result = []
        for sub in self.load_subscriptions():
            if not isinstance(sub, dict):
                continue
            email = str(sub.get('email') or '').strip().lower()
            if query not in email:
                continue
            username = str(sub.get('assigned_user') or '')
            user = users.get(username) or {}
            user = user if isinstance(user, dict) else {}
            result.append(dict(email=email, source='panel', source_label='Painel de consulta',
                               client=username or 'Sem cliente vinculado',
                               client_name=sub.get('assigned_user_name') or user.get('name') or sub.get('cliente') or username,
                               manager=user.get('created_by') or '', quarantined=self.store.matches(email, blocked)))
        for link in self.links():
            email = str(link['email']).strip().lower()
            if query in email:
                result.append(dict(email=email, source='link', source_label='Link individual Netflix',
                                   client=link['manager'], client_name=link['manager_name'],
                                   manager=link['manager'], quarantined=self.store.matches(email, blocked)))
        result.sort(key=lambda item: (item['email'] != query, item['email'], item['source'], item['client']))
        return result[:200], len(result)

    def search_all(self, query):
        query = str(query or '').strip().lower()[:254]
        local, total = self.search(query)
        warnings = []
        if self.remote_search and len(query) >= 2:
            try:
                remote = self.remote_search(query)
                blocked = self.store.emails()
                remote_items = []
                for row in remote['items'][:200]:
                    email = str(row.get('email') or '').strip().lower()
                    if query not in email or '@' not in email:
                        continue
                    remote_items.append(dict(email=email, source='jmp', source_label='JMP — Painel de consulta',
                                             client=str(row.get('client') or 'Sem cliente vinculado'),
                                             client_name=str(row.get('client_name') or row.get('client') or ''),
                                             manager=str(row.get('manager') or ''),
                                             quarantined=self.store.matches(email, blocked)))
                remote_total = max(len(remote_items), int(remote.get('total') or 0))
                local.extend(remote_items)
                total += remote_total
            except Exception:
                warnings.append('Não foi possível pesquisar os emails do JMP agora. Os resultados abaixo podem estar incompletos. Tente pesquisar novamente.')
        local.sort(key=lambda item: (item['email'] != query, item['email'], item['source'], item['client']))
        return dict(items=local[:200], total=total, limited=total > len(local[:200]), partial=bool(warnings), warnings=warnings)

    def quarantine(self, emails):
        with self.serialized():
            # Block first: if cleanup fails, consultation must remain denied.
            added = self.store.add(emails, 'admin')
            targets = set(emails)
            subscriptions = self.load_subscriptions()
            removed = [s for s in subscriptions if isinstance(s, dict) and self.store.matches(s.get('email'), targets)]
            links = [row for row in self.links() if self.store.matches(row['email'], targets)]
            # Keep a private recovery journal before removing registrations.
            conn = self.store.connect()
            try:
                with conn:
                    conn.execute('CREATE TABLE IF NOT EXISTS quarantine_cleanup_audit (id INTEGER PRIMARY KEY,created_at INTEGER NOT NULL,actor TEXT NOT NULL,requested_emails TEXT NOT NULL,subscriptions TEXT NOT NULL,links TEXT NOT NULL)')
                    conn.execute('INSERT INTO quarantine_cleanup_audit(created_at,actor,requested_emails,subscriptions,links) VALUES(?,?,?,?,?)',
                                 (int(time.time()), 'admin', json.dumps(emails), json.dumps(removed), json.dumps(links)))
            finally:
                conn.close()
            if removed:
                if self.save_subscriptions is None:
                    raise RuntimeError('Subscription writer unavailable')
                kept = [s for s in subscriptions if not (isinstance(s, dict) and self.store.matches(s.get('email'), targets))]
                if self.save_subscriptions(kept) is False:
                    raise RuntimeError('Subscription write failed')
                if any(isinstance(s, dict) and self.store.matches(s.get('email'), targets) for s in self.load_subscriptions()):
                    raise RuntimeError('Subscription cleanup verification failed')
            if links:
                conn = sqlite3.connect(self.links_path, timeout=15)
                try:
                    with conn:
                        conn.executemany('DELETE FROM links WHERE email=?', [(row['email'],) for row in links])
                finally:
                    conn.close()
            return dict(added=added, existing=len(emails)-added,
                        removed_bindings=len(removed), removed_links=len(links))
