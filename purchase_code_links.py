"""Paid Loja Mestre account links; independent from panel ownership and admin links."""
import hashlib
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse
from flask import Blueprint, abort, jsonify, request, send_from_directory
from netflix_links import strict_email_context, NETFLIX_PLATFORMS, NETFLIX_FILTER_LABELS

HOST = 'consulta-codigos-jr7z.onrender.com'
STORE_URL = 'https://lojamestre.onrender.com/api/internal/store-code-access'


def verify_store_ticket(token):
    secret = os.environ.get('SHOP_CODE_LINK_SECRET', '')
    if not secret:
        raise RuntimeError('Store verification unavailable')
    req = urllib.request.Request(STORE_URL, data=json.dumps({'token': token}).encode(), method='POST',
                                 headers={'X-Store-Code-Secret': secret, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            result = json.loads(response.read(16384))
    except urllib.error.HTTPError as error:
        if error.code in (403, 404):
            return None
        raise
    if not result.get('success') or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', str(result.get('email') or '')):
        return None
    return result


def register_purchase_code_links(app, data_dir, quarantine, search_all, verify=verify_store_ticket):
    bp = Blueprint('purchase_code_links', __name__)
    db_path = os.path.join(data_dir, 'purchase_code_limits.sqlite3')

    @bp.before_request
    def host_guard():
        if request.host.lower().split(':', 1)[0] != HOST:
            abort(404)

    @bp.after_request
    def private_headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Robots-Tag'] = 'noindex, nofollow'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        return response

    @bp.get('/compra')
    def page():
        return send_from_directory(app.static_folder, 'purchase-code-link.html')

    def access():
        auth = request.headers.get('Authorization', '')
        token = auth[7:] if auth.startswith('Bearer ') else ''
        if len(token) > 512 or not re.fullmatch(r'[A-Za-z0-9_-]+\.[a-f0-9]{64}', token):
            return None, (jsonify(success=False, message='Link inválido. Use o link entregue na compra.'), 403)
        try:
            row = verify(token)
        except Exception:
            return None, (jsonify(success=False, message='Não foi possível validar sua compra agora. Tente novamente.'), 503)
        if not row:
            return None, (jsonify(success=False, message='Link inválido, revogado ou compra ainda não liberada.'), 403)
        email = row['email'].strip().lower()
        supplied = request.get_json(silent=True) or {}
        if not isinstance(supplied, dict):
            return None, (jsonify(success=False, message='Dados inválidos.'), 400)
        for override in (supplied.get('email'), request.args.get('email')):
            if override is not None and str(override).strip().lower() != email:
                return None, (jsonify(success=False, message='Este link permite consultar somente o email da conta comprada.'), 403)
        if quarantine.is_blocked(email):
            return None, (jsonify(success=False, quarantined=True, message='Esse email está na lista que não pode receber códigos.'), 403)
        product = (str(row.get('product_id') or '') + ' ' + str(row.get('product_name') or '')).lower()
        if 'disney' in product:
            platforms = ['disney', 'disney-residence']
        elif 'globo' in product:
            platforms = ['bug-globo', 'codigo-globo', 'senha-globo']
        elif 'netflix' in product:
            platforms = list(NETFLIX_PLATFORMS)
        else:
            platforms = list(NETFLIX_PLATFORMS) + ['disney', 'disney-residence', 'bug-globo', 'codigo-globo', 'senha-globo']
        labels = dict(NETFLIX_FILTER_LABELS, disney='Código Disney+', **{'disney-residence': 'Residência Disney+', 'bug-globo': 'Acesso Globo', 'codigo-globo': 'Código Globo', 'senha-globo': 'Senha Globo'})
        row.update(email=email, platforms=platforms, filters=[{'platform': p, 'label': labels.get(p, p)} for p in platforms])
        return (row, token), None

    @bp.get('/api/purchase-code-link/access')
    def access_info():
        result, error = access()
        if error:
            return error
        row, token = result
        return jsonify(success=True, email=row['email'], filters=row['filters'])

    @bp.post('/api/purchase-code-link/code')
    def code():
        if request.headers.get('Origin') not in (None, 'https://' + HOST):
            abort(403)
        result, error = access()
        if error:
            return error
        row, token = result
        os.makedirs(data_dir, exist_ok=True)
        digest = hashlib.sha256(token.encode()).hexdigest()
        conn = sqlite3.connect(db_path, timeout=15)
        try:
            with conn:
                conn.execute('CREATE TABLE IF NOT EXISTS queries (digest TEXT PRIMARY KEY,last_query REAL NOT NULL)')
                conn.execute('BEGIN IMMEDIATE')
                last = conn.execute('SELECT last_query FROM queries WHERE digest=?', (digest,)).fetchone()
                now = time.time()
                if last and now - last[0] < 12:
                    return jsonify(success=False, message='Aguarde alguns segundos antes de atualizar.'), 429
                conn.execute('INSERT OR REPLACE INTO queries(digest,last_query) VALUES(?,?)', (digest, now))
                conn.execute('DELETE FROM queries WHERE last_query<?', (now - 86400,))
            os.chmod(db_path, 0o600)
        finally:
            conn.close()
        marker = strict_email_context.set(row['email'])
        try:
            raw, errors = search_all(row['email'], row['platforms'])
        except Exception:
            return jsonify(success=False, message='Não foi possível consultar agora. Tente novamente.'), 503
        finally:
            strict_email_context.reset(marker)
        # Revalidate payment/revocation and quarantine after a slow IMAP lookup.
        current, error = access()
        if error:
            return error
        if current[0]['email'] != row['email']:
            return jsonify(success=False, message='Este link foi alterado. Atualize a página.'), 403
        allowed = set(row['platforms']);labels = {x['platform']: x['label'] for x in row['filters']}
        results = [];seen = set()
        for item in raw:
            platform = item.get('platform')
            if platform not in allowed or platform in seen:
                continue
            value = item.get('code') or item.get('link')
            if not value:
                continue
            kind = 'code' if item.get('code') else 'link'
            if kind == 'link':
                try:
                    parsed = urlparse(str(value));host = (parsed.hostname or '').lower()
                    domains = ('netflix.com', 'disneyplus.com', 'disney.com', 'globo.com')
                    if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.port not in (None,443) or not any(host == d or host.endswith('.'+d) for d in domains):
                        continue
                except ValueError:
                    continue
            results.append(dict(platform=platform, label=labels[platform], type=kind, value=str(value)));seen.add(platform)
        if not results and errors:
            return jsonify(success=False, message='Não foi possível consultar as caixas agora. Tente novamente.'), 503
        return jsonify(success=True, results=results, message='' if results else 'Nenhum código ou link recente encontrado para esta conta. Solicite o código no serviço e atualize aqui.')

    app.register_blueprint(bp)
