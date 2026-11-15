"""Guest checkout receipts and paid-account code links, Loja Mestre only."""
import base64
import fcntl
import hashlib
import hmac
import os
import re
import secrets
import threading
from contextlib import contextmanager
from functools import wraps
from flask import abort, jsonify, request, session

STORE_HOST = 'lojamestre.onrender.com'
CENTRAL_HOST = 'consulta-codigos-jr7z.onrender.com'
_lock = threading.RLock()


def guest_store_enabled():
    return request.host.lower().split(':', 1)[0] == STORE_HOST


def new_guest_fields():
    return {'delivery_mode': 'direct-link', 'guest_receipt_token': secrets.token_urlsafe(32),
            'code_access_nonce': secrets.token_urlsafe(32)}


def guest_order_id(product_id):
    return 'PED-' + secrets.token_hex(12).upper()


def guest_order_allowed(order):
    if not guest_store_enabled() or order.get('delivery_mode') != 'direct-link':
        return True
    if session.get('logged_in') and session.get('role') == 'admin':
        return True
    token = request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
    data = request.get_json(silent=True) or {}
    supplied = (data.get('order_access_tokens') or {}) if isinstance(data, dict) else {}
    if isinstance(supplied, dict):
        token = token or str(supplied.get(order.get('id')) or '')
    expected = str(order.get('guest_receipt_token') or '')
    return bool(expected and token and hmac.compare_digest(token, expected))


def code_ticket(order):
    secret = os.environ.get('SHOP_CODE_LINK_SECRET', '')
    nonce = str(order.get('code_access_nonce') or '')
    if not secret or not nonce:
        return None
    raw = base64.urlsafe_b64encode(order['id'].encode()).decode().rstrip('=')
    signature = hmac.new(secret.encode(), (order['id'] + ':' + nonce).encode(), hashlib.sha256).hexdigest()
    return raw + '.' + signature


def delivery_link(order):
    if order.get('status') != 'paid' or not order.get('delivered_email') or not order.get('delivered_password'):
        return None
    ticket = code_ticket(order)
    return 'https://' + CENTRAL_HOST + '/compra#' + ticket if ticket else None


def public_delivery_fields(order):
    if order.get('delivery_mode') != 'direct-link':
        return {}
    link = delivery_link(order)
    return {'delivered_code_link': link, 'delivery_mode': 'direct-link',
            'code_link_pending': order.get('status') == 'paid' and bool(order.get('delivered_email')) and not link}


def store_delivery_lock(data_dir):
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not guest_store_enabled():
                return fn(*args, **kwargs)
            os.makedirs(data_dir, exist_ok=True)
            with _lock, open(os.path.join(data_dir, '.guest-delivery.lock'), 'a') as handle:
                os.chmod(handle.name, 0o600)
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    return fn(*args, **kwargs)
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return wrapped
    return decorate


def register_store_guest(app, load_orders):
    @app.post('/api/internal/store-code-access')
    def verify_paid_code_access():
        if not guest_store_enabled():
            abort(404)
        expected = os.environ.get('SHOP_CODE_LINK_SECRET', '')
        received = request.headers.get('X-Store-Code-Secret', '')
        if not expected or not hmac.compare_digest(expected, received):
            return jsonify(success=False, message='Acesso não autorizado.'), 403
        body = request.get_json(silent=True) or {}
        token = str(body.get('token') or '') if isinstance(body, dict) else ''
        if len(token) > 512 or not re.fullmatch(r'[A-Za-z0-9_-]+\.[a-f0-9]{64}', token):
            return jsonify(success=False, message='Link inválido.'), 403
        try:
            raw = token.split('.', 1)[0]
            oid = base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)).decode()
        except Exception:
            return jsonify(success=False, message='Link inválido.'), 403
        order = next((o for o in load_orders() if isinstance(o, dict) and o.get('id') == oid), None)
        if not order or order.get('delivery_mode') != 'direct-link' or order.get('status') != 'paid' or not order.get('delivered_email') or not order.get('delivered_password'):
            return jsonify(success=False, message='Acesso ainda não liberado ou link revogado.'), 403
        computed = code_ticket(order)
        if not computed or not hmac.compare_digest(token, computed):
            return jsonify(success=False, message='Link inválido ou revogado.'), 403
        return jsonify(success=True, email=str(order['delivered_email']).strip().lower(),
                       product_id=order.get('product_id'), product_name=order.get('product_name'))

    @app.after_request
    def guest_private_headers(response):
        if guest_store_enabled() and request.path.startswith(('/api/loja/', '/api/internal/store-code-access')):
            response.headers['Cache-Control'] = 'no-store'
            response.headers['Referrer-Policy'] = 'no-referrer'
        return response
