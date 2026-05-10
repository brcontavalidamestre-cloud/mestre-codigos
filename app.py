from flask import Flask, request, jsonify, send_from_directory, session, redirect
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import imaplib
import email
from email.header import decode_header
import re
import os
import json
import unicodedata
import uuid
import time
from datetime import timedelta, datetime, timezone
import requests

app = Flask(__name__, static_folder='static')
CORS(app)

app.secret_key = os.environ.get('SECRET_KEY', 'mestre-codigos-secret-2025')
app.permanent_session_lifetime = timedelta(hours=8)

DATA_DIR = '/data' if os.path.isdir('/data') else '/tmp'
USERS_FILE = os.environ.get('USERS_FILE', os.path.join(DATA_DIR, 'users.json'))
ORDERS_FILE = os.environ.get('ORDERS_FILE', os.path.join(DATA_DIR, 'orders_infinitepay.json'))
CREDENTIALS_FILE = os.environ.get('CREDENTIALS_FILE', os.path.join(DATA_DIR, 'credentials.json'))

railway_public_domain = os.environ.get('RAILWAY_PUBLIC_DOMAIN', '').strip()
default_base_url = f"https://{railway_public_domain}" if railway_public_domain else 'http://localhost:8080'
BASE_URL = os.environ.get('BASE_URL', default_base_url).rstrip('/')

INFINITEPAY_HANDLE = os.environ.get('INFINITEPAY_HANDLE', '').strip().lstrip('$')
INFINITEPAY_API_BASE = os.environ.get('INFINITEPAY_API_BASE', 'https://api.checkout.infinitepay.io').rstrip('/')
INFINITEPAY_REDIRECT_URL = os.environ.get('INFINITEPAY_REDIRECT_URL', f'{BASE_URL}/pagamento/sucesso').strip()
INFINITEPAY_WEBHOOK_URL = os.environ.get('INFINITEPAY_WEBHOOK_URL', f'{BASE_URL}/webhooks/infinitepay').strip()

DEFAULT_PRODUCTS = [
    {
        'id': 'netflix-premium',
        'name': 'Netflix Premium',
        'description': 'Acesso Netflix com liberação automática após pagamento aprovado.',
        'price_cents': 3500,
        'delivery_url': os.environ.get('DELIVERY_URL_NETFLIX_PREMIUM', os.environ.get('DELIVERY_URL_PREMIUM', 'https://SEU-LINK-NETFLIX-AQUI')),
        'badge': 'Netflix • liberação automática',
        'image_url': 'https://sspark.genspark.ai/cfimages?u1=vxnlFCUBJ1MdeiGsBChh3m2AgkQKsj8okqVtFS9OAIcvAa0w8jEtgPicUyvjkHkmTrGinrFoAKxCKNkdzIMUHoDBwyMgXSxF6KwERAM%2BpFC4CDDIfU4%3D&u2=BLC7%2FgtFE4awllH4&width=2560'
    },
    {
        'id': 'disney-premium',
        'name': 'Disney Premium',
        'description': 'Acesso Disney+ com liberação automática após a confirmação do pagamento.',
        'price_cents': 2500,
        'delivery_url': os.environ.get('DELIVERY_URL_DISNEY_PREMIUM', os.environ.get('DELIVERY_URL_VIP', 'https://SEU-LINK-DISNEY-AQUI')),
        'badge': 'Disney+ • liberação automática',
        'image_url': 'https://sspark.genspark.ai/cfimages?u1=geWt%2B8PWaG7%2BshOH1RmMyJOXyuTsP3nvUQfb4tYndylZX%2FAfSG%2BQRo4d5paq5Rw30bJ8nCmOPt1F9c63jWEXKgq3mD6JKe9DKW%2FhxasRqcC9xM8ototOzLILQkkbF2InfFpuDGlOKRq5fnsmbT51pr6hCbhC0R5KD10%3D&u2=V7E27TOU7vW46V12&width=2560'
    }
]

IMAP_SERVER = os.environ.get('IMAP_SERVER', 'imap.hostinger.com')
IMAP_PORT = int(os.environ.get('IMAP_PORT', 993))
EMAIL_USER = os.environ.get('EMAIL_USER', 'mestre@codigo.log.br')
EMAIL_PASS = os.environ.get('EMAIL_PASS', 'Mcodigo10@')

PLATFORM_CONFIG = {
    'netflix': {
        'from_keyword': 'netflix.com',
        'subject_keywords': ['digo de acesso'],
        'name': 'Netflix',
        'type': 'code'
    },
    'disney': {
        'from_keyword': 'disneyplus.com',
        'subject_keywords': ['digo de acesso'],
        'name': 'Disney+',
        'type': 'code'
    },
    'globo': {
        'from_keyword': 'globo.com',
        'from_keywords': ['globo.com', 'globoplay.com', 'globoplay'],
        'subject_keywords': ['digo de acesso', 'codigo de acesso', 'verificação', 'verificacao', 'globoplay', 'acesso', 'código', 'codigo', 'one-time', 'login', 'entrar'],
        'name': 'Globoplay',
        'type': 'code'
    },
    'max-prime': {
        'from_keyword': 'max.com',
        'from_keywords': ['max.com', 'hbomax', 'warnermedia', 'amazon.com', 'amazon.com.br', 'primevideo', 'amazonses.com', 'amazon'],
        'subject_keywords': ['digo de acesso', 'codigo de acesso', 'código', 'codigo', 'verificação', 'verificacao', 'verification', 'sign in', 'sign-in', 'signin', 'entrar', 'one-time', 'one time', 'OTP', 'OTP', 'login', 'acesso', 'amazon', 'prime video', 'max'],
        'name': 'Max / Prime Video',
        'type': 'code'
    },
    'netflix-residence': {
        'from_keyword': 'netflix.com',
        'subject_keywords': ['atualizar'],
        'name': 'Residência Netflix',
        'type': 'link'
    },
    'password-reset': {
        'from_keyword': 'netflix.com',
        'subject_keywords': [
            'Complete a solicitacao de redefinicao de senha',
            'redefinicao de senha',
            'Completa tu solicitud de restablecimiento de contrasena',
            'restablecimiento de contrasena',
            'Tapusin ang request mong i-reset ang password',
            'reset ang password',
            'reset password',
            'password reset',
            'redefini'
        ],
        'name': 'Redefinição de Senha Netflix',
        'type': 'link'
    },
    'disney-residence': {
        'from_keyword': 'disneyplus.com',
        'subject_keywords': [
            'Quer atualizar sua Residencia do Disney+',
            'atualizar sua Residencia do Disney',
            'Residencia do Disney',
            'update your Disney+ Home',
            'Disney+ Home'
        ],
        'name': 'Residência Disney+',
        'type': 'link'
    }
}


def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    default = {
        'admin': {
            'password': generate_password_hash('admin123'),
            'role': 'admin',
            'name': 'Administrador'
        }
    }
    save_users(default)
    return default


def save_users(users):
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


def load_orders():
    if os.path.exists(ORDERS_FILE):
        try:
            with open(ORDERS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_orders(orders):
    os.makedirs(os.path.dirname(ORDERS_FILE), exist_ok=True)
    with open(ORDERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(orders, f, indent=2, ensure_ascii=False)


def load_credentials():
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
    return {}


def save_credentials(data):
    os.makedirs(os.path.dirname(CREDENTIALS_FILE), exist_ok=True)
    with open(CREDENTIALS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def assign_credential(product_id):
    creds = load_credentials()
    items = creds.get(product_id, [])
    for item in items:
        if not item.get('used'):
            item['used'] = True
            item['used_at'] = now_iso()
            creds[product_id] = items
            save_credentials(creds)
            return {
                'id': item.get('id', ''),
                'email': item.get('email', ''),
                'password': item.get('password', ''),
                'note': item.get('note', '')
            }
    return None


def get_product_by_id(product_id):
    for p in DEFAULT_PRODUCTS:
        if p['id'] == product_id:
            return p
    return None


def brl_from_cents(value):
    return f"R$ {value / 100:.2f}".replace('.', ',')


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def new_order_nsu():
    return f"PED-{int(time.time())}-{uuid.uuid4().hex[:6].upper()}"


def decode_str(s):
    if not s:
        return ''
    parts = decode_header(s)
    result = ''
    for part, enc in parts:
        if isinstance(part, bytes):
            result += part.decode(enc or 'utf-8', errors='ignore')
        else:
            result += str(part)
    return result


def normalize(text):
    text = text.lower()
    nfkd = unicodedata.normalize('NFKD', text)
    return ''.join(c for c in nfkd if not unicodedata.combining(c))


def subject_matches(subject, keywords):
    subj_norm = normalize(subject)
    subj_lower = subject.lower()
    for kw in keywords:
        if normalize(kw) in subj_norm or kw.lower() in subj_lower:
            return True
    return False


def get_html_body(msg):
    html = ''
    plain = ''
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get('Content-Disposition', ''))
            if 'attachment' in cd:
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or 'utf-8'
            text = payload.decode(charset, errors='ignore')
            if ct == 'text/html':
                html += text
            elif ct == 'text/plain' and not plain:
                plain += text
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or 'utf-8'
            text = payload.decode(charset, errors='ignore')
            if msg.get_content_type() == 'text/html':
                html = text
            else:
                plain = text
    return html or plain


def extract_code_from_html(html_body):
    m = re.search(r'letter-spacing\s*:\s*[^;>]+[^>]*>\s*([A-Z0-9]{4,8})\s*<', html_body, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r'font-size\s*:\s*(?:[3-9]\d|[12]\d\d)px[^>]*>\s*([A-Z0-9]{4,8})\s*<', html_body, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    clean = re.sub(r'<[^>]+>', ' ', html_body)
    clean = re.sub(r'\s+', ' ', clean)
    patterns_text = [
        r'c[oó]digo\s*(?:de acesso)?\s*[:\-]?\s*([A-Z0-9]{4,8})',
        r'access\s*code\s*[:\-]?\s*([A-Z0-9]{4,8})',
        r'\b([0-9]{4,8})\b(?=\s*(?:é seu|é o seu|para entrar|para acessar))',
        r'\b([0-9]{6})\b',
    ]
    for pat in patterns_text:
        m = re.search(pat, clean, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None


def extract_link(html_body, platform):
    if platform == 'netflix-residence':
        patterns = [
            r'href=["\']([^"\']*netflix\.com[^"\']*(?:update|atualiz|resid|location)[^"\']*)["\']',
            r'href=["\']([^"\']*netflix\.com[^"\']*account[^"\']*)["\']',
        ]
        domain = 'netflix.com'
    elif platform == 'password-reset':
        patterns = [
            r'href=["\']([^"\']*netflix\.com[^"\']*(?:password|reset|redefin|senha)[^"\']*)["\']',
            r'href=["\']([^"\']*netflix\.com[^"\']*account[^"\']*)["\']',
        ]
        domain = 'netflix.com'
    elif platform == 'disney-residence':
        patterns = [
            r'href=["\']([^"\']*(?:disneyplus|disney)\.com[^"\']*(?:update|atualiz|resid|home|location)[^"\']*)["\']',
            r'href=["\']([^"\']*disneyplus\.com[^"\']*)["\']',
        ]
        domain = 'disney'
    else:
        patterns = []
        domain = 'netflix.com'
    for pat in patterns:
        m = re.search(pat, html_body, re.IGNORECASE)
        if m:
            link = m.group(1)
            if len(link) > 30:
                return link
    all_links = re.findall(r'href=["\']([^"\']+)["\']', html_body, re.IGNORECASE)
    domain_links = [l for l in all_links if domain in l.lower() and len(l) > 50]
    if domain_links:
        return domain_links[0]
    return None


def email_matches_user(msg, html_body, user_email):
    user_lower = user_email.lower()
    if user_lower in html_body.lower():
        return True
    for header in ['To', 'Delivered-To', 'X-Original-To']:
        if user_lower in decode_str(msg.get(header, '')).lower():
            return True
    return False


def connect_imap():
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(EMAIL_USER, EMAIL_PASS)
    return mail


def search_code(user_email, platform):
    config = PLATFORM_CONFIG.get(platform)
    if not config:
        return None, None, 'Plataforma não suportada.'
    try:
        mail = connect_imap()
        mail.select('INBOX')
        from_kws = config.get('from_keywords') or [config.get('from_keyword', '')]
        from_kws = [k for k in from_kws if k]
        subj_kws = config['subject_keywords']
        result_type = config.get('type', 'code')
        all_ids = []
        seen = set()
        for fk in from_kws:
            try:
                status, msgs = mail.search(None, 'FROM', fk)
                if status == 'OK' and msgs and msgs[0]:
                    for eid in msgs[0].split():
                        if eid not in seen:
                            seen.add(eid)
                            all_ids.append(eid)
            except Exception:
                continue
        if not all_ids:
            mail.logout()
            return None, None, 'Nenhum email da plataforma encontrado.'
        recent_ids = all_ids[-150:]
        recent_ids.reverse()
        matched_ids = []
        for eid in recent_ids:
            try:
                status, data = mail.fetch(eid, '(BODY[HEADER.FIELDS (SUBJECT)])')
                if status != 'OK':
                    continue
                hdr = email.message_from_bytes(data[0][1])
                subj = decode_str(hdr.get('Subject', ''))
                if subject_matches(subj, subj_kws):
                    matched_ids.append(eid)
            except Exception:
                continue
        if not matched_ids:
            mail.logout()
            return None, None, f"Nenhum email de {config['name']} encontrado. Verifique se o email já chegou."
        for eid in matched_ids:
            try:
                status, data = mail.fetch(eid, '(RFC822)')
                if status != 'OK':
                    continue
                msg = email.message_from_bytes(data[0][1])
                html_body = get_html_body(msg)
                if email_matches_user(msg, html_body, user_email):
                    if result_type == 'link':
                        link = extract_link(html_body, platform)
                        if link:
                            mail.logout()
                            return None, link, None
                    else:
                        code = extract_code_from_html(html_body)
                        if code:
                            mail.logout()
                            return code, None, None
            except Exception:
                continue
        mail.logout()
        return None, None, 'Email da conta não encontrado. Verifique se digitou o email correto.'
    except imaplib.IMAP4.error as e:
        return None, None, f'Erro de conexão com servidor de email: {e}'
    except Exception as e:
        return None, None, f'Erro interno: {e}'


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({'success': False, 'message': 'Não autenticado.', 'redirect': '/login'}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({'success': False, 'message': 'Não autenticado.', 'redirect': '/login'}), 401
        if session.get('role') != 'admin':
            return jsonify({'success': False, 'message': 'Acesso restrito ao administrador.'}), 403
        return f(*args, **kwargs)
    return decorated


def json_or_text(resp):
    try:
        return resp.json()
    except Exception:
        return {'raw': resp.text}


def deep_find_first(data, keys):
    if isinstance(data, dict):
        for k, v in data.items():
            if str(k).lower() in keys:
                return v
            found = deep_find_first(v, keys)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data:
            found = deep_find_first(item, keys)
            if found is not None:
                return found
    return None


def collect_all_strings(data, bucket=None):
    if bucket is None:
        bucket = []
    if isinstance(data, dict):
        for v in data.values():
            collect_all_strings(v, bucket)
    elif isinstance(data, list):
        for item in data:
            collect_all_strings(item, bucket)
    elif isinstance(data, str):
        bucket.append(data)
    return bucket


def find_checkout_url(data):
    for keyset in [
        {'url'}, {'link'}, {'payment_url'}, {'checkout_url'},
        {'checkoutlink'}, {'paymentlink'}
    ]:
        val = deep_find_first(data, keyset)
        if isinstance(val, str) and val.startswith('http'):
            return val
    strings = collect_all_strings(data)
    for s in strings:
        if isinstance(s, str) and s.startswith('http'):
            return s
    return None


def payload_indicates_paid(payload):
    strings = ' '.join([s.lower() for s in collect_all_strings(payload)])
    if any(word in strings for word in ['paid', 'approved', 'aprovado', 'success', 'successful']):
        return True
    paid_flag = deep_find_first(payload, {'paid'})
    if isinstance(paid_flag, bool):
        return paid_flag
    if isinstance(paid_flag, str) and paid_flag.lower() in ('true', '1', 'yes', 'paid'):
        return True
    return False


def mark_order_paid(order_nsu, extra=None):
    orders = load_orders()
    order = orders.get(order_nsu)
    if not order:
        return None
    order['status'] = 'paid'
    order['paid_at'] = now_iso()
    if extra and isinstance(extra, dict):
        if extra.get('slug'):
            order['slug'] = extra['slug']
        if extra.get('transaction_nsu'):
            order['transaction_nsu'] = extra['transaction_nsu']
        if extra.get('receipt_url'):
            order['receipt_url'] = extra['receipt_url']
        if extra.get('capture_method'):
            order['capture_method'] = extra['capture_method']
    if not order.get('assigned_account'):
        account = assign_credential(order.get('product_id', ''))
        if account:
            order['assigned_account'] = account
    orders[order_nsu] = order
    save_orders(orders)
    return order


def infinitepay_create_link(product, customer_name='', customer_email='', customer_phone=''):
    if not INFINITEPAY_HANDLE:
        raise RuntimeError('INFINITEPAY_HANDLE não configurado.')
    order_nsu = new_order_nsu()
    payload = {
        'handle': INFINITEPAY_HANDLE,
        'items': [
            {
                'quantity': 1,
                'price': int(product['price_cents']),
                'description': product['name']
            }
        ],
        'order_nsu': order_nsu,
        'redirect_url': INFINITEPAY_REDIRECT_URL,
        'webhook_url': INFINITEPAY_WEBHOOK_URL
    }
    if customer_name or customer_email or customer_phone:
        payload['customer'] = {}
        if customer_name:
            payload['customer']['name'] = customer_name
        if customer_email:
            payload['customer']['email'] = customer_email
        if customer_phone:
            payload['customer']['phone_number'] = customer_phone
    resp = requests.post(f'{INFINITEPAY_API_BASE}/links', json=payload, timeout=30)
    data = json_or_text(resp)
    if resp.status_code >= 400:
        raise RuntimeError(f"Erro ao criar checkout: {json.dumps(data, ensure_ascii=False)}")
    checkout_url = find_checkout_url(data)
    if not checkout_url:
        raise RuntimeError(f"Checkout criado, mas a URL não foi identificada na resposta: {json.dumps(data, ensure_ascii=False)}")
    slug = deep_find_first(data, {'slug'})
    order = {
        'order_nsu': order_nsu,
        'status': 'pending',
        'created_at': now_iso(),
        'product_id': product['id'],
        'product_name': product['name'],
        'price_cents': product['price_cents'],
        'delivery_url': product['delivery_url'],
        'checkout_url': checkout_url,
        'slug': slug if isinstance(slug, str) else '',
        'customer_name': customer_name,
        'customer_email': customer_email,
        'customer_phone': customer_phone,
        'gateway': 'infinitepay'
    }
    orders = load_orders()
    orders[order_nsu] = order
    save_orders(orders)
    return order


def infinitepay_check_payment(order_nsu, slug, transaction_nsu):
    if not INFINITEPAY_HANDLE:
        raise RuntimeError('INFINITEPAY_HANDLE não configurado.')
    payload = {
        'handle': INFINITEPAY_HANDLE,
        'order_nsu': order_nsu,
        'transaction_nsu': transaction_nsu,
        'slug': slug
    }
    resp = requests.post(f'{INFINITEPAY_API_BASE}/payment_check', json=payload, timeout=30)
    data = json_or_text(resp)
    if resp.status_code >= 400:
        raise RuntimeError(f"Erro ao consultar pagamento: {json.dumps(data, ensure_ascii=False)}")
    paid = False
    if isinstance(data, dict):
        paid_value = data.get('paid')
        if isinstance(paid_value, bool):
            paid = paid_value
        elif isinstance(paid_value, str):
            paid = paid_value.lower() in ('true', '1', 'yes', 'paid')
    return data, paid


@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect('/login')
    return send_from_directory('static', 'index.html')


@app.route('/pagamento/sucesso')
def pagamento_sucesso():
    if not session.get('logged_in'):
        return redirect('/login')
    return send_from_directory('static', 'index.html')


@app.route('/login')
def login_page():
    if session.get('logged_in'):
        if session.get('role') == 'admin':
            return redirect('/admin')
        return redirect('/')
    return send_from_directory('static', 'login.html')


@app.route('/admin')
def admin_page():
    if not session.get('logged_in'):
        return redirect('/login')
    if session.get('role') != 'admin':
        return redirect('/')
    return send_from_directory('static', 'admin.html')


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'message': 'Dados inválidos.'}), 400
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'success': False, 'message': 'Informe usuário e senha.'}), 400
    users = load_users()
    user = users.get(username)
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'success': False, 'message': 'Usuário ou senha incorretos.'}), 401
    session.permanent = True
    session['logged_in'] = True
    session['username'] = username
    session['role'] = user.get('role', 'client')
    session['name'] = user.get('name', username)
    redirect_to = '/admin' if user.get('role') == 'admin' else '/'
    return jsonify({'success': True, 'role': user.get('role', 'client'), 'redirect': redirect_to})


@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True, 'redirect': '/login'})


@app.route('/api/auth/me', methods=['GET'])
def api_me():
    if not session.get('logged_in'):
        return jsonify({'logged_in': False}), 401
    return jsonify({
        'logged_in': True,
        'username': session.get('username'),
        'name': session.get('name'),
        'role': session.get('role')
    })


@app.route('/api/admin/users', methods=['GET'])
@admin_required
def api_list_users():
    users = load_users()
    result = []
    for uname, udata in users.items():
        result.append({
            'username': uname,
            'name': udata.get('name', uname),
            'role': udata.get('role', 'client')
        })
    return jsonify({'success': True, 'users': result})


@app.route('/api/admin/users', methods=['POST'])
@admin_required
def api_create_user():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'message': 'Dados inválidos.'}), 400
    username = data.get('username', '').strip().lower()
    password = data.get('password', '').strip()
    name = data.get('name', '').strip()
    role = data.get('role', 'client').strip().lower()
    if not username or not password:
        return jsonify({'success': False, 'message': 'Usuário e senha são obrigatórios.'}), 400
    if not re.match(r'^[a-z0-9_\.]{3,30}$', username):
        return jsonify({'success': False, 'message': 'Usuário inválido. Use letras, números, _ ou . (3-30 chars).'}), 400
    if len(password) < 4:
        return jsonify({'success': False, 'message': 'Senha deve ter pelo menos 4 caracteres.'}), 400
    if role not in ('admin', 'client'):
        role = 'client'
    users = load_users()
    if username in users:
        return jsonify({'success': False, 'message': 'Usuário já existe.'}), 409
    users[username] = {
        'password': generate_password_hash(password),
        'role': role,
        'name': name or username
    }
    save_users(users)
    return jsonify({'success': True, 'message': 'Usuário criado com sucesso.'})


@app.route('/api/admin/users/<username>', methods=['DELETE'])
@admin_required
def api_delete_user(username):
    username = username.strip().lower()
    if username == session.get('username'):
        return jsonify({'success': False, 'message': 'Você não pode excluir sua própria conta.'}), 400
    users = load_users()
    if username not in users:
        return jsonify({'success': False, 'message': 'Usuário não encontrado.'}), 404
    del users[username]
    save_users(users)
    return jsonify({'success': True, 'message': 'Usuário removido.'})


@app.route('/api/admin/users/<username>/password', methods=['PUT'])
@admin_required
def api_change_password(username):
    username = username.strip().lower()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'message': 'Dados inválidos.'}), 400
    new_password = data.get('password', '').strip()
    if len(new_password) < 4:
        return jsonify({'success': False, 'message': 'Senha deve ter pelo menos 4 caracteres.'}), 400
    users = load_users()
    if username not in users:
        return jsonify({'success': False, 'message': 'Usuário não encontrado.'}), 404
    users[username]['password'] = generate_password_hash(new_password)
    save_users(users)
    return jsonify({'success': True, 'message': 'Senha alterada com sucesso.'})


@app.route('/api/admin/credentials', methods=['GET'])
@admin_required
def api_list_credentials():
    creds = load_credentials()
    products_meta = []
    for p in DEFAULT_PRODUCTS:
        items = creds.get(p['id'], [])
        available = sum(1 for it in items if not it.get('used'))
        delivered = sum(1 for it in items if it.get('delivered_at'))
        products_meta.append({
            'id': p['id'],
            'name': p['name'],
            'price_label': brl_from_cents(p['price_cents']),
            'total': len(items),
            'available': available,
            'used': len(items) - available,
            'delivered': delivered,
            'items': items
        })
    return jsonify({'success': True, 'products': products_meta})


@app.route('/api/admin/credentials', methods=['POST'])
@admin_required
def api_create_credential():
    data = request.get_json(silent=True) or {}
    product_id = str(data.get('product_id', '')).strip()
    email = str(data.get('email', '')).strip()
    password = str(data.get('password', '')).strip()
    note = str(data.get('note', '')).strip()
    if not product_id or not get_product_by_id(product_id):
        return jsonify({'success': False, 'message': 'Produto inválido.'}), 400
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email e senha são obrigatórios.'}), 400
    creds = load_credentials()
    items = creds.get(product_id, [])
    items.append({
        'id': uuid.uuid4().hex[:10],
        'email': email,
        'password': password,
        'note': note,
        'used': False,
        'created_at': now_iso()
    })
    creds[product_id] = items
    save_credentials(creds)
    return jsonify({'success': True, 'message': 'Acesso cadastrado com sucesso.'})


@app.route('/api/admin/credentials/<product_id>/<credential_id>', methods=['DELETE'])
@admin_required
def api_delete_credential(product_id, credential_id):
    creds = load_credentials()
    items = creds.get(product_id, [])
    new_items = [it for it in items if it.get('id') != credential_id]
    if len(new_items) == len(items):
        return jsonify({'success': False, 'message': 'Acesso não encontrado.'}), 404
    creds[product_id] = new_items
    save_credentials(creds)
    return jsonify({'success': True, 'message': 'Acesso removido.'})


@app.route('/api/admin/credentials/<product_id>/<credential_id>/reset', methods=['POST'])
@admin_required
def api_reset_credential(product_id, credential_id):
    creds = load_credentials()
    items = creds.get(product_id, [])
    found = False
    for it in items:
        if it.get('id') == credential_id:
            it['used'] = False
            it.pop('used_at', None)
            it.pop('delivered_to', None)
            it.pop('delivered_at', None)
            found = True
            break
    if not found:
        return jsonify({'success': False, 'message': 'Acesso não encontrado.'}), 404
    creds[product_id] = items
    save_credentials(creds)
    return jsonify({'success': True, 'message': 'Acesso liberado novamente.'})


@app.route('/api/admin/credentials/<product_id>/<credential_id>', methods=['PUT'])
@admin_required
def api_update_credential(product_id, credential_id):
    data = request.get_json(silent=True) or {}
    creds = load_credentials()
    items = creds.get(product_id, [])
    found = None
    for it in items:
        if it.get('id') == credential_id:
            found = it
            break
    if not found:
        return jsonify({'success': False, 'message': 'Acesso não encontrado.'}), 404
    if 'email' in data:
        new_email = str(data.get('email', '')).strip()
        if not new_email:
            return jsonify({'success': False, 'message': 'Email é obrigatório.'}), 400
        found['email'] = new_email
    if 'password' in data:
        new_password = str(data.get('password', '')).strip()
        if not new_password:
            return jsonify({'success': False, 'message': 'Senha é obrigatória.'}), 400
        found['password'] = new_password
    if 'note' in data:
        found['note'] = str(data.get('note', '')).strip()
    found['updated_at'] = now_iso()
    creds[product_id] = items
    save_credentials(creds)
    return jsonify({'success': True, 'message': 'Acesso atualizado.'})


@app.route('/api/admin/credentials/<product_id>/<credential_id>/deliver', methods=['POST'])
@admin_required
def api_mark_credential_delivered(product_id, credential_id):
    data = request.get_json(silent=True) or {}
    delivered_to = str(data.get('delivered_to', '')).strip()
    creds = load_credentials()
    items = creds.get(product_id, [])
    found = None
    for it in items:
        if it.get('id') == credential_id:
            found = it
            break
    if not found:
        return jsonify({'success': False, 'message': 'Acesso não encontrado.'}), 404
    found['used'] = True
    found['used_at'] = found.get('used_at') or now_iso()
    found['delivered_at'] = now_iso()
    if delivered_to:
        found['delivered_to'] = delivered_to
    creds[product_id] = items
    save_credentials(creds)
    return jsonify({'success': True, 'message': 'Acesso marcado como entregue.'})


@app.route('/api/get-code', methods=['POST'])
@login_required
def get_code():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'message': 'Dados inválidos.'}), 400
    user_email = data.get('email', '').strip().lower()
    platform = data.get('platform', '').strip().lower()
    if not user_email:
        return jsonify({'success': False, 'message': 'Por favor, informe seu email.'}), 400
    if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', user_email):
        return jsonify({'success': False, 'message': 'Email inválido.'}), 400
    if platform not in PLATFORM_CONFIG:
        return jsonify({'success': False, 'message': 'Plataforma não suportada.'}), 400
    code, link, error = search_code(user_email, platform)
    if code:
        return jsonify({'success': True, 'code': code, 'platform': platform, 'type': 'code'})
    elif link:
        return jsonify({'success': True, 'link': link, 'platform': platform, 'type': 'link'})
    else:
        return jsonify({'success': False, 'message': error or 'Não encontrado.'})


@app.route('/api/store/config', methods=['GET'])
@login_required
def api_store_config():
    return jsonify({
        'success': True,
        'handle': INFINITEPAY_HANDLE,
        'redirect_url': INFINITEPAY_REDIRECT_URL,
        'webhook_url': INFINITEPAY_WEBHOOK_URL
    })


@app.route('/api/store/products', methods=['GET'])
@login_required
def api_store_products():
    result = []
    for p in DEFAULT_PRODUCTS:
        result.append({
            'id': p['id'],
            'name': p['name'],
            'description': p['description'],
            'badge': p.get('badge', ''),
            'image_url': p.get('image_url', ''),
            'price_cents': p['price_cents'],
            'price_label': brl_from_cents(p['price_cents'])
        })
    return jsonify({'success': True, 'products': result})


@app.route('/api/store/create-checkout', methods=['POST'])
@login_required
def api_store_create_checkout():
    data = request.get_json(silent=True) or {}
    product_id = data.get('product_id', '').strip()
    customer_name = data.get('customer_name', '').strip()
    customer_email = data.get('customer_email', '').strip().lower()
    customer_phone = data.get('customer_phone', '').strip()
    product = get_product_by_id(product_id)
    if not product:
        return jsonify({'success': False, 'message': 'Produto não encontrado.'}), 404
    if not INFINITEPAY_HANDLE:
        return jsonify({'success': False, 'message': 'INFINITEPAY_HANDLE não configurado no ambiente.'}), 500
    try:
        order = infinitepay_create_link(product, customer_name, customer_email, customer_phone)
        return jsonify({
            'success': True,
            'message': 'Checkout criado com sucesso.',
            'order_nsu': order['order_nsu'],
            'checkout_url': order['checkout_url']
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/store/verify-return', methods=['POST'])
@login_required
def api_store_verify_return():
    data = request.get_json(silent=True) or {}
    order_nsu = str(data.get('order_nsu', '')).strip()
    slug = str(data.get('slug', '')).strip()
    transaction_nsu = str(data.get('transaction_nsu', '')).strip()
    receipt_url = str(data.get('receipt_url', '')).strip()
    capture_method = str(data.get('capture_method', '')).strip()
    if not order_nsu:
        return jsonify({'success': False, 'message': 'order_nsu é obrigatório.'}), 400
    orders = load_orders()
    order = orders.get(order_nsu)
    if not order:
        return jsonify({'success': False, 'message': 'Pedido não encontrado.'}), 404
    changed = False
    if slug and order.get('slug') != slug:
        order['slug'] = slug
        changed = True
    if transaction_nsu and order.get('transaction_nsu') != transaction_nsu:
        order['transaction_nsu'] = transaction_nsu
        changed = True
    if receipt_url and order.get('receipt_url') != receipt_url:
        order['receipt_url'] = receipt_url
        changed = True
    if capture_method and order.get('capture_method') != capture_method:
        order['capture_method'] = capture_method
        changed = True
    if changed:
        orders[order_nsu] = order
        save_orders(orders)
    if order.get('status') == 'paid':
        if not order.get('assigned_account'):
            account = assign_credential(order.get('product_id', ''))
            if account:
                order['assigned_account'] = account
                orders[order_nsu] = order
                save_orders(orders)
        return jsonify({
            'success': True,
            'paid': True,
            'delivery_url': order.get('delivery_url'),
            'product_name': order.get('product_name'),
            'receipt_url': order.get('receipt_url', ''),
            'assigned_account': order.get('assigned_account')
        })
    slug_to_use = slug or order.get('slug', '')
    transaction_to_use = transaction_nsu or order.get('transaction_nsu', '')
    if not slug_to_use or not transaction_to_use:
        return jsonify({'success': True, 'paid': False, 'message': 'Aguardando confirmação do pagamento.'})
    try:
        data_check, paid = infinitepay_check_payment(order_nsu, slug_to_use, transaction_to_use)
        if paid:
            updated = mark_order_paid(order_nsu, {
                'slug': slug_to_use,
                'transaction_nsu': transaction_to_use,
                'receipt_url': receipt_url or str(deep_find_first(data_check, {'receipt_url'}) or ''),
                'capture_method': capture_method or str(data_check.get('capture_method', ''))
            })
            return jsonify({
                'success': True,
                'paid': True,
                'delivery_url': updated.get('delivery_url'),
                'product_name': updated.get('product_name'),
                'receipt_url': updated.get('receipt_url', ''),
                'assigned_account': updated.get('assigned_account')
            })
        return jsonify({'success': True, 'paid': False, 'message': 'Pagamento ainda não confirmado.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/store/order-status/<order_nsu>', methods=['GET'])
@login_required
def api_store_order_status(order_nsu):
    orders = load_orders()
    order = orders.get(order_nsu)
    if not order:
        return jsonify({'success': False, 'message': 'Pedido não encontrado.'}), 404
    return jsonify({
        'success': True,
        'order_nsu': order['order_nsu'],
        'status': order.get('status', 'pending'),
        'product_name': order.get('product_name'),
        'delivery_url': order.get('delivery_url', '') if order.get('status') == 'paid' else '',
        'receipt_url': order.get('receipt_url', ''),
        'assigned_account': order.get('assigned_account') if order.get('status') == 'paid' else None
    })


@app.route('/webhooks/infinitepay', methods=['POST'])
def webhook_infinitepay():
    payload = request.get_json(silent=True) or {}
    print('Webhook InfinitePay recebido:', json.dumps(payload, ensure_ascii=False))
    order_nsu = deep_find_first(payload, {'order_nsu'})
    slug = deep_find_first(payload, {'slug'})
    transaction_nsu = deep_find_first(payload, {'transaction_nsu'})
    receipt_url = deep_find_first(payload, {'receipt_url'})
    capture_method = deep_find_first(payload, {'capture_method'})
    if order_nsu:
        orders = load_orders()
        if order_nsu in orders:
            if payload_indicates_paid(payload):
                mark_order_paid(order_nsu, {
                    'slug': slug if isinstance(slug, str) else '',
                    'transaction_nsu': transaction_nsu if isinstance(transaction_nsu, str) else '',
                    'receipt_url': receipt_url if isinstance(receipt_url, str) else '',
                    'capture_method': capture_method if isinstance(capture_method, str) else ''
                })
            else:
                order = orders[order_nsu]
                changed = False
                if isinstance(slug, str) and slug and order.get('slug') != slug:
                    order['slug'] = slug
                    changed = True
                if isinstance(transaction_nsu, str) and transaction_nsu and order.get('transaction_nsu') != transaction_nsu:
                    order['transaction_nsu'] = transaction_nsu
                    changed = True
                if isinstance(receipt_url, str) and receipt_url and order.get('receipt_url') != receipt_url:
                    order['receipt_url'] = receipt_url
                    changed = True
                if isinstance(capture_method, str) and capture_method and order.get('capture_method') != capture_method:
                    order['capture_method'] = capture_method
                    changed = True
                if changed:
                    orders[order_nsu] = order
                    save_orders(orders)
    return '', 200


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'service': 'Mestre Códigos',
        'infinitepay_handle_configured': bool(INFINITEPAY_HANDLE),
        'base_url': BASE_URL
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(debug=False, host='0.0.0.0', port=port)
