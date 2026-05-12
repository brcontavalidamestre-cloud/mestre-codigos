from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import imaplib
import email
from email.header import decode_header
import re
import os
import json
import unicodedata
import time
from datetime import timedelta

app = Flask(__name__, static_folder='static')
CORS(app)

# ─── SECRET KEY para sessoes ───────────────────────────────────────────────────
app.secret_key = os.environ.get("SECRET_KEY", "central-codigos-secret-2025")
app.permanent_session_lifetime = timedelta(hours=8)

# ─── ARQUIVO DE USUARIOS ───────────────────────────────────────────────────────
# /data é o Volume persistente do Railway (não apaga no redeploy)
# Fallback para /tmp se /data não existir ainda
_data_dir = "/data" if os.path.isdir("/data") else "/tmp"
USERS_FILE = os.environ.get("USERS_FILE", os.path.join(_data_dir, "users.json"))

# Link pendente de redefinição protegido por PIN (armazenado no servidor, não no cliente)
_pending_reset_links = {}
_PENDING_RESET_TTL = 300  # 5 minutos
DEFAULT_RESET_PIN = os.environ.get("DEFAULT_RESET_PIN", "1995")

def _set_pending_reset_link(username, link):
    _pending_reset_links[username] = {
        "link": link,
        "expires_at": time.time() + _PENDING_RESET_TTL
    }

def _pop_pending_reset_link(username):
    item = _pending_reset_links.pop(username, None)
    if not item:
        return None
    if item.get("expires_at", 0) < time.time():
        return None
    return item.get("link")

def _peek_pending_reset_link(username):
    item = _pending_reset_links.get(username)
    if not item:
        return None
    if item.get("expires_at", 0) < time.time():
        _pending_reset_links.pop(username, None)
        return None
    return item.get("link")

def _clear_pending_reset_link(username):
    _pending_reset_links.pop(username, None)


def _user_has_custom_reset_pin(user):
    return bool((user or {}).get("reset_pin"))


def _is_reset_pin_protected(user):
    # Redefinição de senha agora SEMPRE exige PIN.
    return True


def _verify_reset_pin_value(user, pin):
    user = user or {}
    custom_pin = user.get("reset_pin")
    if custom_pin:
        return check_password_hash(custom_pin, pin)
    return pin == DEFAULT_RESET_PIN


def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    # Cria admin padrao se o arquivo nao existe
    default = {
        "admin": {
            "password": generate_password_hash("admin123"),
            "role": "admin",
            "name": "Administrador"
        }
    }
    save_users(default)
    return default

def save_users(users):
    try:
        parent = os.path.dirname(USERS_FILE)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        print(f"[users] salvo em {USERS_FILE} ({len(users)} usuarios)")
    except Exception as e:
        print(f"[users] ERRO ao salvar: {e}")

# ─── CONFIGURACOES IMAP ────────────────────────────────────────────────────────
IMAP_SERVER = os.environ.get("IMAP_SERVER", "imap.hostinger.com")
IMAP_PORT   = int(os.environ.get("IMAP_PORT", 993))
EMAIL_USER  = os.environ.get("EMAIL_USER", "mestre@codigo.log.br")
EMAIL_PASS  = os.environ.get("EMAIL_PASS", "Mcodigo10@")

# Caixa secundária opcional: preencha no Railway para pesquisar em 2 caixas
SECOND_IMAP_SERVER = os.environ.get("SECOND_IMAP_SERVER") or os.environ.get("IMAP_SERVER_2") or IMAP_SERVER
SECOND_IMAP_PORT   = int(os.environ.get("SECOND_IMAP_PORT") or os.environ.get("IMAP_PORT_2") or IMAP_PORT)
SECOND_EMAIL_USER  = os.environ.get("SECOND_EMAIL_USER") or os.environ.get("EMAIL_USER_2") or os.environ.get("EMAIL_USER2", "")
SECOND_EMAIL_PASS  = os.environ.get("SECOND_EMAIL_PASS") or os.environ.get("EMAIL_PASS_2") or os.environ.get("EMAIL_PASS2", "")


def get_imap_accounts():
    accounts = [
        {
            "name": "caixa-principal",
            "server": IMAP_SERVER,
            "port": IMAP_PORT,
            "user": EMAIL_USER,
            "password": EMAIL_PASS,
        }
    ]
    if SECOND_EMAIL_USER and SECOND_EMAIL_PASS:
        accounts.append({
            "name": "caixa-secundaria",
            "server": SECOND_IMAP_SERVER,
            "port": SECOND_IMAP_PORT,
            "user": SECOND_EMAIL_USER,
            "password": SECOND_EMAIL_PASS,
        })
    return accounts

# ─── LOJA / EFI PIX ─────────────────────────────────────────────────────────────
LOJA_PASSWORD       = os.environ.get("LOJA_PASSWORD", "1995")
PRODUCTS_FILE       = os.environ.get("PRODUCTS_FILE", os.path.join(_data_dir, "products.json"))
STOCK_FILE          = os.environ.get("STOCK_FILE", os.path.join(_data_dir, "stock.json"))
ORDERS_FILE         = os.environ.get("ORDERS_FILE", os.path.join(_data_dir, "orders.json"))

# Credenciais Efi (Gerencianet) - configurar via Railway
# Credenciais Efi (Produção) - valores padrão embutidos; podem ser sobrescritos via Railway
EFI_CLIENT_ID       = os.environ.get("EFI_CLIENT_ID", "Client_Id_c9131912e26dcc950ac23d1d271aec2a8a960767")
EFI_CLIENT_SECRET   = os.environ.get("EFI_CLIENT_SECRET", "Client_Secret_7407a03baaf2c2a5984807b845d5de91c7a24a81")
EFI_CERT_PATH       = os.environ.get("EFI_CERT_PATH", "/app/certs/producao-916938-mestre.pem")
EFI_PIX_KEY         = os.environ.get("EFI_PIX_KEY", "efi@mundial.log.br")
EFI_SANDBOX         = os.environ.get("EFI_SANDBOX", "false").lower() == "true"
EFI_WEBHOOK_TOKEN   = os.environ.get("EFI_WEBHOOK_TOKEN", "mestre-codigos-webhook")

DEFAULT_PRODUCTS = [
    {"id": "netflix-premium",  "name": "Netflix Premium",       "price": 35.00, "emoji": "🎬", "color": "#e50914", "description": "Acesso Netflix Premium - liberação automática"},
    {"id": "disney-premium",   "name": "Disney+ Premium",       "price": 25.00, "emoji": "✨", "color": "#0066cc", "description": "Acesso Disney+ Premium - liberação automática"},
    {"id": "globoplay-premium","name": "Globoplay+ Premium",    "price": 20.00, "emoji": "📡", "color": "#ff6600", "description": "Acesso Globoplay+ - liberação automática"},
    {"id": "max-premium",      "name": "Max Premium",           "price": 25.00, "emoji": "🎬", "color": "#7e22ce", "description": "Acesso Max Premium - liberação automática"},
    {"id": "prime-premium",    "name": "Prime Video Premium",   "price": 25.00, "emoji": "📺", "color": "#00a8e1", "description": "Acesso Prime Video - liberação automática"},
]

def _read_json_file(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default
    return default

def _write_json_file(path, data):
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[loja] erro ao gravar {path}: {e}")
        return False

def load_products():
    data = _read_json_file(PRODUCTS_FILE, None)
    if data is None:
        _write_json_file(PRODUCTS_FILE, DEFAULT_PRODUCTS)
        return DEFAULT_PRODUCTS
    return data

def save_products(products):
    return _write_json_file(PRODUCTS_FILE, products)

def load_stock():
    """Estoque de acessos: { product_id: [ {id, email, password, note, used, used_at, delivered_to} ] }"""
    data = _read_json_file(STOCK_FILE, {})
    if not isinstance(data, dict):
        data = {}
    return data

def save_stock(stock):
    if not isinstance(stock, dict):
        stock = {}
    return _write_json_file(STOCK_FILE, stock)

def load_orders():
    data = _read_json_file(ORDERS_FILE, [])
    # Robustez: se alguém gravou como dict, normaliza para lista
    if isinstance(data, dict):
        # tenta converter valores em lista
        try:
            data = list(data.values()) if data else []
        except Exception:
            data = []
    if not isinstance(data, list):
        data = []
    return data

def save_orders(orders):
    if not isinstance(orders, list):
        orders = []
    return _write_json_file(ORDERS_FILE, orders)

def get_next_stock_item(product_id):
    """Retorna o primeiro acesso não usado do produto e marca como usado."""
    stock = load_stock()
    items = stock.get(product_id, [])
    for item in items:
        if not item.get("used"):
            item["used"] = True
            item["used_at"] = int(time.time())
            save_stock(stock)
            return item
    return None

PLATFORM_CONFIG = {
    # ── NETFLIX: código de acesso (PT/EN/ES) ──────────────────────────────────
    "netflix": {
        "from_keyword": "netflix.com",
        "subject_keywords": [
            # Português
            "netflix: seu código de acesso",
            "digo de acesso",
            "código de acesso netflix",
            # Inglês
            "your netflix access code",
            "netflix access code",
            "netflix verification code",
            "your netflix verification code",
            "your one-time passcode for netflix",
            "netflix one-time passcode",
            # Espanhol
            "tu código de acceso netflix",
            "código de acceso netflix",
            "codigo de acceso netflix",
            "tu código de verificación netflix",
            "codigo de verificacion netflix"
        ],
        "negative_keywords": ["temporario", "temporário", "temporal", "temporary", "acceso temporal"],
        "name": "Netflix",
        "type": "code"
    },
    # ── NETFLIX LOGIN: código de início de sessão (PT/EN/ES) ──────────────────
    "netflix-login": {
        "from_keyword": "netflix.com",
        "subject_keywords": [
            # Português
            "digo de in",
            "icio de sess",
            "inicio de sess",
            "código de início",
            # Inglês
            "code to sign in",
            "sign in code",
            "sign-in code",
            "login code",
            "your netflix sign in code",
            "netflix sign-in code",
            # Espanhol
            "código de inicio de sesión",
            "codigo de inicio de sesion",
            "tu código para iniciar sesión",
            "codigo para iniciar sesion",
            "inicia sesión en netflix",
            "código de acceso para iniciar"
        ],
        "name": "Netflix Login",
        "type": "code"
    },
    # ── NETFLIX TEMPORÁRIO: acesso temporário (PT/EN/ES) ──────────────────────
    "netflix-temp": {
        "from_keyword": "netflix.com",
        "subject_keywords": [
            # Português
            "acesso tempor",
            "acesso temporário",
            "acesso temporario",
            "código de acesso temporário",
            "seu código de acesso temporário da netflix",
            "seu codigo de acesso temporario da netflix",
            "código de acesso temporário da netflix",
            "codigo de acesso temporario da netflix",
            "nova solicitação de acesso",
            "nova solicitacao de acesso",
            "solicitação de acesso",
            "solicitacao de acesso",
            # Inglês
            "temporary access",
            "temp access",
            "your temporary access",
            "netflix temporary code",
            "new sign-in request",
            "new login request",
            "new access request",
            # Espanhol
            "acceso temporal",
            "código de acceso temporal",
            "tu código de acceso temporal",
            "codigo de acceso temporal",
            "acceso temporal de netflix",
            "nueva solicitud de inicio de sesión",
            "nueva solicitud de inicio de sesion",
            "nueva solicitud de acceso"
        ],
        "name": "Codigo Temporario Netflix",
        "type": "link"
    },
    # ── DISNEY+: código de acesso (PT/EN/ES) ──────────────────────────────────
    "disney": {
        "from_keyword": "disneyplus.com",
        "subject_keywords": [
            # Português
            "digo de acesso",
            "código de acesso disney",
            "codigo de acesso disney",
            "seu código de acesso único para o disney+",
            "seu codigo de acesso unico para o disney+",
            "código de acesso único para o disney+",
            "codigo de acesso unico para o disney+",
            "código de acesso único disney+",
            "codigo de acesso unico disney+",
            # Inglês
            "your one-time passcode for disney+",
            "your disney+ verification code",
            "disney+ verification code",
            "your disney+ access code",
            "disney+ access code",
            "disney+ one-time passcode",
            # Espanhol
            "tu código de acceso disney+",
            "tu codigo de acceso disney+",
            "tu código de verificación de disney+",
            "tu codigo de verificacion de disney+",
            "código de acceso disney+",
            "codigo de acceso disney+",
            "tu código de acceso de disney+",
            "tu código de acceso único para disney+",
            "tu codigo de acceso unico para disney+"
        ],
        "negative_keywords": [
            "we noticed a new login",
            "identificamos um novo login",
            "novo login",
            "new login",
            "sua conta mydisney foi atualizada",
            "mydisney was updated",
            "complete your disney+ subscription",
            "sabia que o disney+ tem beneficios",
            "sabia que o disney+ tem benefícios"
        ],
        "name": "Disney+",
        "type": "code"
    },
    # ── MAX: código único ──────────────────────────────────────────────────────
    "max": {
        "from_keyword": "hbomax.com",
        "from_keywords": [
            "alerts.hbomax.com",
            "no-reply@alerts.hbomax.com",
            "noreply@alerts.hbomax.com",
            "hbomax.com",
            "hbomax",
            "max.com",
            "warnermedia",
            "wbd.com"
        ],
        "subject_keywords": [
            # Português
            "temporário: aqui está seu código único",
            "temporario: aqui esta seu codigo unico",
            "aqui está seu código único",
            "aqui esta seu codigo unico",
            "seu código único",
            "seu codigo unico",
            "temporário",
            "temporario",
            "código único",
            "codigo unico",
            # Inglês
            "your unique code",
            "your max unique code",
            "your verification code",
            "temporary",
            "unique code",
            # Espanhol
            "tu código único",
            "tu codigo unico",
            "tu código único de max",
            "tu codigo unico de max",
            "código único de max",
            "codigo unico de max"
        ],
        "name": "Max",
        "type": "code"
    },
    # ── PRIME VIDEO: tentativa de login ────────────────────────────────────────
    "prime-video": {
        "from_keyword": "amazon.com",
        "subject_keywords": [
            # Inglês
            "sign-in attempt",
            "sign in attempt",
            "prime video sign-in attempt",
            "amazon sign-in attempt",
            # Espanhol
            "intento de inicio de sesión",
            "intento de inicio de sesion",
            "intento de inicio de sesión en prime video",
            "intento de inicio de sesion en prime video"
        ],
        "name": "Prime Video",
        "type": "code"
    },
    # ── GLOBO BUG: etapa de segurança ──────────────────────────────────────────
    "bug-globo": {
        "from_keyword": "globo.com",
        "subject_keywords": [
            # Português
            "etapa de segurança",
            "etapa de seguranca",
            # Inglês
            "security step",
            "security verification step",
            # Espanhol
            "etapa de seguridad",
            "paso de seguridad"
        ],
        "name": "Bug Globo",
        "type": "code"
    },
    # ── GLOBO CÓDIGO: acesso à Conta Globo ─────────────────────────────────────
    "codigo-globo": {
        "from_keyword": "globo.com",
        "subject_keywords": [
            # Português
            "seu código para acessar a conta globo",
            "seu codigo para acessar a conta globo",
            # Inglês
            "your code to access conta globo",
            "your code to access globo account",
            "your globo account access code",
            # Espanhol
            "tu código para acceder a la cuenta globo",
            "tu codigo para acceder a la cuenta globo",
            "código para acceder a la cuenta globo",
            "codigo para acceder a la cuenta globo"
        ],
        "name": "Código Globo",
        "type": "code"
    },
    # ── GLOBO SENHA: recuperação de senha ──────────────────────────────────────
    # ── STREAMING ALL: Max + Prime Video ────────────────────────────────────
    "streaming-all": {
        "from_keyword": "amazon.com",
        "subject_keywords": ["max", "prime", "amazon"],
        "name": "Max & Prime Video",
        "type": "code"
    },
    # ── GLOBO ALL: busca nas 3 sub-plataformas Globo ────────────────────────
    "globo-all": {
        "from_keyword": "globo.com",
        "subject_keywords": ["globo"],
        "name": "Todos os Códigos Globo",
        "type": "code"
    },
    "senha-globo": {
        "from_keyword": "globo.com",
        "subject_keywords": [
            # Português
            "recuperar sua senha da conta globo",
            # Inglês
            "recover your globo account password",
            "reset your globo account password",
            # Espanhol
            "recuperar tu contraseña de la cuenta globo",
            "recuperar tu contrasena de la cuenta globo",
            "restablecer la contraseña de la cuenta globo",
            # Português (assunto direto)
            "clique para recuperar sua senha"
        ],
        "name": "Senha Globo",
        "type": "link"
    },
    # ── MERCADO LIVRE: código de segurança ───────────────────────────────────
    "apple-tv": {
        "from_keyword": "apple.com",
        "subject_keywords": [
            # Português
            "te enviamos o código de segurança",
            "te enviamos o codigo de seguranca",
            "código de segurança",
            "codigo de seguranca",
            # Inglês
            "we sent you a security code",
            "your security code",
            "security code",
            # Espanhol
            "te enviamos el código de seguridad",
            "te enviamos el codigo de seguridad",
            "código de seguridad",
            "codigo de seguridad"
        ],
        "name": "Apple TV",
        "type": "code"
    },
    # ── NETFLIX ALL: busca em todas as plataformas Netflix ───────────────────
    "netflix-all": {
        "from_keyword": "netflix.com",
        "subject_keywords": ["netflix"],
        "name": "Todos os Códigos Netflix",
        "type": "code"
    },
    # ── NETFLIX RESIDÊNCIA: link de atualização (PT/EN/ES) ────────────────────
    "netflix-residence": {
        "from_keyword": "netflix.com",
        "subject_keywords": [
            # Português
            "pediu para atualizar",
            "atualizar sua resid",
            "atualizar resid",
            "atualizar",
            "importante: como atualizar sua residencia netflix",
            "importante: como atualizar sua residência netflix",
            "como atualizar sua residencia netflix",
            "como atualizar sua residência netflix",
            "enc: importante: como atualizar sua residencia netflix",
            "enc: importante: como atualizar sua residência netflix",
            # Inglês
            "update your Netflix",
            "Netflix Home",
            "update your netflix household",
            "netflix household",
            "confirm your netflix location",
            "confirm your location",
            # Espanhol
            "actualiza tu residencia netflix",
            "actualizar tu residencia",
            "residencia netflix",
            "confirmar tu ubicacion netflix",
            "confirma tu residencia",
            # Espanhol extra
            "Importante: Cómo actualizar tu Hogar con Netflix",
            "Importante: Como actualizar tu Hogar con Netflix",
            "actualizar tu Hogar con Netflix",
            "tu Hogar con Netflix"
        ],
        "name": "Residencia Netflix",
        "type": "link"
    },
    # ── NETFLIX SENHA: redefinição de senha (PT/EN/ES) ────────────────────────
    "password-reset": {
        "from_keyword": "netflix.com",
        "subject_keywords": [
            # Português
            "Complete a solicitacao de redefinicao de senha",
            "redefinicao de senha",
            "redefini",
            "redefinir senha",
            "alterar senha netflix",
            # Inglês
            "reset password",
            "password reset",
            "reset ang password",
            "complete your password reset",
            "netflix password reset",
            "change your netflix password",
            # Espanhol / Filipino
            "Completa tu solicitud de restablecimiento de contrasena",
            "restablecimiento de contrasena",
            "Tapusin ang request mong i-reset ang password",
            "restablecer contraseña netflix",
            "cambiar contraseña netflix",
            # Português (variação ENC)
            "enc: complete a solicitação de redefinição de senha",
            "enc: complete a solicitacao de redefinicao de senha"
        ],
        "negative_keywords": [
            "nova solicitação de acesso",
            "nova solicitacao de acesso",
            "solicitação de acesso",
            "solicitacao de acesso",
            "new sign-in request",
            "new login request",
            "new access request",
            "nueva solicitud de inicio de sesión",
            "nueva solicitud de inicio de sesion",
            "nueva solicitud de acceso"
        ],
        "name": "Redefinicao de Senha Netflix",
        "type": "link"
    },
    # ── DISNEY+ RESIDÊNCIA: link de atualização (PT/EN/ES) ────────────────────
    # ── DISNEY ALL: busca em ambas as plataformas Disney+ ────────────────────
    "disney-all": {
        "from_keyword": "disneyplus.com",
        "subject_keywords": ["disney"],
        "name": "Todos os Códigos Disney+",
        "type": "code"
    },
    "disney-residence": {
        "from_keyword": "disneyplus.com",
        "subject_keywords": [
            # Português
            "Quer atualizar sua Residencia do Disney+",
            "atualizar sua Residencia do Disney",
            "Residencia do Disney",
            # Inglês
            "update your Disney+ Home",
            "Disney+ Home",
            "update your disney+ household",
            "confirm your disney+ location",
            "disney+ household",
            # Espanhol
            "actualiza tu Residencia de Disney+",
            "actualizar Residencia Disney+",
            "tu Residencia de Disney+",
            "Residencia Disney+",
            "confirmar ubicacion disney+"
        ],
        "name": "Residencia Disney+",
        "type": "link"
    }
}

# ─── UTILITARIOS ───────────────────────────────────────────────────────────────

def decode_str(s):
    if not s:
        return ""
    parts = decode_header(s)
    result = ""
    for part, enc in parts:
        if isinstance(part, bytes):
            result += part.decode(enc or "utf-8", errors="ignore")
        else:
            result += str(part)
    return result

def normalize(text):
    text = text.lower()
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c))

FORWARD_PREFIX_RE = re.compile(r'^\s*((?:fw|fwd|enc|re)\s*:\s*)+', re.IGNORECASE)

def clean_subject_prefixes(subject):
    subject = subject or ""
    return FORWARD_PREFIX_RE.sub("", subject).strip()

def subject_matches(subject, keywords, negative_keywords=None):
    subject = clean_subject_prefixes(subject)
    subj_norm  = normalize(subject)
    subj_lower = subject.lower()
    # Rejeita se o assunto contiver alguma palavra negativa
    if negative_keywords:
        for nkw in negative_keywords:
            if normalize(nkw) in subj_norm or nkw.lower() in subj_lower:
                return False
    for kw in keywords:
        if normalize(kw) in subj_norm or kw.lower() in subj_lower:
            return True
    return False

def get_html_body(msg):
    html = ""
    plain = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct  = part.get_content_type()
            cd  = str(part.get("Content-Disposition", ""))
            if "attachment" in cd:
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="ignore")
            if ct == "text/html":
                html += text
            elif ct == "text/plain" and not plain:
                plain += text
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="ignore")
            if msg.get_content_type() == "text/html":
                html = text
            else:
                plain = text
    return html or plain

def extract_code_from_html(html_body):
    # Lista de números que NUNCA devem ser retornados como código (rodapé, ano, endereço, etc.)
    BLACKLIST = {
        "1026", "10026", "230",  # Endereço HBO Max: 230 Park Avenue South, NY 10026
        "2024", "2025", "2026", "2027",  # Anos
        "1999", "2000", "2001", "2002", "2003", "2004", "2005",
        "2006", "2007", "2008", "2009", "2010", "2011", "2012",
        "2013", "2014", "2015", "2016", "2017", "2018", "2019",
        "2020", "2021", "2022", "2023",
        "100", "200", "300", "400", "500", "800", "900", "1000",  # Números redondos
    }

    def is_valid_code(c):
        if not c or not c.isdigit():
            return False
        if c in BLACKLIST:
            return False
        if len(c) < 4 or len(c) > 8:
            return False
        return True

    # 1. Dígitos separados por espaço/nbsp dentro de span/td estilizado (ex: "0 4 6 4")
    m = re.search(
        r"letter-spacing[^>]{0,200}>\s*((?:[0-9]\s*){4,8})<",
        html_body, re.IGNORECASE | re.DOTALL
    )
    if m:
        code = re.sub(r"\s+", "", m.group(1)).strip()
        if is_valid_code(code):
            return code

    # 2. Dígitos em fonte grande (só numérico) — código do Max/HBO normalmente em font-size grande
    m = re.search(
        r"font-size\s*:\s*(?:[3-9]\d|[12]\d\d)px[^>]*>\s*((?:[0-9]\s*){4,8})\s*<",
        html_body, re.IGNORECASE
    )
    if m:
        code = re.sub(r"\s+", "", m.group(1)).strip()
        if is_valid_code(code):
            return code

    # 3. Qualquer elemento com letter-spacing que contenha SOMENTE dígitos
    for m in re.finditer(
        r"letter-spacing[^>]{0,300}>\s*((?:[0-9][\s\u00a0]*){4,8})\s*<",
        html_body, re.IGNORECASE | re.DOTALL
    ):
        candidate = re.sub(r"[\s\u00a0]+", "", m.group(1)).strip()
        if is_valid_code(candidate):
            return candidate

    # 3.5. Padrão específico HBO Max: "Seu código único" seguido de número 6 dígitos
    m = re.search(
        r"seu\s*c[o\u00f3]digo\s*[\u00fau]nico[^0-9]{0,200}([0-9]{6})",
        html_body, re.IGNORECASE | re.DOTALL
    )
    if m and is_valid_code(m.group(1)):
        return m.group(1)

    m = re.search(
        r"your\s*unique\s*code[^0-9]{0,200}([0-9]{6})",
        html_body, re.IGNORECASE | re.DOTALL
    )
    if m and is_valid_code(m.group(1)):
        return m.group(1)

    m = re.search(
        r"tu\s*c[o\u00f3]digo\s*[\u00fau]nico[^0-9]{0,200}([0-9]{6})",
        html_body, re.IGNORECASE | re.DOTALL
    )
    if m and is_valid_code(m.group(1)):
        return m.group(1)

    # 4. Texto limpo — padrões semânticos (PRIORIDADE: 6 dígitos > 5 > 4)
    clean = re.sub(r"<[^>]+>", " ", html_body)
    clean = re.sub(r"\s+", " ", clean)

    # 4a. Códigos de 6 dígitos com contexto semântico forte
    patterns_6 = [
        r"c[o\u00f3]digo\s*[\u00fau]nico[^0-9]{0,100}([0-9]{6})",
        r"c[o\u00f3]digo\s*(?:de acesso|tempor[a\u00e1]rio)?\s*[:\-]?\s*([0-9]{6})",
        r"access\s*code\s*[:\-]?\s*([0-9]{6})",
        r"unique\s*code\s*[:\-]?\s*([0-9]{6})",
        r"verification\s*code\s*[:\-]?\s*([0-9]{6})",
        r"c[o\u00f3]digo\s*de\s*verifica[c\u00e7][a\u00e3]o\s*[:\-]?\s*([0-9]{6})",
        r"one[- ]time\s*(?:password|code)\s*[:\-]?\s*([0-9]{6})",
        r"OTP\s*[:\-]?\s*([0-9]{6})",
    ]
    for pat in patterns_6:
        m = re.search(pat, clean, re.IGNORECASE)
        if m and is_valid_code(m.group(1)):
            return m.group(1)

    # 4b. Códigos de 4-8 dígitos com contexto semântico
    patterns_text = [
        r"c[o\u00f3]digo\s*(?:de acesso|tempor[a\u00e1]rio|[\u00fau]nico)?\s*[:\-]?\s*([0-9]{4,8})",
        r"access\s*code\s*[:\-]?\s*([0-9]{4,8})",
        r"\b([0-9]{4,8})\b(?=\s*(?:\u00e9 seu|\u00e9 o seu|para entrar|para acessar|es tu|es el))",
    ]
    for pat in patterns_text:
        m = re.search(pat, clean, re.IGNORECASE)
        if m and is_valid_code(m.group(1)):
            return m.group(1)

    # 4c. Fallback final: qualquer 6 dígitos isolado que NÃO esteja na blacklist
    for m in re.finditer(r"\b([0-9]{6})\b", clean):
        if is_valid_code(m.group(1)):
            return m.group(1)

    # 4d. Fallback ainda mais permissivo: 4 dígitos isolados (último recurso)
    for m in re.finditer(r"\b([0-9]{4})\b", clean):
        if is_valid_code(m.group(1)):
            return m.group(1)

    return None

def extract_link(html_body, platform):
    """
    Extrai o link relevante do corpo HTML do email.
    Para netflix-residence, prioriza o botão "Sim, fui eu".
    """
    if platform == "netflix-residence":
        # Prioridade 1: botão "Sim, fui eu" (link de confirmação de residência)
        patterns = [
            r'href=["\'](https://www\.netflix\.com/account/travel/[^"\' ]+)["\']',
            r'href=["\'](https://www\.netflix\.com/account/[^"\' ]*(?:update|atualiz|resid|location|travel|verify)[^"\' ]*)["\']',
            r'href=["\'](https://www\.netflix\.com/[^"\' ]*(?:confirm|yes|sim|approve|atualiz|resid)[^"\' ]*)["\']',
            r'href=["\'](https://www\.netflix\.com/account/[^"\' ]+)["\']',
        ]
        domain = "netflix.com"
    elif platform == "netflix-temp":
        # Link de acesso temporário / nova solicitação de acesso
        patterns = [
            r'href=["\'](https://www\.netflix\.com/ilum\?code=[^"\' ]+)["\']',
            r'href=["\'](https://www\.netflix\.com/[^"\' ]*(?:temporary|tempor|receive|receber|acesso|request|solicita|login|signin|sign-in)[^"\' ]*)["\']',
            r'href=["\'](https://[^"\' ]*netflix\.com[^"\' ]*(?:code|codigo|auth|verify|token)[^"\' ]*)["\']',
            r'href=["\'](https://www\.netflix\.com/[^"\' ]{40,})["\']',
        ]
        domain = "netflix.com"
    elif platform == "password-reset":
        patterns = [
            r'href=["\'](https://www\.netflix\.com/[^"\' ]*(?:password|reset|redefin|senha)[^"\' ]*)["\']',
            r'href=["\'](https://www\.netflix\.com/account/[^"\' ]+)["\']',
        ]
        domain = "netflix.com"
    elif platform == "disney-residence":
        patterns = [
            r'href=["\'](https://[^"\' ]*(?:disneyplus|disney)\.com[^"\' ]*(?:update|atualiz|resid|home|location)[^"\' ]*)["\']',
            r'href=["\'](https://[^"\' ]*disneyplus\.com[^"\' ]+)["\']',
        ]
        domain = "disney"
    elif platform == "senha-globo":
        patterns = [
            r'href=["\'](https://[^"\' ]*conta\.globo\.com[^"\' ]+)["\']',
            r'href=["\'](https://[^"\' ]*globo\.com[^"\' ]*(?:senha|recuper|login|conta)[^"\' ]*)["\']',
            r'href=["\'](https://[^"\' ]*globo\.com[^"\' ]+)["\']',
        ]
        domain = "globo"
    else:
        patterns = []
        domain = "netflix.com"
    for pat in patterns:
        m = re.search(pat, html_body, re.IGNORECASE)
        if m:
            link = m.group(1)
            if len(link) > 30:
                return link
    # Fallback: any link from the domain
    all_links = re.findall(r'href=["\'"]([^"\'"]+)["\'"]', html_body, re.IGNORECASE)
    domain_links = [l for l in all_links if domain in l.lower() and len(l) > 50]
    if domain_links:
        return domain_links[0]
    return None
def email_matches_user(msg, html_body, user_email):
    user_lower = user_email.lower()

    # 1. Verifica no corpo HTML já extraído
    if user_lower in html_body.lower():
        return True

    # 2. Verifica nos headers principais
    for header in ["To", "Delivered-To", "X-Original-To", "X-Forwarded-To"]:
        if user_lower in decode_str(msg.get(header, "")).lower():
            return True

    # 3. Verifica em TODAS as partes de texto (HTML + plain) do email
    #    Essencial para emails encaminhados (ENC:/FW:) onde o destinatário
    #    original aparece apenas no texto plano da mensagem encaminhada
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct in ("text/plain", "text/html"):
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        try:
                            text = payload.decode(charset, errors="ignore")
                            if user_lower in text.lower():
                                return True
                        except Exception:
                            pass
    except Exception:
        pass

    # 4. Varre os bytes brutos do email (corrigido: decode antes de lower())
    try:
        raw_str = msg.as_bytes().decode("utf-8", errors="ignore").lower()
        if user_lower in raw_str:
            return True
    except Exception:
        pass

    # 5. Matching relaxado: parte do usuário antes do "@"
    #    Netflix password-reset não inclui o email no corpo, só o primeiro nome.
    #    Mas o username (ex: "ivo89cg") costuma aparecer em links ou cabeçalhos.
    try:
        username = user_lower.split("@")[0]
        domain   = user_lower.split("@")[1] if "@" in user_lower else ""
        if len(username) >= 5:                     # evita falsos positivos
            combined = html_body.lower()
            if username in combined:
                return True
            # Tenta também nas partes de texto
            if msg.is_multipart():
                for part in msg.walk():
                    ct = part.get_content_type()
                    if ct in ("text/plain", "text/html"):
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            try:
                                text = payload.decode(charset, errors="ignore").lower()
                                if username in text:
                                    return True
                            except Exception:
                                pass
    except Exception:
        pass

    return False

import socket as _socket
from datetime import datetime as _dt, timedelta as _td

# ── Cache de caixas de spam disponíveis (descoberto 1x, reutilizado) ──────────
_spam_boxes_cache = {}


def _account_cache_key(account_cfg):
    return f"{account_cfg.get('user','')}@{account_cfg.get('server','')}:{account_cfg.get('port','')}"


def connect_imap(account_cfg=None):
    """Conecta ao IMAP com timeout um pouco maior e sem vazar socket auxiliar."""
    account_cfg = account_cfg or get_imap_accounts()[0]
    mail = imaplib.IMAP4_SSL(account_cfg["server"], int(account_cfg["port"]), timeout=20)
    try:
        mail.sock.settimeout(20)
    except Exception:
        pass
    mail.login(account_cfg["user"], account_cfg["password"])
    return mail


def _safe_logout(mail):
    """Encerra a sessão IMAP sem deixar exceções de timeout vazarem ao usuário."""
    try:
        if mail is not None:
            mail.logout()
    except Exception:
        pass

def _get_spam_boxes(mail, account_cfg=None):
    """Descobre caixas de spam uma única vez por conta e armazena em cache."""
    account_cfg = account_cfg or get_imap_accounts()[0]
    cache_key = _account_cache_key(account_cfg)
    if cache_key in _spam_boxes_cache:
        return _spam_boxes_cache[cache_key]
    SPAM_CANDIDATES = ["Spam", "Junk", "SPAM", "JUNK",
                       "[Gmail]/Spam", "[Gmail]/Lixo Eletrônico",
                       "Junk Email", "Bulk Mail", "Lixo Eletronico"]
    try:
        status_list, mailbox_list = mail.list()
        available = []
        if status_list == "OK":
            for mb in mailbox_list:
                try:
                    mb_str = mb.decode("utf-8") if isinstance(mb, bytes) else str(mb)
                    parts = mb_str.split('"')
                    if len(parts) >= 3:
                        box_name = parts[-2].strip()
                    else:
                        box_name = mb_str.split()[-1].strip('"')
                    available.append(box_name)
                except Exception:
                    continue
        result = []
        for cand in SPAM_CANDIDATES:
            for avail in available:
                if cand.lower() == avail.lower():
                    result.append(avail)
                    break
        _spam_boxes_cache[cache_key] = result
    except Exception:
        _spam_boxes_cache[cache_key] = []
    return _spam_boxes_cache[cache_key]

FWD_PREFIXES_SEARCH = ["ENC:", "Enc:", "FW:", "Fw:", "Fwd:", "FWD:", "RE:", "Re:"]

def _batch_search_mailbox(mail, mailbox, from_kw, platform_configs, seen_ids,
                           use_date_filter=True, since_date=None):
    """
    Busca emails de uma caixa usando BATCH FETCH de headers.
    Filtra por múltiplas plataformas de uma vez.
    Retorna lista de (mailbox, platform_key, email_id) do MAIS RECENTE para o mais antigo.
    """
    matched = []
    try:
        sel_status, _ = mail.select(mailbox, readonly=True)
        if sel_status != "OK":
            return matched

        # ── Passagem 1: SEARCH FROM + data ──────────────────────────────────
        if use_date_filter and since_date:
            search_criteria = ["FROM", from_kw, "SINCE", since_date]
        else:
            search_criteria = ["FROM", from_kw]

        status, msgs = mail.search(None, *search_criteria)
        if status == "OK" and msgs[0]:
            all_ids = msgs[0].split()
            # Últimos 50 — servidor devolve em ordem crescente de ID
            # Os IDs maiores = emails mais recentes
            recent_ids = all_ids[-50:]  # os 50 de maior ID (mais recentes)

            # ── BATCH FETCH de todos os headers em um único round-trip ──────
            id_str = b",".join(recent_ids)
            st_b, data_b = mail.fetch(id_str, "(BODY[HEADER.FIELDS (SUBJECT)])")
            if st_b == "OK":
                id_idx = 0
                for item in data_b:
                    if isinstance(item, tuple):
                        if id_idx >= len(recent_ids):
                            break
                        eid = recent_ids[id_idx]
                        hdr  = email.message_from_bytes(item[1])
                        subj = decode_str(hdr.get("Subject", ""))
                        key  = (mailbox, eid)
                        if key not in seen_ids:
                            for plat_key, plat_cfg in platform_configs.items():
                                if subject_matches(subj,
                                                   plat_cfg["subject_keywords"],
                                                   plat_cfg.get("negative_keywords")):
                                    matched.append((mailbox, plat_key, eid))
                                    seen_ids.add(key)
                                    break
                        id_idx += 1

        # ── Passagem 2: encaminhados (só se sem resultado) ───────────────────
        if not matched:
            for prefix in FWD_PREFIXES_SEARCH:
                try:
                    if use_date_filter and since_date:
                        st2, msgs2 = mail.search(None, "SUBJECT", prefix, "SINCE", since_date)
                    else:
                        st2, msgs2 = mail.search(None, "SUBJECT", prefix)
                    if st2 != "OK" or not msgs2[0]:
                        continue
                    fwd_ids = msgs2[0].split()[-200:]  # últimos 200 encaminhados
                    if not fwd_ids:
                        continue
                    id_str2 = b",".join(fwd_ids)
                    st3, data3 = mail.fetch(id_str2, "(BODY[HEADER.FIELDS (SUBJECT)])")
                    if st3 != "OK":
                        continue
                    id_idx2 = 0
                    for item3 in data3:
                        if isinstance(item3, tuple):
                            if id_idx2 >= len(fwd_ids):
                                break
                            eid3 = fwd_ids[id_idx2]
                            hdr3  = email.message_from_bytes(item3[1])
                            subj3 = decode_str(hdr3.get("Subject", ""))
                            subj_clean = clean_subject_prefixes(subj3)
                            key3 = (mailbox, eid3)
                            if key3 not in seen_ids:
                                for plat_key, plat_cfg in platform_configs.items():
                                    if subject_matches(subj_clean,
                                                       plat_cfg["subject_keywords"],
                                                       plat_cfg.get("negative_keywords")):
                                        matched.append((mailbox, plat_key, eid3))
                                        seen_ids.add(key3)
                                        break
                            id_idx2 += 1
                except Exception:
                    continue
    except Exception:
        pass
    # Reverter: IDs crescentes → queremos o MAIOR ID (mais recente) primeiro
    matched.reverse()
    return matched


def _fetch_and_extract(mail, mailbox, eid, plat_key, user_email):
    """Faz RFC822 fetch, verifica email do usuário e extrai código/link."""
    try:
        mail.select(mailbox, readonly=True)
        status, data = mail.fetch(eid, "(RFC822)")
        if status != "OK":
            return None, None
        msg       = email.message_from_bytes(data[0][1])
        html_body = get_html_body(msg)
        if not email_matches_user(msg, html_body, user_email):
            return None, None
        cfg = PLATFORM_CONFIG[plat_key]
        if cfg.get("type") == "link":
            link = extract_link(html_body, plat_key)
            return None, link
        else:
            code = extract_code_from_html(html_body)
            return code, None
    except Exception:
        return None, None


def _targeted_subject_search(mail, mailbox, from_kw, plat_key, seen_ids,
                             subject_terms, since_date=None):
    """
    Busca direcionada por assunto sem disparar vários SEARCH SUBJECT caros.
    Faz 1 SEARCH por remetente, pega uma janela recente e filtra assuntos em memória.
    Retorna (mailbox, plat_key, eid) do mais recente para o mais antigo.
    """
    matched = []
    try:
        sel_status, _ = mail.select(mailbox, readonly=True)
        if sel_status != "OK":
            return matched

        criteria = ["FROM", from_kw]
        if since_date:
            criteria += ["SINCE", since_date]
        st, msgs = mail.search(None, *criteria)
        if st != "OK" or not msgs[0]:
            return matched

        all_ids = msgs[0].split()
        recent_ids = all_ids[-250:]
        if not recent_ids:
            return matched

        id_str = b",".join(recent_ids)
        st_b, data_b = mail.fetch(id_str, "(BODY[HEADER.FIELDS (SUBJECT)])")
        if st_b != "OK":
            return matched

        cfg = PLATFORM_CONFIG[plat_key]
        idx = 0
        for item in data_b:
            if isinstance(item, tuple):
                if idx >= len(recent_ids):
                    break
                eid = recent_ids[idx]
                hdr = email.message_from_bytes(item[1])
                subj = decode_str(hdr.get("Subject", ""))
                subj_norm = normalize(subj)
                fast_hit = any(normalize(term) in subj_norm for term in subject_terms)
                key = (mailbox, eid)
                if key not in seen_ids and fast_hit and subject_matches(
                    subj,
                    cfg["subject_keywords"],
                    cfg.get("negative_keywords")
                ):
                    matched.append((mailbox, plat_key, eid))
                    seen_ids.add(key)
                idx += 1
    except Exception:
        pass

    matched.reverse()
    return matched


def _targeted_forwarded_search(mail, mailbox, plat_key, seen_ids,
                               subject_terms, since_date=None):
    """
    Busca encaminhados recentes sem usar SEARCH SUBJECT por prefixo.
    Quando há data, usa SEARCH SINCE; sem data, varre só a cauda da caixa por faixa sequencial.
    Retorna (mailbox, plat_key, eid) do mais recente para o mais antigo.
    """
    matched = []
    try:
        sel_status, sel_data = mail.select(mailbox, readonly=True)
        if sel_status != "OK":
            return matched

        recent_ids = []
        if since_date:
            st, msgs = mail.search(None, "SINCE", since_date)
            if st != "OK" or not msgs[0]:
                return matched
            recent_ids = msgs[0].split()[-1500:]
        else:
            total_msgs = int(sel_data[0]) if sel_data and sel_data[0] else 0
            if total_msgs <= 0:
                return matched
            start_seq = max(1, total_msgs - 1500 + 1)
            recent_ids = [str(i).encode() for i in range(start_seq, total_msgs + 1)]

        if not recent_ids:
            return matched

        id_str = b",".join(recent_ids)
        st_b, data_b = mail.fetch(id_str, "(BODY[HEADER.FIELDS (SUBJECT)])")
        if st_b != "OK":
            return matched

        cfg = PLATFORM_CONFIG[plat_key]
        idx = 0
        for item in data_b:
            if isinstance(item, tuple):
                if idx >= len(recent_ids):
                    break
                eid = recent_ids[idx]
                hdr = email.message_from_bytes(item[1])
                subj = decode_str(hdr.get("Subject", ""))
                subj_upper = subj.upper()
                subj_clean = clean_subject_prefixes(subj)
                if subj_clean == subj.strip():
                    idx += 1
                    continue
                key = (mailbox, eid)
                fast_hit = any(normalize(term) in normalize(subj_clean) for term in subject_terms)
                if key not in seen_ids and fast_hit and subject_matches(
                    subj_clean,
                    cfg["subject_keywords"],
                    cfg.get("negative_keywords")
                ):
                    matched.append((mailbox, plat_key, eid))
                    seen_ids.add(key)
                idx += 1
    except Exception:
        pass

    matched.reverse()
    return matched


def search_code_unified(user_email, platform_list):
    """
    Busca múltiplas plataformas do mesmo remetente em UMA ÚNICA passagem IMAP.
    Agora consulta também uma segunda caixa IMAP, se configurada.
    Retorna (code, link, matched_platform, error).
    """
    # Agrupar plataformas por remetente
    by_sender = {}
    for p in platform_list:
        cfg = PLATFORM_CONFIG.get(p)
        if not cfg:
            continue
        fk = cfg["from_keyword"]
        if fk not in by_sender:
            by_sender[fk] = {}
        by_sender[fk][p] = cfg

    accounts = get_imap_accounts()
    if not accounts:
        return None, None, None, "Nenhuma caixa de email configurada."

    last_error = None

    for account_cfg in accounts:
        mail = None
        try:
            mail = connect_imap(account_cfg)
            today     = _dt.utcnow().strftime("%d-%b-%Y")
            since_2d  = (_dt.utcnow() - _td(days=2)).strftime("%d-%b-%Y")
            spam_boxes = _get_spam_boxes(mail, account_cfg)
            seen_ids   = set()

            for sender, plat_configs in by_sender.items():
                matched = _batch_search_mailbox(
                    mail, "INBOX", sender, plat_configs, seen_ids,
                    use_date_filter=True, since_date=today)

                if not matched:
                    matched = _batch_search_mailbox(
                        mail, "INBOX", sender, plat_configs, seen_ids,
                        use_date_filter=True, since_date=since_2d)

                if not matched:
                    matched = _batch_search_mailbox(
                        mail, "INBOX", sender, plat_configs, seen_ids,
                        use_date_filter=False)

                if not matched:
                    for mb in spam_boxes:
                        matched.extend(_batch_search_mailbox(
                            mail, mb, sender, plat_configs, seen_ids,
                            use_date_filter=False))
                        if matched:
                            break

                for mb, plat_key, eid in matched:
                    code, link = _fetch_and_extract(mail, mb, eid, plat_key, user_email)
                    if code or link:
                        _safe_logout(mail)
                        return code, link, plat_key, None

                targeted_platforms = []
                if "password-reset" in plat_configs:
                    targeted_platforms.append(("password-reset", ["redefini", "password", "reset", "restablec", "i-reset"]))
                if "netflix-temp" in plat_configs:
                    targeted_platforms.append(("netflix-temp", ["tempor", "temporary", "solicitacao de acesso", "solicitação de acesso", "sign-in request", "login request", "inicio de sesion", "inicio de sesión"]))
                if "netflix-residence" in plat_configs:
                    targeted_platforms.append(("netflix-residence", ["residencia", "atualizar", "household", "hogar", "importante"]))
                if "disney" in plat_configs:
                    targeted_platforms.append(("disney", ["codigo de acesso", "acesso unico", "access code", "verification code", "passcode", "codigo de verificacion"]))
                if "max" in plat_configs:
                    targeted_platforms.append(("max", ["codigo unico", "código único", "codigo único", "código unico", "unique code", "temporario", "temporário", "temporary", "aqui esta seu codigo", "aqui está seu código", "your unique code", "tu codigo unico", "tu código único", "max", "hbo"]))

                if targeted_platforms:
                    _safe_logout(mail)
                    mail = connect_imap(account_cfg)
                    spam_boxes = _get_spam_boxes(mail, account_cfg)

                for target_plat, targeted_terms in targeted_platforms:
                    since_7d = (_dt.utcnow() - _td(days=7)).strftime("%d-%b-%Y")
                    targeted_matches = []

                    targeted_matches.extend(_targeted_subject_search(
                        mail, "INBOX", sender, target_plat, seen_ids,
                        targeted_terms, since_date=since_7d
                    ))

                    if not targeted_matches:
                        targeted_matches.extend(_targeted_subject_search(
                            mail, "INBOX", sender, target_plat, seen_ids,
                            targeted_terms, since_date=None
                        ))

                    if not targeted_matches:
                        for mb in spam_boxes:
                            targeted_matches.extend(_targeted_subject_search(
                                mail, mb, sender, target_plat, seen_ids,
                                targeted_terms, since_date=None
                            ))
                            if targeted_matches:
                                break

                    if not targeted_matches:
                        targeted_matches.extend(_targeted_forwarded_search(
                            mail, "INBOX", target_plat, seen_ids,
                            targeted_terms, since_date=since_7d
                        ))

                    if not targeted_matches:
                        targeted_matches.extend(_targeted_forwarded_search(
                            mail, "INBOX", target_plat, seen_ids,
                            targeted_terms, since_date=None
                        ))

                    if not targeted_matches:
                        for mb in spam_boxes:
                            targeted_matches.extend(_targeted_forwarded_search(
                                mail, mb, target_plat, seen_ids,
                                targeted_terms, since_date=None
                            ))
                            if targeted_matches:
                                break

                    for mb, plat_key, eid in targeted_matches:
                        code, link = _fetch_and_extract(mail, mb, eid, plat_key, user_email)
                        if code or link:
                            _safe_logout(mail)
                            return code, link, plat_key, None

            _safe_logout(mail)
        except imaplib.IMAP4.error as e:
            last_error = f"[{account_cfg.get('name')}] Erro de conexao com servidor de email: {e}"
            _safe_logout(mail)
            continue
        except Exception as e:
            _safe_logout(mail)
            if "timed out object" in str(e).lower() or "timed out" in str(e).lower():
                last_error = f"[{account_cfg.get('name')}] Tempo de consulta excedido no servidor de email."
            else:
                last_error = f"[{account_cfg.get('name')}] Erro interno: {e}"
            continue

    return None, None, None, last_error or "Nenhum email encontrado para este endereco."

def search_code(user_email, platform):
    """Busca código/link para uma plataforma específica (usa search_code_unified internamente)."""
    config = PLATFORM_CONFIG.get(platform)
    if not config:
        return None, None, "Plataforma nao suportada."
    code, link, matched_plat, error = search_code_unified(user_email, [platform])
    if code:
        return code, None, None
    elif link:
        return None, link, None
    else:
        return None, None, error or ("Nenhum email de " + config["name"] + " encontrado.")

# ─── MIDDLEWARES / HELPERS ─────────────────────────────────────────────────────

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"success": False, "message": "Nao autenticado.", "redirect": "/login"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"success": False, "message": "Nao autenticado.", "redirect": "/login"}), 401
        if session.get("role") != "admin":
            return jsonify({"success": False, "message": "Acesso restrito ao administrador."}), 403
        return f(*args, **kwargs)
    return decorated

# ─── ROTAS DE PAGINAS ──────────────────────────────────────────────────────────

@app.route("/")
def index():
    if not session.get("logged_in"):
        return redirect("/login")
    return send_from_directory("static", "index.html")

@app.route("/login")
def login_page():
    if session.get("logged_in"):
        if session.get("role") == "admin":
            return redirect("/admin")
        return redirect("/")
    return send_from_directory("static", "login.html")

@app.route("/admin")
def admin_page():
    if not session.get("logged_in"):
        return redirect("/login")
    if session.get("role") != "admin":
        return redirect("/")
    return send_from_directory("static", "admin.html")

# ─── ROTAS DE AUTENTICACAO ─────────────────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Dados invalidos."}), 400
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"success": False, "message": "Informe usuario e senha."}), 400
    users = load_users()
    user  = users.get(username)
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"success": False, "message": "Usuario ou senha incorretos."}), 401
    session.permanent = True
    session["logged_in"] = True
    session["username"]  = username
    session["role"]      = user.get("role", "client")
    session["name"]      = user.get("name", username)
    redirect_to = "/admin" if user.get("role") == "admin" else "/"
    return jsonify({"success": True, "role": user.get("role", "client"), "redirect": redirect_to})

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True, "redirect": "/login"})

@app.route("/api/auth/me", methods=["GET"])
def api_me():
    if not session.get("logged_in"):
        return jsonify({"logged_in": False}), 401
    return jsonify({
        "logged_in": True,
        "username": session.get("username"),
        "name":     session.get("name"),
        "role":     session.get("role")
    })

# ─── ROTAS DE ADMIN (gerenciamento de usuarios) ───────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
@admin_required
def api_list_users():
    current_admin = session.get("username")
    users = load_users()
    result = []
    for uname, udata in users.items():
        if uname == current_admin:
            continue  # nao lista a si mesmo
        result.append({
            "username":         uname,
            "name":             udata.get("name", uname),
            "role":             udata.get("role", "client"),
            "reset_pin_set":    _is_reset_pin_protected(udata),
            "reset_pin_custom": _user_has_custom_reset_pin(udata)
        })
    return jsonify({"success": True, "users": result})

@app.route("/api/admin/users", methods=["POST"])
@admin_required
def api_create_user():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Dados invalidos."}), 400
    username = data.get("username", "").strip().lower()
    password = data.get("password", "").strip()
    name     = data.get("name", "").strip()
    role     = data.get("role", "client").strip().lower()
    if not username or not password:
        return jsonify({"success": False, "message": "Usuario e senha sao obrigatorios."}), 400
    if not re.match(r"^[a-z0-9_\.]{3,30}$", username):
        return jsonify({"success": False, "message": "Usuario invalido. Use letras, numeros, _ ou . (3-30 chars)."}), 400
    if len(password) < 4:
        return jsonify({"success": False, "message": "Senha deve ter pelo menos 4 caracteres."}), 400
    if role not in ("admin", "client"):
        role = "client"
    users = load_users()
    if username in users:
        return jsonify({"success": False, "message": "Usuario ja existe."}), 409
    users[username] = {
        "password":   generate_password_hash(password),
        "role":       role,
        "name":       name or username,
        "created_by": session.get("username")  # registra qual admin criou
    }
    save_users(users)
    return jsonify({"success": True, "message": "Usuario criado com sucesso."})

@app.route("/api/admin/users/<username>", methods=["DELETE"])
@admin_required
def api_delete_user(username):
    username = username.strip().lower()
    current_admin = session.get("username")
    if username == current_admin:
        return jsonify({"success": False, "message": "Voce nao pode excluir sua propria conta."}), 400
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "message": "Usuario nao encontrado."}), 404
    # Apenas o admin que criou pode remover
    if users[username].get("created_by") != current_admin:
        return jsonify({"success": False, "message": "Sem permissao para remover este usuario."}), 403
    del users[username]
    save_users(users)
    return jsonify({"success": True, "message": "Usuario removido."})

@app.route("/api/admin/users/<username>/password", methods=["PUT"])
@admin_required
def api_change_password(username):
    username = username.strip().lower()
    current_admin = session.get("username")
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Dados invalidos."}), 400
    new_password = data.get("password", "").strip()
    if len(new_password) < 4:
        return jsonify({"success": False, "message": "Senha deve ter pelo menos 4 caracteres."}), 400
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "message": "Usuario nao encontrado."}), 404
    # Apenas o admin que criou pode alterar senha, ou o proprio usuario alterando a propria senha
    if users[username].get("created_by") != current_admin and username != current_admin:
        return jsonify({"success": False, "message": "Sem permissao para alterar senha deste usuario."}), 403
    users[username]["password"] = generate_password_hash(new_password)
    save_users(users)
    return jsonify({"success": True, "message": "Senha alterada com sucesso."})

# ─── ROTA PRINCIPAL DA APP ────────────────────────────────────────────────────


# ─── BLOQUEIO DE REDEFINIÇÃO DE SENHA POR PIN ─────────────────────────────────

@app.route("/api/admin/users/<username>/reset-pin", methods=["PUT"])
@admin_required
def api_set_reset_pin(username):
    """Define PIN personalizado ou restaura o PIN padrão da redefinição de senha."""
    username = username.strip().lower()
    current_admin = session.get("username")
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Dados invalidos."}), 400

    action = data.get("action", "set")
    users  = load_users()

    if username not in users:
        return jsonify({"success": False, "message": "Usuario nao encontrado."}), 404
    if users[username].get("created_by") != current_admin and username != current_admin:
        return jsonify({"success": False, "message": "Sem permissao."}), 403

    if action in ("remove", "restore_default", "reset_default"):
        users[username].pop("reset_pin", None)
        save_users(users)
        return jsonify({
            "success": True,
            "message": f"PIN restaurado para o padrão {DEFAULT_RESET_PIN}.",
            "default_pin_active": True
        })

    pin = str(data.get("pin", "")).strip()
    if not re.match(r"^\d{4}$", pin):
        return jsonify({"success": False, "message": "PIN deve ter exatamente 4 digitos numericos."}), 400

    users[username]["reset_pin"] = generate_password_hash(pin)
    save_users(users)
    return jsonify({
        "success": True,
        "message": "PIN de bloqueio definido com sucesso.",
        "custom_pin_active": True
    })


@app.route("/api/verify-reset-pin", methods=["POST"])
@login_required
def api_verify_reset_pin():
    """Cliente verifica o PIN antes de receber o link de redefinição de senha."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Dados invalidos."}), 400

    pin = str(data.get("pin", "")).strip()
    username = session.get("username")
    users = load_users()
    user  = users.get(username, {})

    pending_link = _peek_pending_reset_link(username)
    if not pending_link:
        return jsonify({"success": False, "message": "Nenhum link protegido pendente. Faça a busca novamente."}), 409

    if not re.match(r"^\d{4}$", pin):
        return jsonify({"success": False, "message": "PIN invalido."}), 400

    if not _verify_reset_pin_value(user, pin):
        return jsonify({"success": False, "message": "PIN incorreto."}), 403

    released_link = _pop_pending_reset_link(username)
    if not released_link:
        return jsonify({"success": False, "message": "Link expirado. Faça a busca novamente."}), 410

    return jsonify({
        "success": True,
        "unlocked": True,
        "link": released_link,
        "platform": "password-reset",
        "type": "link"
    })


@app.route("/api/check-reset-pin", methods=["GET"])
@login_required
def api_check_reset_pin():
    """Informa o estado do PIN da redefinição de senha do usuário logado."""
    username = session.get("username")
    users    = load_users()
    user     = users.get(username, {})
    return jsonify({
        "locked": _is_reset_pin_protected(user),
        "custom_pin": _user_has_custom_reset_pin(user),
        "pending": bool(_peek_pending_reset_link(username))
    })

@app.route("/api/get-code", methods=["POST"])
@login_required
def get_code():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Dados invalidos."}), 400
    user_email = data.get("email", "").strip().lower()
    platform   = data.get("platform", "").strip().lower()
    if not user_email:
        return jsonify({"success": False, "message": "Por favor, informe seu email."}), 400
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", user_email):
        return jsonify({"success": False, "message": "Email invalido."}), 400
    if platform not in PLATFORM_CONFIG:
        return jsonify({"success": False, "message": "Plataforma nao suportada."}), 400

    # ── Busca unificada: UMA conexão IMAP, batch-fetch de headers ──────────
    UNIFIED_MAP = {
        "netflix-all":   (["netflix", "netflix-login", "netflix-temp",
                           "netflix-residence", "password-reset"],
                          "Nenhum email Netflix encontrado para este endereço."),
        "disney-all":    (["disney", "disney-residence"],
                          "Nenhum email Disney+ encontrado para este endereço."),
        "globo-all":     (["bug-globo", "codigo-globo", "senha-globo"],
                          "Nenhum email Globo encontrado para este endereço."),
        "streaming-all": (["max", "prime-video"],
                          "Nenhum email Max ou Prime Video encontrado para este endereço."),
    }
    username = session.get("username")
    _clear_pending_reset_link(username)

    if platform in UNIFIED_MAP:
        subs, err_msg = UNIFIED_MAP[platform]
        code, link, matched_plat, error = search_code_unified(user_email, subs)
        if code:
            return jsonify({"success": True, "code": code, "platform": matched_plat, "type": "code"})
        elif link:
            if matched_plat == "password-reset":
                _set_pending_reset_link(username, link)
                return jsonify({
                    "success": True,
                    "platform": "password-reset",
                    "type": "pin_required",
                    "pin_required": True,
                    "message": "PIN necessario para liberar o link de redefinicao."
                })
            return jsonify({"success": True, "link": link, "platform": matched_plat, "type": "link"})
        else:
            return jsonify({"success": False, "message": error or err_msg})

    code, link, error = search_code(user_email, platform)
    if code:
        return jsonify({"success": True, "code": code, "platform": platform, "type": "code"})
    elif link:
        if platform == "password-reset":
            _set_pending_reset_link(username, link)
            return jsonify({
                "success": True,
                "platform": "password-reset",
                "type": "pin_required",
                "pin_required": True,
                "message": "PIN necessario para liberar o link de redefinicao."
            })
        return jsonify({"success": True, "link": link, "platform": platform, "type": "link"})
    else:
        return jsonify({"success": False, "message": error or "Nao encontrado."})

# ─── ROTAS LOJA (PÚBLICAS / CLIENTE) ──────────────────────────────────────────
@app.route("/api/loja/unlock", methods=["POST"])
def api_loja_unlock():
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", "")).strip()
    if password == LOJA_PASSWORD:
        session["loja_unlocked"] = True
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "Senha incorreta."}), 401

@app.route("/api/loja/produtos", methods=["GET"])
def api_loja_produtos():
    products = load_products()
    stock = load_stock()
    result = []
    for p in products:
        items = stock.get(p["id"], [])
        avail = sum(1 for i in items if not i.get("used"))
        result.append({
            "id": p["id"],
            "name": p["name"],
            "price": p.get("price", 0),
            "emoji": p.get("emoji", "🛍️"),
            "color": p.get("color", "#7e22ce"),
            "description": p.get("description", ""),
            "available": avail,
            "has_stock": avail > 0
        })
    return jsonify({"success": True, "products": result})

@app.route("/api/loja/checkout", methods=["POST"])
def api_loja_checkout():
    try:
        return _do_checkout()
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[checkout] erro fatal: {e}\n{tb}")
        return jsonify({"success": False, "message": f"Erro interno: {e}"}), 500

def _do_checkout():
    if not session.get("loja_unlocked"):
        return jsonify({"success": False, "message": "Acesso à loja bloqueado. Informe a senha."}), 403
    data = request.get_json(silent=True) or {}
    product_id = str(data.get("product_id", "")).strip()
    customer_name  = str(data.get("name", "")).strip()
    customer_email = str(data.get("email", "")).strip().lower()
    customer_phone = str(data.get("phone", "")).strip()

    if not product_id:
        return jsonify({"success": False, "message": "Produto inválido."}), 400
    if not customer_name or not customer_email:
        return jsonify({"success": False, "message": "Informe nome e email."}), 400

    products = load_products()
    product  = next((p for p in products if p["id"] == product_id), None)
    if not product:
        return jsonify({"success": False, "message": "Produto não encontrado."}), 404

    # Verifica estoque
    stock = load_stock()
    items = stock.get(product_id, [])
    avail = sum(1 for i in items if not i.get("used"))
    if avail <= 0:
        return jsonify({
            "success": False,
            "message": "Produto temporariamente sem estoque. Tente novamente em alguns minutos."
        }), 409

    # Cria pedido
    order_id  = f"PED-{int(time.time())}-{product_id[:6].upper()}"
    order = {
        "id": order_id,
        "product_id": product_id,
        "product_name": product["name"],
        "price": product.get("price", 0),
        "customer_name": customer_name,
        "customer_email": customer_email,
        "customer_phone": customer_phone,
        "status": "pending",
        "created_at": int(time.time()),
        "paid_at": None,
        "delivered_email": None,
        "delivered_password": None,
        "delivered_note": None,
        "pix_txid": None,
        "pix_qrcode": None,
        "pix_copia_cola": None,
    }

    # Tenta gerar Pix via Efi (se configurado) - protegido contra exception
    try:
        pix_data = efi_create_pix_charge(order)
    except Exception as e:
        print(f"[checkout] excecao em efi_create_pix_charge: {e}")
        pix_data = {"success": False, "message": f"Erro Efi: {e}"}

    if pix_data.get("success"):
        order["pix_txid"]      = pix_data.get("txid")
        order["pix_qrcode"]    = pix_data.get("qrcode_image")
        order["pix_copia_cola"]= pix_data.get("copia_cola")
        order["pix_expires_at"]= pix_data.get("expires_at")
    else:
        # Modo simulado quando Efi não configurado: gera Pix manual placeholder
        order["pix_txid"]      = order_id
        order["pix_qrcode"]    = None
        order["pix_copia_cola"]= None
        order["pix_warning"]   = pix_data.get("message", "Gateway Pix não configurado.")

    orders = load_orders()
    orders.append(order)
    save_orders(orders)

    return jsonify({
        "success": True,
        "order_id": order_id,
        "product_name": product["name"],
        "price": product.get("price", 0),
        "pix_qrcode": order.get("pix_qrcode"),
        "pix_copia_cola": order.get("pix_copia_cola"),
        "pix_warning": order.get("pix_warning")
    })

@app.route("/api/loja/order-status/<order_id>", methods=["GET"])
def api_loja_order_status(order_id):
    try:
        orders = load_orders()
        order  = next((o for o in orders if isinstance(o, dict) and o.get("id") == order_id), None)
        if not order:
            return jsonify({"success": False, "message": "Pedido não encontrado."}), 404

        debug_info = {}
        # Se ainda pendente e tem txid Efi, consulta status no Efi
        if order.get("status") == "pending" and order.get("pix_txid"):
            check = efi_check_pix_status(order["pix_txid"])
            debug_info["efi_check"] = {
                "status": check.get("status"),
                "paid": check.get("paid"),
                "reason": check.get("reason")
            }
            if check.get("paid"):
                order = mark_order_paid_and_deliver(order_id)

        return jsonify({
            "success": True,
            "order_id": order["id"],
            "status": order.get("status"),
            "product_name": order.get("product_name"),
            "delivered_email":    order.get("delivered_email"),
            "delivered_password": order.get("delivered_password"),
            "delivered_note":     order.get("delivered_note"),
            "debug": debug_info
        })
    except Exception as e:
        import traceback
        print(f"[order-status] erro: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "message": f"Erro: {e}"}), 500

@app.route("/api/loja/force-check/<order_id>", methods=["POST"])
def api_loja_force_check(order_id):
    """Força a verificação de pagamento de um pedido via Efi (útil quando o webhook falha)."""
    try:
        orders = load_orders()
        order  = next((o for o in orders if isinstance(o, dict) and o.get("id") == order_id), None)
        if not order:
            return jsonify({"success": False, "message": "Pedido não encontrado."}), 404
        if order.get("status") == "paid":
            return jsonify({"success": True, "already_paid": True, "order": order})
        if not order.get("pix_txid"):
            return jsonify({"success": False, "message": "Pedido sem txid."})
        check = efi_check_pix_status(order["pix_txid"])
        if check.get("paid"):
            order = mark_order_paid_and_deliver(order_id)
            return jsonify({"success": True, "paid": True, "order": order})
        return jsonify({
            "success": True,
            "paid": False,
            "efi_status": check.get("status"),
            "reason": check.get("reason"),
            "raw": check.get("raw")
        })
    except Exception as e:
        import traceback
        print(f"[force-check] erro: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "message": f"Erro: {e}"}), 500

# ─── EFI PIX HELPERS ────────────────────────────────────────────────────────────────
def efi_is_configured():
    return bool(EFI_CLIENT_ID and EFI_CLIENT_SECRET and EFI_PIX_KEY)

def efi_create_pix_charge(order):
    """Cria cobrança Pix imediata na Efi. Retorna dict com qrcode_image e copia_cola."""
    if not efi_is_configured():
        return {
            "success": False,
            "message": "Gateway Efi não configurado."
        }
    # Verifica se certificado existe
    if not os.path.exists(EFI_CERT_PATH):
        return {
            "success": False,
            "message": f"Certificado não encontrado: {EFI_CERT_PATH}"
        }
    try:
        try:
            from efipay import EfiPay
        except ImportError as e:
            return {
                "success": False,
                "message": f"SDK Efi não instalado: {e}"
            }

        options = {
            "client_id":     EFI_CLIENT_ID,
            "client_secret": EFI_CLIENT_SECRET,
            "certificate":   EFI_CERT_PATH,
            "sandbox":       EFI_SANDBOX
        }
        efi = EfiPay(options)

        # Devedor exige CPF/CNPJ na Efi — como não coletamos CPF do cliente, não enviamos devedor.
        # A Efi aceita cobrança Pix sem devedor (campo opcional).
        body = {
            "calendario": {"expiracao": 3600},
            "valor": {"original": f"{float(order['price']):.2f}"},
            "chave": EFI_PIX_KEY,
            "solicitacaoPagador": f"{order['product_name']} - {order['id']}"[:140]
        }
        resp = efi.pix_create_immediate_charge(body=body)
        print(f"[efi] resposta criar cobranca: {resp}")

        if not isinstance(resp, dict):
            return {"success": False, "message": f"Resposta inválida da Efi: {resp}"}

        if resp.get("nome") or resp.get("erro"):
            return {"success": False, "message": f"Efi rejeitou cobranca: {resp.get('mensagem') or resp.get('erro')}"}

        txid = resp.get("txid")
        loc  = (resp.get("loc") or {}).get("id")

        if not loc:
            return {"success": False, "message": f"Sem 'loc.id' na resposta Efi: {resp}"}

        try:
            qr = efi.pix_generate_qrcode(params={"id": loc})
        except Exception as e:
            return {"success": False, "message": f"Erro ao gerar QR Code: {e}"}

        return {
            "success": True,
            "txid": txid,
            "qrcode_image": qr.get("imagemQrcode"),
            "copia_cola":   qr.get("qrcode"),
            "expires_at":   int(time.time()) + 3600
        }
    except Exception as e:
        import traceback
        print(f"[efi] erro ao criar cobranca: {e}\n{traceback.format_exc()}")
        return {"success": False, "message": f"Erro Efi: {e}"}

def efi_check_pix_status(txid):
    """Consulta Efi e retorna {paid: bool, status: str, raw: dict}."""
    if not efi_is_configured() or not txid:
        return {"paid": False, "reason": "no_config_or_txid"}
    try:
        from efipay import EfiPay
        options = {
            "client_id":     EFI_CLIENT_ID,
            "client_secret": EFI_CLIENT_SECRET,
            "certificate":   EFI_CERT_PATH,
            "sandbox":       EFI_SANDBOX
        }
        efi  = EfiPay(options)
        resp = efi.pix_detail_charge(params={"txid": txid})
        if not isinstance(resp, dict):
            return {"paid": False, "reason": "resposta_nao_dict", "raw": str(resp)}
        status = (resp.get("status") or "").upper()
        # Considera paga se status concluida OU se ja tem array 'pix' com valor recebido
        is_paid = (status == "CONCLUIDA") or bool(resp.get("pix"))
        print(f"[efi] txid={txid} status={status} pix_array_len={len(resp.get('pix') or [])} paid={is_paid}")
        return {"paid": is_paid, "status": status, "raw": resp}
    except Exception as e:
        import traceback
        print(f"[efi] erro ao consultar txid {txid}: {e}\n{traceback.format_exc()}")
        return {"paid": False, "reason": str(e)}

def mark_order_paid_and_deliver(order_id):
    """Marca pedido como pago e entrega o próximo acesso do estoque."""
    orders = load_orders()
    # Filtra apenas dicts válidos antes de procurar
    order  = next((o for o in orders if isinstance(o, dict) and o.get("id") == order_id), None)
    if not order or order.get("status") != "pending":
        return order
    stock_item = get_next_stock_item(order.get("product_id"))
    order["status"]  = "paid"
    order["paid_at"] = int(time.time())
    if stock_item:
        order["delivered_email"]    = stock_item.get("email")
        order["delivered_password"] = stock_item.get("password")
        order["delivered_note"]     = stock_item.get("note")
        # marca o item como entregue ao cliente
        st = load_stock()
        for it in st.get(order.get("product_id"), []):
            if isinstance(it, dict) and it.get("id") == stock_item.get("id"):
                it["delivered_to"] = order.get("customer_email")
                it["order_id"]     = order_id
                break
        save_stock(st)
    else:
        order["delivered_note"] = "Pagamento confirmado. Aguarde - entrega manual."
    save_orders(orders)
    return order

@app.route("/api/loja/webhook/efi", methods=["POST", "GET"])
@app.route("/api/loja/webhook/efi/pix", methods=["POST", "GET"])
def api_loja_webhook_efi():
    """Webhook Efi confirmando pagamento Pix. Aceita /efi e /efi/pix (Efi adiciona /pix)."""
    # Aceita validacao GET da Efi (handshake)
    if request.method == "GET":
        return jsonify({"success": True}), 200
    token = (request.args.get("token", "") or
             request.args.get("hmac", "") or
             request.headers.get("X-Webhook-Token", ""))
    # Aceita sem token tambem para o handshake inicial da Efi
    if token and token != EFI_WEBHOOK_TOKEN:
        return jsonify({"success": False, "message": "Token invalido."}), 403
    data = request.get_json(silent=True) or {}
    pix_list = data.get("pix", [])
    for px in pix_list:
        txid = px.get("txid")
        if not txid:
            continue
        orders = load_orders()
        order  = next((o for o in orders if o.get("pix_txid") == txid), None)
        if order and order["status"] == "pending":
            mark_order_paid_and_deliver(order["id"])
    return jsonify({"success": True})

@app.route("/api/admin/loja/efi-setup-webhook", methods=["POST"])
@admin_required
def api_admin_efi_setup_webhook():
    """Cadastra automaticamente o webhook Pix da loja na Efi via API."""
    if not efi_is_configured():
        return jsonify({"success": False, "message": "Efi nao configurado."}), 400
    try:
        from efipay import EfiPay
        options = {
            "client_id":     EFI_CLIENT_ID,
            "client_secret": EFI_CLIENT_SECRET,
            "certificate":   EFI_CERT_PATH,
            "sandbox":       EFI_SANDBOX
        }
        efi = EfiPay(options)
        # Efi adiciona /pix no final da URL ao chamar o webhook
        # Por isso a URL base nao precisa ter /pix - mas precisa terminar sem barra
        webhook_url = f"https://mestre-codigos-production.up.railway.app/api/loja/webhook/efi?hmac={EFI_WEBHOOK_TOKEN}"
        params = {"chave": EFI_PIX_KEY}
        body   = {"webhookUrl": webhook_url}
        # PUT /v2/webhook/{chave} - cadastra ou substitui o webhook
        # x-skip-mtls-checking: pula validação de mTLS no cadastro
        resp = efi.pix_config_webhook(params=params, body=body, headers={"x-skip-mtls-checking": "true"})
        return jsonify({
            "success": True,
            "message": "Webhook cadastrado.",
            "webhook_url": webhook_url,
            "pix_key": EFI_PIX_KEY,
            "response": resp
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Erro ao cadastrar webhook: {e}"
        }), 500

@app.route("/api/admin/loja/efi-status-webhook", methods=["GET"])
@admin_required
def api_admin_efi_status_webhook():
    """Consulta se o webhook ja esta cadastrado na Efi."""
    if not efi_is_configured():
        return jsonify({"success": False, "message": "Efi nao configurado."}), 400
    try:
        from efipay import EfiPay
        options = {
            "client_id":     EFI_CLIENT_ID,
            "client_secret": EFI_CLIENT_SECRET,
            "certificate":   EFI_CERT_PATH,
            "sandbox":       EFI_SANDBOX
        }
        efi = EfiPay(options)
        params = {"chave": EFI_PIX_KEY}
        resp = efi.pix_detail_webhook(params=params)
        return jsonify({
            "success": True,
            "webhook": resp
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Sem webhook ou erro: {e}"
        })

# ─── ROTAS ADMIN LOJA ───────────────────────────────────────────────────────────────────────
@app.route("/api/admin/loja/produtos", methods=["GET"])
@admin_required
def api_admin_list_products():
    products = load_products()
    stock = load_stock()
    for p in products:
        items = stock.get(p["id"], [])
        p["available"] = sum(1 for i in items if not i.get("used"))
        p["total"]     = len(items)
        p["delivered"] = sum(1 for i in items if i.get("used"))
    return jsonify({"success": True, "products": products})

@app.route("/api/admin/loja/produtos/<product_id>", methods=["PUT"])
@admin_required
def api_admin_update_product(product_id):
    data = request.get_json(silent=True) or {}
    products = load_products()
    product = next((p for p in products if p["id"] == product_id), None)
    if not product:
        return jsonify({"success": False, "message": "Produto não encontrado."}), 404
    if "name" in data:
        product["name"] = str(data["name"]).strip()[:80] or product["name"]
    if "price" in data:
        try:
            product["price"] = float(str(data["price"]).replace(",", "."))
        except Exception:
            return jsonify({"success": False, "message": "Preço inválido."}), 400
    if "description" in data:
        product["description"] = str(data["description"]).strip()[:200]
    if "emoji" in data:
        product["emoji"] = str(data["emoji"]).strip()[:4]
    if "color" in data:
        product["color"] = str(data["color"]).strip()[:20]
    save_products(products)
    return jsonify({"success": True, "product": product})

@app.route("/api/admin/loja/estoque/<product_id>", methods=["GET"])
@admin_required
def api_admin_list_stock(product_id):
    stock = load_stock()
    items = stock.get(product_id, [])
    return jsonify({"success": True, "items": items})

@app.route("/api/admin/loja/estoque/<product_id>", methods=["POST"])
@admin_required
def api_admin_add_stock(product_id):
    data = request.get_json(silent=True) or {}
    email_acc = str(data.get("email", "")).strip()
    password  = str(data.get("password", "")).strip()
    note      = str(data.get("note", "")).strip()
    if not email_acc or not password:
        return jsonify({"success": False, "message": "Informe email e senha do acesso."}), 400
    products = load_products()
    if not any(p["id"] == product_id for p in products):
        return jsonify({"success": False, "message": "Produto não encontrado."}), 404
    stock = load_stock()
    items = stock.get(product_id, [])
    new_item = {
        "id":       f"acc-{int(time.time()*1000)}",
        "email":    email_acc,
        "password": password,
        "note":     note,
        "used":     False,
        "used_at":  None,
        "delivered_to": None,
        "order_id": None,
        "created_at": int(time.time())
    }
    items.append(new_item)
    stock[product_id] = items
    save_stock(stock)
    return jsonify({"success": True, "item": new_item})

@app.route("/api/admin/loja/estoque/<product_id>/<item_id>", methods=["DELETE"])
@admin_required
def api_admin_delete_stock(product_id, item_id):
    stock = load_stock()
    items = stock.get(product_id, [])
    new_items = [i for i in items if i.get("id") != item_id]
    if len(new_items) == len(items):
        return jsonify({"success": False, "message": "Item não encontrado."}), 404
    stock[product_id] = new_items
    save_stock(stock)
    return jsonify({"success": True})

@app.route("/api/admin/loja/estoque/<product_id>/<item_id>/reset", methods=["POST"])
@admin_required
def api_admin_reset_stock(product_id, item_id):
    """Marca acesso como disponível novamente (útil se cliente teve problema)."""
    stock = load_stock()
    items = stock.get(product_id, [])
    for it in items:
        if it.get("id") == item_id:
            it["used"] = False
            it["used_at"] = None
            it["delivered_to"] = None
            it["order_id"] = None
            save_stock(stock)
            return jsonify({"success": True})
    return jsonify({"success": False, "message": "Item não encontrado."}), 404

@app.route("/api/admin/loja/pedidos", methods=["GET"])
@admin_required
def api_admin_list_orders():
    try:
        orders = load_orders()
        # Filtra apenas dicts válidos (defesa contra dados antigos corrompidos)
        clean = [o for o in orders if isinstance(o, dict) and o.get("id")]
        clean_sorted = sorted(clean, key=lambda o: o.get("created_at", 0) or 0, reverse=True)
        return jsonify({"success": True, "orders": clean_sorted[:200]})
    except Exception as e:
        import traceback
        print(f"[admin/pedidos] erro: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "message": f"Erro: {e}", "orders": []})

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "Central dos Codigos",
        "loja_enabled": True,
        "efi_configured": efi_is_configured()
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(debug=False, host="0.0.0.0", port=port)
