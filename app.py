from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import imaplib
import smtplib
import email
from email.header import decode_header
import re
import os
import json
import unicodedata
import time
import threading
import hmac
import hashlib
from datetime import timedelta

app = Flask(__name__, static_folder='static')
CORS(app)

# Variável global para indicar se a requisição atual está bloqueada por licença
# (preenchida no before_request, lida pelo template)

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
AUTO_LOGIN_TTL = int(os.environ.get("AUTO_LOGIN_TTL", "600"))  # segundos

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


def _make_auto_login_sig(username, ts):
    payload = f"{str(username or '').strip().lower()}|{int(ts or 0)}"
    return hmac.new(app.secret_key.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()


def _set_session_for_user(username, user):
    session.permanent = True
    session["logged_in"] = True
    session["username"]  = username
    session["role"]      = user.get("role", "client")
    session["name"]      = user.get("name", username)


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


# ╔═══ AUTO-RESTAURAÇÃO DE USUÁRIOS (apenas JMP) ═══╗
# Se o JMP perder os usuários (redeploy sem volume), restaura automaticamente
# do painel Livre no primeiro acesso. Roda 1x por processo.
JMP_AUTO_RESTORE_SOURCE = os.environ.get(
    "JMP_AUTO_RESTORE_SOURCE",
    "https://livre.up.railway.app"
)
JMP_AUTO_RESTORE_PASS = os.environ.get("JMP_AUTO_RESTORE_PASS", "admin123")
_jmp_autorestore_done = False

def _jmp_auto_restore_users():
    """Restaura usuários do source se a base local estiver quase vazia.
    Só roda no host jmp.up.railway.app, 1x por processo."""
    global _jmp_autorestore_done
    if _jmp_autorestore_done:
        return
    try:
        host = (request.host or "").lower()
    except Exception:
        return
    if "jmp" not in host:
        return
    _jmp_autorestore_done = True  # marca antes de tentar (evita loop)
    try:
        users = load_users()
        # Se já tem usuários suficientes (>5), não precisa restaurar
        if len(users) > 5:
            print(f"[jmp-autorestore] {len(users)} usuarios presentes, OK")
            return
        print(f"[jmp-autorestore] apenas {len(users)} usuarios — restaurando de {JMP_AUTO_RESTORE_SOURCE}")
        import urllib.request as _ur, urllib.parse as _upp, http.cookiejar as _cj
        cookies = _cj.CookieJar()
        opener = _ur.build_opener(_ur.HTTPCookieProcessor(cookies))
        # 1) login no source
        login_data = json.dumps({"username": "admin", "password": JMP_AUTO_RESTORE_PASS}).encode()
        req = _ur.Request(f"{JMP_AUTO_RESTORE_SOURCE}/api/auth/login", data=login_data,
                          headers={"Content-Type": "application/json"})
        opener.open(req, timeout=20).read()
        # 2) pegar export de usuários (endpoint backup/export retorna data.users)
        req = _ur.Request(f"{JMP_AUTO_RESTORE_SOURCE}/api/admin/backup/export")
        resp = opener.open(req, timeout=25).read()
        data = json.loads(resp)
        src_users = (data.get("data") or {}).get("users") or {}
        if not src_users:
            print("[jmp-autorestore] source sem usuarios, abortando")
            return
        # 3) merge (mantém os locais, adiciona os do source)
        merged = dict(src_users)
        merged.update(users)  # locais têm prioridade
        save_users(merged)
        print(f"[jmp-autorestore] ✅ restaurado: {len(merged)} usuarios totais")
    except Exception as e:
        print(f"[jmp-autorestore] erro: {type(e).__name__}: {e}")

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

# 3ª caixa hard-coded (SiteGround mundial.log.br) — configurável via env
THIRD_IMAP_SERVER  = os.environ.get("THIRD_IMAP_SERVER") or os.environ.get("IMAP_SERVER_3", "mail.mundial.log.br")
THIRD_IMAP_PORT    = int(os.environ.get("THIRD_IMAP_PORT") or os.environ.get("IMAP_PORT_3") or 993)
THIRD_EMAIL_USER   = os.environ.get("THIRD_EMAIL_USER") or os.environ.get("EMAIL_USER_3", "codigo@mundial.log.br")
THIRD_EMAIL_PASS   = os.environ.get("THIRD_EMAIL_PASS") or os.environ.get("EMAIL_PASS_3", "Mestre13579@")

# ╔══ Caixa EXCLUSIVA do RIOS (SiteGround ggtv.net.br) ══╗
# Só é incluída quando o host é rios.up.railway.app
RIOS_IMAP_SERVER = os.environ.get("RIOS_IMAP_SERVER", "mail.ggtv.net.br")
RIOS_IMAP_PORT   = int(os.environ.get("RIOS_IMAP_PORT", 993))
RIOS_EMAIL_USER  = os.environ.get("RIOS_EMAIL_USER", "mestre@ggtv.net.br")
RIOS_EMAIL_PASS  = os.environ.get("RIOS_EMAIL_PASS", "Mestre13579@")

# ─── Caixas IMAP EXCLUSIVAS do ceara.up.railway.app ────────────────────────────
# Estas variaveis sao definidas APENAS no serviço 'ceara' no Railway.
# Em qualquer outro link (rios, mestre, lojario, jmp...) elas ficam vazias e
# sao IGNORADAS — ou seja, NADA muda nos outros sites.
CEARA_IMAP_SERVER_1 = os.environ.get("CEARA_IMAP_SERVER_1", "")
CEARA_IMAP_PORT_1   = int(os.environ.get("CEARA_IMAP_PORT_1", 993))
CEARA_EMAIL_USER_1  = os.environ.get("CEARA_EMAIL_USER_1", "")
CEARA_EMAIL_PASS_1  = os.environ.get("CEARA_EMAIL_PASS_1", "")
CEARA_IMAP_SERVER_2 = os.environ.get("CEARA_IMAP_SERVER_2", "")
CEARA_IMAP_PORT_2   = int(os.environ.get("CEARA_IMAP_PORT_2", 993))
CEARA_EMAIL_USER_2  = os.environ.get("CEARA_EMAIL_USER_2", "")
CEARA_EMAIL_PASS_2  = os.environ.get("CEARA_EMAIL_PASS_2", "")


def _is_rios_request():
    """True se o request atual vem de rios.up.railway.app"""
    try:
        return "rios" in (request.host or "").lower()
    except Exception:
        return False


def _is_ceara_request():
    """True se o request atual vem de ceara.up.railway.app"""
    try:
        return "ceara" in (request.host or "").lower()
    except Exception:
        return False


def get_imap_accounts():
    # ╔══ CEARA: usa SOMENTE as 2 caixas exclusivas (nao usa ggtv, nem principal) ══╗
    if _is_ceara_request():
        ceara_accs = []
        if CEARA_EMAIL_USER_1 and CEARA_EMAIL_PASS_1 and CEARA_IMAP_SERVER_1:
            ceara_accs.append({
                "name": "caixa-ceara-1",
                "server": CEARA_IMAP_SERVER_1,
                "port": CEARA_IMAP_PORT_1,
                "user": CEARA_EMAIL_USER_1,
                "password": CEARA_EMAIL_PASS_1,
            })
        if CEARA_EMAIL_USER_2 and CEARA_EMAIL_PASS_2 and CEARA_IMAP_SERVER_2:
            ceara_accs.append({
                "name": "caixa-ceara-2",
                "server": CEARA_IMAP_SERVER_2,
                "port": CEARA_IMAP_PORT_2,
                "user": CEARA_EMAIL_USER_2,
                "password": CEARA_EMAIL_PASS_2,
            })
        if ceara_accs:
            return ceara_accs
        # se nao houver caixas configuradas para ceara, retorna vazio (nao usa as outras)
        return []

    # ╔══ RIOS: usa SOMENTE a caixa ggtv.net.br ══╗
    if _is_rios_request() and RIOS_EMAIL_USER and RIOS_EMAIL_PASS:
        return [{
            "name": "caixa-rios-ggtv",
            "server": RIOS_IMAP_SERVER,
            "port": RIOS_IMAP_PORT,
            "user": RIOS_EMAIL_USER,
            "password": RIOS_EMAIL_PASS,
        }]

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
    # 3ª caixa (mundial.log.br) — SiteGround
    if THIRD_EMAIL_USER and THIRD_EMAIL_PASS:
        # Evita duplicar caso seja igual à principal/secundária
        already = any(a["user"].lower() == THIRD_EMAIL_USER.lower() and a["server"] == THIRD_IMAP_SERVER for a in accounts)
        if not already:
            accounts.append({
                "name": "caixa-mundial",
                "server": THIRD_IMAP_SERVER,
                "port": THIRD_IMAP_PORT,
                "user": THIRD_EMAIL_USER,
                "password": THIRD_EMAIL_PASS,
            })
    # Caixas extras genéricas (IMAP_SERVER_4, IMAP_SERVER_5, etc) — para expansão futura
    for i in range(4, 11):
        srv = os.environ.get(f"IMAP_SERVER_{i}")
        usr = os.environ.get(f"EMAIL_USER_{i}")
        pwd = os.environ.get(f"EMAIL_PASS_{i}")
        if srv and usr and pwd:
            prt = int(os.environ.get(f"IMAP_PORT_{i}", 993))
            accounts.append({
                "name": f"caixa-{i}",
                "server": srv,
                "port": prt,
                "user": usr,
                "password": pwd,
            })
    return accounts

# ─── LOJA / EFI PIX ─────────────────────────────────────────────────────────────
LOJA_PASSWORD       = os.environ.get("LOJA_PASSWORD", "1995")
PRODUCTS_FILE       = os.environ.get("PRODUCTS_FILE", os.path.join(_data_dir, "products.json"))
STOCK_FILE          = os.environ.get("STOCK_FILE", os.path.join(_data_dir, "stock.json"))
ORDERS_FILE         = os.environ.get("ORDERS_FILE", os.path.join(_data_dir, "orders.json"))
LICENSES_FILE       = os.environ.get("LICENSES_FILE", os.path.join(_data_dir, "licenses.json"))

# ╔══ PAINEL DE COBRANÇA (assinaturas por conta de streaming) — só no MESTRE ══╗
# Cada assinatura: { email, plataforma, cliente, telefone, valor, dur_days,
#   start_at, expires_at, status (active/expired), created_at, renew_pix_txid }
SUBSCRIPTIONS_FILE  = os.environ.get("SUBSCRIPTIONS_FILE", os.path.join(_data_dir, "subscriptions.json"))
SUB_DEFAULT_DAYS    = int(os.environ.get("SUB_DEFAULT_DAYS", "30"))
SUB_RENEW_VALUE     = float(os.environ.get("SUB_RENEW_VALUE", "35.00"))

def load_subscriptions():
    data = _read_json_file(SUBSCRIPTIONS_FILE, [])
    if not isinstance(data, list):
        data = []
    return data

def save_subscriptions(subs):
    if not isinstance(subs, list):
        subs = []
    return _write_json_file(SUBSCRIPTIONS_FILE, subs)

_CARLOSADM_CLEANUP_MARKER = os.path.join(_data_dir, ".cleanup_carlosadm_done")
_carlosadm_cleanup_done = False

def _cleanup_customer_purchases_once():
    global _carlosadm_cleanup_done
    if _carlosadm_cleanup_done:
        return
    try:
        if os.path.exists(_CARLOSADM_CLEANUP_MARKER):
            _carlosadm_cleanup_done = True
            return
        target = "carlosadm"
        orders = load_orders()
        new_orders = [o for o in orders if not (isinstance(o, dict) and str(o.get("customer_name", "")).strip().lower() == target)]
        removed_orders = len(orders) - len(new_orders)
        if removed_orders > 0:
            save_orders(new_orders)

        subs = load_subscriptions()
        new_subs = [s for s in subs if not (isinstance(s, dict) and str(s.get("cliente", "")).strip().lower() == target)]
        removed_subs = len(subs) - len(new_subs)
        if removed_subs > 0:
            save_subscriptions(new_subs)

        Path(_CARLOSADM_CLEANUP_MARKER).write_text(
            json.dumps({
                "customer_name": target,
                "removed_orders": removed_orders,
                "removed_subscriptions": removed_subs,
                "timestamp": int(time.time())
            }, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        print(f"[cleanup] carlosadm removido: pedidos={removed_orders} assinaturas={removed_subs}")
        _carlosadm_cleanup_done = True
    except Exception as e:
        print(f"[cleanup] erro ao remover compras de carlosadm: {e}")

def _sub_is_active(sub):
    """True se a assinatura está ativa (não vencida)."""
    if not isinstance(sub, dict):
        return False
    exp = sub.get("expires_at") or 0
    return int(time.time()) < exp

def _find_subscription(email):
    """Acha a assinatura de um email (case-insensitive). Retorna (sub, index) ou (None, -1)."""
    el = (email or "").strip().lower()
    subs = load_subscriptions()
    for i, s in enumerate(subs):
        if isinstance(s, dict) and (s.get("email", "") or "").lower() == el:
            return s, i
    return None, -1

# ╔══ LOJA 2 (nova loja vitrine, dados SEPARADOS, gerenciada pelo admin do rios) ══╗
PRODUCTS_FILE_2     = os.environ.get("PRODUCTS_FILE_2", os.path.join(_data_dir, "products_loja2.json"))
STOCK_FILE_2        = os.environ.get("STOCK_FILE_2", os.path.join(_data_dir, "stock_loja2.json"))
ORDERS_FILE_2       = os.environ.get("ORDERS_FILE_2", os.path.join(_data_dir, "orders_loja2.json"))
# Token que a nova loja usa para puxar dados do rios
LOJA2_PROXY_TOKEN   = os.environ.get("LOJA2_PROXY_TOKEN", "rios-loja2-token-2026")
# Caixa de emails recebidos via WEBHOOK do kuku.lu (apenas rios)
KUKU_WEBHOOK_FILE   = os.environ.get("KUKU_WEBHOOK_FILE", os.path.join(_data_dir, "kuku_webhook_mails.json"))
# Token simples p/ validar o webhook (configurável via env)
KUKU_WEBHOOK_TOKEN  = os.environ.get("KUKU_WEBHOOK_TOKEN", "rios2026kuku")
# Repasse do webhook por SMTP para uma caixa de email (deixa tudo cair lá, sem limite)
KUKU_FORWARD_TO     = os.environ.get("KUKU_FORWARD_TO", "mestre@ggtv.net.br")
KUKU_SMTP_SERVER    = os.environ.get("KUKU_SMTP_SERVER", "mail.ggtv.net.br")
KUKU_SMTP_PORT      = int(os.environ.get("KUKU_SMTP_PORT", 465))
KUKU_SMTP_USER      = os.environ.get("KUKU_SMTP_USER", "mestre@ggtv.net.br")
KUKU_SMTP_PASS      = os.environ.get("KUKU_SMTP_PASS", "Mestre13579@")
KUKU_FORWARD_ENABLE = os.environ.get("KUKU_FORWARD_ENABLE", "1") == "1"

# Domínio do painel MESTRE (só ele pode gerenciar licenças).
# Pode incluir múltiplos separados por vírgula via env MASTER_DOMAINS.
MASTER_DOMAINS = [d.strip().lower() for d in os.environ.get(
    "MASTER_DOMAINS",
    "mestre-codigos-production.up.railway.app,localhost,127.0.0.1"
).split(",") if d.strip()]

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

# Produtos padrão da LOJA 2 (começa vazia — o admin cadastra)
DEFAULT_PRODUCTS_2 = []

def load_products2():
    data = _read_json_file(PRODUCTS_FILE_2, None)
    if data is None:
        _write_json_file(PRODUCTS_FILE_2, DEFAULT_PRODUCTS_2)
        return list(DEFAULT_PRODUCTS_2)
    return data

def save_products2(products):
    return _write_json_file(PRODUCTS_FILE_2, products)

def load_stock2():
    data = _read_json_file(STOCK_FILE_2, {})
    if not isinstance(data, dict):
        data = {}
    return data

def save_stock2(stock):
    if not isinstance(stock, dict):
        stock = {}
    return _write_json_file(STOCK_FILE_2, stock)

def load_orders2():
    data = _read_json_file(ORDERS_FILE_2, [])
    if isinstance(data, dict):
        try:
            data = list(data.values())
        except Exception:
            data = []
    if not isinstance(data, list):
        data = []
    return data

def save_orders2(orders):
    if not isinstance(orders, list):
        orders = []
    return _write_json_file(ORDERS_FILE_2, orders)

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

# ─── LICENÇAS DE SITES FILHOS ───────────────────────────────────────────
def load_licenses():
    """Lista de licenças: cada uma com domain, admin_user, admin_pass, dur_days,
    start_at, expires_at, customer_name, plan_value, payment_method, payment_status, notes, active."""
    data = _read_json_file(LICENSES_FILE, [])
    if not isinstance(data, list):
        data = []
    return data

def save_licenses(licenses):
    if not isinstance(licenses, list):
        licenses = []
    return _write_json_file(LICENSES_FILE, licenses)

def _normalize_domain(domain):
    """Remove protocolo, www, barras finais, espaços e deixa minúsculo."""
    if not domain:
        return ""
    d = str(domain).strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = re.sub(r"^www\.", "", d)
    d = d.split("/")[0]
    return d.strip()

def get_current_host():
    """Pega o host da requisição atual (Host header), normalizado."""
    try:
        host = request.headers.get("X-Forwarded-Host") or request.host or ""
        return _normalize_domain(host)
    except Exception:
        return ""

def is_master_host():
    """True se a requisição atual está vindo do domínio MESTRE."""
    host = get_current_host()
    return any(host == _normalize_domain(d) for d in MASTER_DOMAINS)

# Lista hard-coded de domínios marcados como LOJA standalone.
# Adicione novos domínios aqui caso não tenham 'loja' no nome.
_LOJA_DOMAINS_HARDCODED = {
    "mestre-codigos-production-2638.up.railway.app",
}

def is_loja_host():
    """True se a requisição atual é do domínio da LOJA SEPARADA.
    Detecção em 4 níveis (qualquer um ativa a loja standalone):
    1) Variável de ambiente IS_LOJA=true (mais confiável — marca o serviço)
    2) Host configurado em LOJA_DOMAINS (lista separada por vírgula)
    3) Lista hard-coded _LOJA_DOMAINS_HARDCODED
    4) Padrão no nome do host: começa com 'loja', contém '-loja' ou 'loja-'
    """
    # Nível 1: variável IS_LOJA=true marca todo o serviço como loja
    if os.environ.get("IS_LOJA", "").strip().lower() in ("1", "true", "yes", "sim"):
        return True

    host = get_current_host()
    if not host:
        return False
    host = host.lower()

    # Nível 2: domínios explicitamente configurados como loja
    loja_domains_env = os.environ.get("LOJA_DOMAINS", "").strip()
    if loja_domains_env:
        loja_domains = [_normalize_domain(d) for d in loja_domains_env.split(",") if d.strip()]
        if host in loja_domains:
            return True

    # Nível 3: domínios hard-coded
    if host in _LOJA_DOMAINS_HARDCODED:
        return True

    # Nível 4: padrões típicos no nome do host
    return (
        host.startswith("loja") or
        "-loja." in host or
        "loja-" in host or
        ".loja." in host
    )

# URL pública do painel MESTRE (sites filhos consultam a licença aqui)
MASTER_API_URL    = os.environ.get(
    "MASTER_API_URL",
    "https://mestre-codigos-production.up.railway.app"
).rstrip("/")
MASTER_API_TOKEN  = os.environ.get("MASTER_API_TOKEN", "mestre-codigos-license-sync-2026")

# Renovação Pix — valor padrão quando o cliente paga direto na tela de bloqueio
LICENSE_RENEW_VALUE = float(os.environ.get("LICENSE_RENEW_VALUE", "100.00"))
LICENSE_RENEW_DAYS  = int(os.environ.get("LICENSE_RENEW_DAYS", "30"))

# Cache de licenças remotas (evita consultar a API a cada request)
_remote_license_cache = {}
_REMOTE_CACHE_TTL = 60  # segundos

def _fetch_remote_license(host):
    """Sites filhos consultam o MESTRE via HTTP para saber sua licença.
    Resultado fica em cache por 60s para não sobrecarregar o mestre."""
    if not host or not MASTER_API_URL:
        return None
    now = int(time.time())
    cached = _remote_license_cache.get(host)
    if cached and (now - cached["ts"] < _REMOTE_CACHE_TTL):
        return cached["lic"]
    try:
        import urllib.request, urllib.parse, urllib.error
        url = f"{MASTER_API_URL}/api/internal/license-by-domain?domain={urllib.parse.quote(host)}&token={urllib.parse.quote(MASTER_API_TOKEN)}"
        req = urllib.request.Request(url, headers={"User-Agent": "mestre-codigos-license-sync/1.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            import json as _json
            data = _json.loads(resp.read().decode("utf-8", errors="ignore"))
        if data.get("success") and data.get("license"):
            lic = data["license"]
        else:
            lic = None
        _remote_license_cache[host] = {"ts": now, "lic": lic}
        return lic
    except Exception as e:
        # Em caso de falha, considera o último valor em cache mesmo expirado
        if cached:
            return cached["lic"]
        print(f"[license_remote] falha ao consultar {host}: {e}")
        return None

def get_license_for_host(host=None):
    """Retorna a licença do domínio (ou None se não existir).
    No painel MESTRE: lê localmente do JSON.
    Em sites filhos: consulta a API do mestre via HTTP (com cache de 60s)."""
    h = _normalize_domain(host or get_current_host())
    if not h:
        return None
    # Se EU sou o painel mestre, leio localmente
    if is_master_host():
        for lic in load_licenses():
            if not isinstance(lic, dict):
                continue
            if _normalize_domain(lic.get("domain", "")) == h:
                return lic
        return None
    # Sites filhos consultam o mestre via HTTP
    return _fetch_remote_license(h)

def license_status(lic):
    """Retorna 'no_license', 'active', 'expired', ou 'disabled'."""
    if not lic:
        return "no_license"
    if not lic.get("active", True):
        return "disabled"
    now = int(time.time())
    exp = int(lic.get("expires_at") or 0)
    if exp and now > exp:
        return "expired"
    return "active"

def days_remaining(lic):
    if not lic or not lic.get("expires_at"):
        return 0
    secs = int(lic["expires_at"]) - int(time.time())
    return max(0, int(secs // 86400))

def compute_expiration(start_at, duration_days):
    try:
        return int(start_at) + int(duration_days) * 86400
    except Exception:
        return int(start_at) + 30 * 86400

def should_block_site():
    """Decide se a requisição deve ser bloqueada por licença expirada.
    Painel MESTRE nunca é bloqueado. Sites filhos são bloqueados quando
    sua licença estiver expirada, desativada ou não existir."""
    if is_master_host():
        return False, None
    lic = get_license_for_host()
    status = license_status(lic)
    if status == "active":
        return False, lic
    return True, lic

PLATFORM_CONFIG = {
    # ── NETFLIX: código de acesso (PT/EN/ES) ──────────────────────────────────
    "netflix": {
        "from_keyword": "netflix.com",
        "subject_keywords": [
            # Português
            "netflix: seu código de acesso",
            "digo de acesso",
            "código de acesso netflix",
            "este código vence em 15 minutos",
            "código vence em 15 minutos",
            "este codigo vence em 15 minutos",
            "o código expira após 15 minutos",
            "o codigo expira apos 15 minutos",
            "código expira após 15 minutos",
            "codigo expira apos 15 minutos",
            "expira após 15 minutos",
            "expira apos 15 minutos",
            "verifique com este código",
            "verifique com este codigo",
            "código de verificação",
            "codigo de verificacao",
            # Inglês
            "your netflix access code",
            "netflix access code",
            "netflix verification code",
            "your netflix verification code",
            "your one-time passcode for netflix",
            "netflix one-time passcode",
            "this code expires in 15 minutes",
            "code expires in 15 minutes",
            "verification code",
            # Espanhol
            "tu código de acceso netflix",
            "código de acceso netflix",
            "codigo de acceso netflix",
            "tu código de verificación netflix",
            "codigo de verificacion netflix",
            "este código vence en 15 minutos",
            "codigo vence en 15 minutos",
            "código vence en 15 minutos",
            "este codigo vence en 15 minutos",
            "código de verificación",
            "codigo de verificacion"
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
            "este código vence em 15 minutos",
            "código vence em 15 minutos",
            "este codigo vence em 15 minutos",
            "o código expira após 15 minutos",
            "o codigo expira apos 15 minutos",
            "código expira após 15 minutos",
            "codigo expira apos 15 minutos",
            "expira após 15 minutos",
            "expira apos 15 minutos",
            "verifique com este código",
            "verifique com este codigo",
            "código de verificação",
            "codigo de verificacao",
            # Inglês
            "code to sign in",
            "sign in code",
            "sign-in code",
            "login code",
            "your netflix sign in code",
            "netflix sign-in code",
            "this code expires in 15 minutes",
            "code expires in 15 minutes",
            "verification code",
            # Espanhol
            "código de inicio de sesión",
            "codigo de inicio de sesion",
            "tu código para iniciar sesión",
            "codigo para iniciar sesion",
            "inicia sesión en netflix",
            "código de acceso para iniciar",
            "este código vence en 15 minutos",
            "codigo vence en 15 minutos",
            "código vence en 15 minutos",
            "este codigo vence en 15 minutos",
            "código de verificación",
            "codigo de verificacion"
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
    user_lower = user_lower.strip()

    # 1. Verifica no corpo HTML já extraído
    if user_lower in html_body.lower():
        return True

    # 1.5 Verifica sem quoted-printable (=40 vira @ em emails encaminhados)
    try:
        import quopri
        decoded_html = quopri.decodestring(html_body.encode("utf-8", errors="ignore")).decode("utf-8", errors="ignore").lower()
        if user_lower in decoded_html:
            return True
        # Tambem testa removendo todas as tags HTML (caso o email esteja entre <a> ou outras tags)
        plain_from_html = re.sub(r"<[^>]+>", " ", decoded_html)
        plain_from_html = re.sub(r"\s+", " ", plain_from_html).strip()
        if user_lower in plain_from_html:
            return True
        # Tambem testa sem hifens/pontos que podem estar codificados (=2E -> .)
        unescaped = (decoded_html.replace("=2e", ".").replace("=2E", ".")
                                .replace("=40", "@").replace("=3d", "="))
        if user_lower in unescaped:
            return True
    except Exception:
        pass

    # 2. Verifica nos headers principais
    # INCLUI From: porque em emails encaminhados (Fw:) o destinatario original
    # pode aparecer como remetente, ou o cliente identifica pelo endereco que
    # encaminhou. Tambem inclui Sender, Return-Path e Received.
    for header in ["To", "Delivered-To", "X-Original-To", "X-Forwarded-To",
                   "Cc", "Bcc", "Reply-To", "From", "Sender",
                   "Return-Path", "X-Original-From", "X-Sender"]:
        if user_lower in decode_str(msg.get(header, "")).lower():
            return True

    # 2.5 Verifica em TODOS os headers Received (caminho percorrido)
    try:
        all_received = msg.get_all("Received") or []
        for rec in all_received:
            if user_lower in str(rec).lower():
                return True
    except Exception:
        pass

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
                            text = payload.decode(charset, errors="ignore").lower()
                            if user_lower in text:
                                return True
                            # Tambem testa removendo tags HTML e quoted-printable
                            plain = re.sub(r"<[^>]+>", " ", text)
                            plain = re.sub(r"\s+", " ", plain).strip()
                            if user_lower in plain:
                                return True
                            try:
                                import quopri
                                qp_decoded = quopri.decodestring(text.encode("utf-8", errors="ignore")).decode("utf-8", errors="ignore").lower()
                                if user_lower in qp_decoded:
                                    return True
                                qp_plain = re.sub(r"<[^>]+>", " ", qp_decoded)
                                qp_plain = re.sub(r"\s+", " ", qp_plain).strip()
                                if user_lower in qp_plain:
                                    return True
                            except Exception:
                                pass
                        except Exception:
                            pass
        else:
            # Email não multipart — tambem decodifica payload simples
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                try:
                    text = payload.decode(charset, errors="ignore").lower()
                    if user_lower in text:
                        return True
                    plain = re.sub(r"<[^>]+>", " ", text)
                    plain = re.sub(r"\s+", " ", plain).strip()
                    if user_lower in plain:
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
        # Tambem aplica quoted-printable nos bytes brutos
        try:
            import quopri
            raw_qp = quopri.decodestring(msg.as_bytes()).decode("utf-8", errors="ignore").lower()
            if user_lower in raw_qp:
                return True
        except Exception:
            pass
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


# Cache de conexões IMAP (reusa por 60s para evitar login repetido a cada busca)
_imap_conn_cache = {}
_IMAP_CONN_TTL = 60  # segundos
_imap_lock = __import__("threading").Lock()

def connect_imap(account_cfg=None):
    """Conecta ao IMAP com cache de conexão (reusa por 60s).
    Cada login no Gmail leva 1.5-3s; o cache evita isso em buscas consecutivas.
    """
    account_cfg = account_cfg or get_imap_accounts()[0]
    key = _account_cache_key(account_cfg)
    now = _dt.utcnow().timestamp()

    with _imap_lock:
        cached = _imap_conn_cache.get(key)
        if cached:
            mail, ts = cached
            # Conexão ainda válida? Testa com NOOP
            if now - ts < _IMAP_CONN_TTL:
                try:
                    typ, _ = mail.noop()
                    if typ == "OK":
                        return mail
                except Exception:
                    pass
            # Conexão expirada ou quebrada — descarta
            try: mail.logout()
            except Exception: pass
            _imap_conn_cache.pop(key, None)

        # Cria nova conexão (timeout reduzido de 20s para 12s)
        mail = imaplib.IMAP4_SSL(account_cfg["server"], int(account_cfg["port"]), timeout=12)
        try:
            mail.sock.settimeout(12)
        except Exception:
            pass
        mail.login(account_cfg["user"], account_cfg["password"])
        _imap_conn_cache[key] = (mail, now)
        return mail

def _release_imap(account_cfg, mail):
    """Não faz logout — deixa a conexão no cache para reuso."""
    key = _account_cache_key(account_cfg)
    with _imap_lock:
        # Atualiza timestamp para indicar uso recente
        if key in _imap_conn_cache:
            _imap_conn_cache[key] = (mail, _dt.utcnow().timestamp())
        else:
            _imap_conn_cache[key] = (mail, _dt.utcnow().timestamp())


def _safe_logout(mail):
    """NOVO: Não faz logout — mantém conexão no cache para reuso rápido.
    A conexão será descartada automaticamente quando expirar (60s) ou quebrar.
    Em caso de erro real, use _force_logout(mail).
    """
    # Mantém conexão no cache; o próximo connect_imap() reusa
    pass

def _force_logout(mail):
    """Força o logout (usar apenas em casos de erro irrecuperável)."""
    if mail is None:
        return
    try:
        mail.logout()
    except Exception:
        pass
    # Remove do cache se estiver lá
    with _imap_lock:
        for k, v in list(_imap_conn_cache.items()):
            if v[0] is mail:
                _imap_conn_cache.pop(k, None)
                break

def _get_spam_boxes(mail, account_cfg=None):
    """Descobre caixas de spam/lixo eletrônico em qualquer hierarquia.
    Detecta pastas com nomes como:
      - Spam / SPAM / spam
      - Junk / JUNK / Junk Email
      - INBOX.Spam / INBOX.Junk / INBOX.spam
      - [Gmail]/Spam / [Gmail]/Lixo Eletrônico
      - Lixo Eletrônico / Lixeira (Português)
      - Correo no deseado (Espanhol)
      - Bulk Mail / Bulk
    Também usa flags IMAP (\Junk, \Spam) para detecção automática.
    """
    account_cfg = account_cfg or get_imap_accounts()[0]
    cache_key = _account_cache_key(account_cfg)
    if cache_key in _spam_boxes_cache:
        return _spam_boxes_cache[cache_key]

    # Palavras-chave que indicam pasta de spam/lixo (busca por substância, case-insensitive)
    SPAM_KEYWORDS = [
        "spam",
        "junk",
        "lixo eletrônico",
        "lixo eletronico",
        "lixeira",
        "correo no deseado",
        "bulk mail",
        "bulk",
        "unwanted",
    ]
    # Palavras que indicam pastas que devem ser EXCLUÍDAS (sent, drafts, archive)
    EXCLUDE_KEYWORDS = [
        "sent", "enviad", "draft", "rascunh", "archive", "arquiv",
    ]

    try:
        status_list, mailbox_list = mail.list()
        result = []
        if status_list == "OK":
            for mb in mailbox_list:
                try:
                    mb_str = mb.decode("utf-8") if isinstance(mb, bytes) else str(mb)
                    # Extrai flags entre parênteses no início (\\HasNoChildren \\Junk)
                    flags_part = ""
                    end_flags = -1
                    if mb_str.startswith("("):
                        end_flags = mb_str.find(")")
                        if end_flags > 0:
                            flags_part = mb_str[1:end_flags].lower()
                    # Extrai o nome da pasta:
                    # Formato típico: (\HasNoChildren \Junk) "." INBOX.Junk
                    # ou:              (\HasNoChildren) "/" "[Gmail]/Spam"
                    # O nome da pasta é o ÚLTIMO token após o delimitador
                    after_flags = mb_str[end_flags+1:].strip() if end_flags > 0 else mb_str.strip()
                    # Tenta extrair pelo padrão: <delimiter>SPACE<name>
                    box_name = ""
                    if after_flags.startswith('"'):
                        # delimitador entre aspas, depois um espaço, depois o nome
                        end_delim = after_flags.find('"', 1)
                        if end_delim > 0:
                            rest = after_flags[end_delim+1:].strip()
                            # O nome pode estar entre aspas ou sem aspas
                            if rest.startswith('"') and rest.endswith('"'):
                                box_name = rest[1:-1].strip()
                            else:
                                box_name = rest.strip().strip('"')
                    if not box_name:
                        # Fallback: pega último token
                        toks = after_flags.split()
                        if toks:
                            box_name = toks[-1].strip().strip('"')
                    if not box_name:
                        continue

                    box_lower = box_name.lower()

                    # Detecção por FLAG IMAP \\Junk (mais confiável)
                    if "\\junk" in flags_part:
                        if box_name not in result:
                            result.append(box_name)
                        continue

                    # Pula pastas excluídas (sent, drafts, archive)
                    if any(ex in box_lower for ex in EXCLUDE_KEYWORDS):
                        continue

                    # Detecção por nome contendo palavra-chave de spam
                    if any(kw in box_lower for kw in SPAM_KEYWORDS):
                        if box_name not in result:
                            result.append(box_name)
                except Exception:
                    continue
        _spam_boxes_cache[cache_key] = result
        try:
            print(f"[spam-boxes] {account_cfg.get('name','?')}: detectadas {len(result)} pastas: {result}")
        except Exception:
            pass
    except Exception as e:
        try: print(f"[spam-boxes] erro: {e}")
        except Exception: pass
        _spam_boxes_cache[cache_key] = []
    return _spam_boxes_cache[cache_key]

FWD_PREFIXES_SEARCH = ["ENC:", "Enc:", "FW:", "Fw:", "Fwd:", "FWD:", "RE:", "Re:"]

def _batch_search_mailbox(mail, mailbox, from_kw, platform_configs, seen_ids,
                           use_date_filter=True, since_date=None,
                           max_age_minutes=None, max_emails=100):
    """
    Busca emails de uma caixa usando BATCH FETCH de headers.
    Filtra por múltiplas plataformas de uma vez.
    Retorna lista de (mailbox, platform_key, email_id) do MAIS RECENTE para o mais antigo.

    max_age_minutes: se definido, descarta emails cuja data > X minutos atras (otimizacao ceara)
    max_emails: quantos emails fazer batch fetch (padrao 100)
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
            # max_emails mais recentes
            recent_ids = all_ids[-max_emails:]
            # cutoff para filtro fino por minutos
            cutoff_ts = None
            if max_age_minutes:
                cutoff_ts = _dt.utcnow().timestamp() - (max_age_minutes * 60)

            # ── BATCH FETCH de todos os headers em um único round-trip ──────
            id_str = b",".join(recent_ids)
            # se filtro de minutos, busca tambem Date para checar idade
            fetch_fields = "(BODY[HEADER.FIELDS (SUBJECT DATE)])" if cutoff_ts else "(BODY[HEADER.FIELDS (SUBJECT)])"
            st_b, data_b = mail.fetch(id_str, fetch_fields)
            if st_b == "OK":
                id_idx = 0
                for item in data_b:
                    if isinstance(item, tuple):
                        if id_idx >= len(recent_ids):
                            break
                        eid = recent_ids[id_idx]
                        hdr  = email.message_from_bytes(item[1])
                        subj = decode_str(hdr.get("Subject", ""))
                        # filtro fino por idade (minutos) usando o header Date
                        if cutoff_ts:
                            try:
                                from email.utils import parsedate_to_datetime
                                msg_dt = parsedate_to_datetime(hdr.get("Date", ""))
                                if msg_dt:
                                    msg_ts = msg_dt.timestamp()
                                    if msg_ts < cutoff_ts:
                                        id_idx += 1
                                        continue
                            except Exception:
                                pass
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


def _search_kuku_webhook(user_email, platform):
    """Procura código/link nos emails recebidos via webhook do kuku.lu.
    Retorna (code, link, matched_platform). Usado apenas no rios.
    """
    try:
        mails = _read_json_safe(KUKU_WEBHOOK_FILE, [])
    except Exception:
        return (None, None, None)
    if not mails:
        return (None, None, None)

    ulow = (user_email or "").strip().lower()

    # Determina lista de plataformas a verificar
    UNIFIED = {
        "netflix-all": ["netflix", "netflix-login", "netflix-temp", "netflix-residence", "password-reset"],
        "disney-all":  ["disney", "disney-residence"],
        "globo-all":   ["bug-globo", "codigo-globo", "senha-globo"],
        "streaming-all": ["max", "prime-video"],
    }
    plats = UNIFIED.get(platform, [platform])

    # Percorre emails do mais recente p/ o mais antigo
    for mail in reversed(mails):
        to_addr = (mail.get("to") or "").lower()
        # Filtro destinatário (precisa bater)
        if ulow and ulow not in to_addr and to_addr not in ulow:
            # também verifica se o email aparece no corpo (forward pode mudar o To)
            if ulow not in (mail.get("body") or "").lower():
                continue
        subject = (mail.get("subject") or "")
        body    = (mail.get("body") or "")
        frm     = (mail.get("from") or "")
        combined = f"{subject}\n{frm}\n{body}"
        clow = combined.lower()

        for plat in plats:
            pcfg = PLATFORM_CONFIG.get(plat, {})
            if not pcfg:
                continue
            from_kw = (pcfg.get("from_keyword") or "").lower()
            subj_kws = [k.lower() for k in pcfg.get("subject_keywords", [])]
            neg_kws  = [k.lower() for k in pcfg.get("negative_keywords", [])]
            # 1) remetente
            if from_kw and from_kw not in clow:
                continue
            # 2) negative
            if any(nk in clow for nk in neg_kws):
                continue
            # 3) subject keyword (pelo menos 1, se configurado)
            if subj_kws and not any(sk in clow for sk in subj_kws):
                continue
            # match! extrai código ou link
            if pcfg.get("type") == "link" or plat in ("netflix-temp", "netflix-residence", "password-reset", "disney-residence"):
                link_pat = pcfg.get("link_pattern")
                if link_pat:
                    m = re.search(link_pat, combined)
                    if m:
                        return (None, m.group(0), plat)
                # fallback: qualquer link netflix
                m = re.search(r'https?://[^\s"\'<>]+', combined)
                if m:
                    return (None, m.group(0), plat)
            code = extract_code_from_html(combined)
            if code:
                return (code, None, plat)
    return (None, None, None)


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

    user_email = str(user_email or "").strip().lower()
    email_domain = user_email.split("@", 1)[1] if "@" in user_email else ""
    hotmail_domains = {
        "hotmail.com", "hotmail.com.br", "outlook.com", "outlook.com.br",
        "live.com", "live.com.br", "msn.com"
    }
    is_hotmail_family = email_domain in hotmail_domains

    accounts = get_imap_accounts()
    if not accounts:
        if _is_ceara_request():
            return None, None, None, "Nenhuma caixa IMAP configurada no Ceará. Configure CEARA_IMAP_SERVER_1/2, CEARA_EMAIL_USER_1/2 e CEARA_EMAIL_PASS_1/2 no Railway."
        return None, None, None, "Nenhuma caixa de email configurada."

    last_error = None

    for account_cfg in accounts:
        mail = None
        try:
            mail = connect_imap(account_cfg)
            today     = _dt.utcnow().strftime("%d-%b-%Y")
            since_2d  = (_dt.utcnow() - _td(days=2)).strftime("%d-%b-%Y")
            since_7d  = (_dt.utcnow() - _td(days=7)).strftime("%d-%b-%Y")

            # Hotmail/Outlook costuma atrasar ou cair no lixo eletrônico.
            # No Ceará, ampliamos a busca para reduzir falhas de consulta.
            if _is_ceara_request() or is_hotmail_family:
                global_window_min = int(os.environ.get("HOTMAIL_TIME_WINDOW_MIN", "180"))
                global_max_emails = int(os.environ.get("HOTMAIL_MAX_EMAILS", "120"))
                primary_since = since_2d
                secondary_since = since_7d
                spam_boxes = _get_spam_boxes(mail, account_cfg)
            else:
                global_window_min = int(os.environ.get("GLOBAL_TIME_WINDOW_MIN", "15"))
                global_max_emails = int(os.environ.get("GLOBAL_MAX_EMAILS", "30"))
                primary_since = today
                secondary_since = since_2d
                spam_boxes = []

            seen_ids = set()
            mailboxes_primary = ["INBOX"] + [b for b in spam_boxes if b and b.upper() != "INBOX"]

            for sender, plat_configs in by_sender.items():
                found = False

                # Passagem principal: INBOX + Junk/Spam quando aplicável
                for mailbox in mailboxes_primary:
                    matched = _batch_search_mailbox(
                        mail, mailbox, sender, plat_configs, seen_ids,
                        use_date_filter=True, since_date=primary_since,
                        max_age_minutes=global_window_min,
                        max_emails=global_max_emails)

                    for mb, plat_key, eid in matched:
                        code, link = _fetch_and_extract(mail, mb, eid, plat_key, user_email)
                        if code or link:
                            _safe_logout(mail)
                            return code, link, plat_key, None
                        found = found or bool(matched)

                # Fallback extra para Ceará/Hotmail: busca maior e sem filtro de minutos
                if (_is_ceara_request() or is_hotmail_family) and not found:
                    fallback_boxes = mailboxes_primary if mailboxes_primary else ["INBOX"]
                    for mailbox in fallback_boxes:
                        matched = _batch_search_mailbox(
                            mail, mailbox, sender, plat_configs, seen_ids,
                            use_date_filter=True, since_date=secondary_since,
                            max_age_minutes=None,
                            max_emails=max(global_max_emails, 180))

                        for mb, plat_key, eid in matched:
                            code, link = _fetch_and_extract(mail, mb, eid, plat_key, user_email)
                            if code or link:
                                _safe_logout(mail)
                                return code, link, plat_key, None

            _safe_logout(mail)
        except imaplib.IMAP4.error as e:
            last_error = f"[{account_cfg.get('name')}] Erro de conexao com servidor de email: {e}"
            _force_logout(mail)
            continue
        except Exception as e:
            _force_logout(mail)
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


def _admin_can_see_assignment(assigned_user):
    assigned_user = str(assigned_user or "").strip().lower()
    current_admin = str(session.get("username") or "").strip().lower()
    if not assigned_user:
        return True
    if not current_admin:
        return False
    if current_admin == "admin":
        return True
    if assigned_user == current_admin:
        return True
    try:
        users = load_users()
        target = users.get(assigned_user) or {}
        created_by = str(target.get("created_by") or "").strip().lower()
        return created_by == current_admin
    except Exception:
        return False


def _get_user_compras_reset_at(username):
    username = str(username or "").strip().lower()
    if not username:
        return 0
    try:
        users = load_users()
        u = users.get(username) or {}
        return int(u.get("compras_reset_at") or 0)
    except Exception:
        return 0


def _ensure_carlosadm_compras_reset_once():
    try:
        users = load_users()
        u = users.get("carlosadm")
        if not isinstance(u, dict):
            return
        if u.get("compras_reset_applied"):
            return
        now = int(time.time())
        u["compras_reset_at"] = now
        u["compras_reset_applied"] = True
        users["carlosadm"] = u
        save_users(users)
        print(f"[cleanup] compras do usuario carlosadm resetadas em {now}")
    except Exception as e:
        print(f"[cleanup] erro ao resetar compras de carlosadm: {e}")

# ─── ROTAS DE PAGINAS ──────────────────────────────────────────────────────────

# ─── MIDDLEWARE DE LICENÇA ──────────────────────────────────────────────────────
# Bloqueia automaticamente sites filhos com licença expirada/desativada/inexistente.
# O domínio MESTRE nunca é bloqueado.
_LICENSE_BYPASS_PATHS = (
    "/api/health",
    "/api/site-mode",
    "/api/keepalive",
    "/api/license/status",
    "/api/internal/license-by-domain",
    "/api/internal/loja/",
    "/api/license/renew/",
    "/api/internal/renew-pix",
    "/api/internal/renew-status",
    "/api/internal/renew-webhook",
    "/licenca-expirada",
    "/static/",
    "/favicon.ico",
)

@app.before_request
def _jmp_autorestore_hook():
    """Dispara auto-restauração de usuários no JMP (1x por processo)."""
    if not _jmp_autorestore_done:
        try:
            _jmp_auto_restore_users()
        except Exception:
            pass
    try:
        _cleanup_customer_purchases_once()
    except Exception:
        pass
    return None

@app.before_request
def _license_gate():
    try:
        path = request.path or "/"
        if any(path == p or path.startswith(p) for p in _LICENSE_BYPASS_PATHS):
            return None
        # Painel mestre nunca é bloqueado
        if is_master_host():
            return None
        # Loja separada nunca é bloqueada (não depende de licença)
        if is_loja_host():
            return None
        block, lic = should_block_site()
        if not block:
            return None
        # Bloqueado: API responde JSON, páginas respondem HTML de licença expirada
        if path.startswith("/api/"):
            return jsonify({
                "success": False,
                "message": "Site bloqueado: licença expirada ou inexistente. Contate o administrador.",
                "license_blocked": True,
                "redirect": "/licenca-expirada"
            }), 402
        # Limpa sessão para impedir uso
        try:
            session.clear()
        except Exception:
            pass
        return redirect("/licenca-expirada")
    except Exception as e:
        print(f"[license_gate] erro: {e}")
        return None

@app.route("/licenca-expirada")
def license_expired_page():
    """Tela exibida quando o site filho está bloqueado por licença.
    Inclui opção de renovação via Pix automático (R$ 100 / 30 dias por padrão)."""
    if is_master_host():
        return redirect("/login")
    lic = get_license_for_host()
    status = license_status(lic)
    domain = get_current_host()
    customer = (lic or {}).get("customer_name", "")
    status_label = {
        "no_license": "Não cadastrado",
        "expired": "Licença expirada",
        "disabled": "Licença desativada",
        "active": "Ativa"
    }.get(status, status)
    renew_value = float((lic or {}).get("plan_value") or LICENSE_RENEW_VALUE)
    renew_days  = LICENSE_RENEW_DAYS
    can_renew = bool(lic)  # só mostra Pix se tem licença cadastrada
    html = """<!DOCTYPE html>
<html lang="pt-BR"><head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Acesso expirado</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
     background:radial-gradient(circle at top, #200015, #0a0010 70%);color:#fef3c7;
     font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:20px;}
.card{max-width:480px;width:100%;background:linear-gradient(135deg,#1a0010,#2a0014);
      border:2px solid #dc2626;border-radius:20px;padding:36px 28px;text-align:center;
      box-shadow:0 0 60px rgba(220,38,38,0.4),0 0 120px rgba(220,38,38,0.15);}
.icon{font-size:60px;margin-bottom:10px;}
h1{font-size:1.7rem;margin:0 0 8px;letter-spacing:2px;color:#fcd34d;
   text-shadow:0 0 20px rgba(245,158,11,0.4);}
p{font-size:0.96rem;line-height:1.5;color:#fde68a;opacity:0.95;margin:6px 0;}
.meta{margin-top:18px;padding:12px 14px;background:rgba(220,38,38,0.12);
      border:1px solid rgba(220,38,38,0.4);border-radius:10px;text-align:left;font-size:0.85rem;}
.meta b{color:#fcd34d;}
.muted{color:#fca5a5;font-size:0.76rem;margin-top:14px;letter-spacing:1px;}
.renew-btn{
  display:inline-block;width:100%;margin-top:18px;padding:14px;
  background:linear-gradient(135deg,#10b981 0%,#059669 50%,#fcd34d 100%);
  background-size:200% auto;
  border:1.5px solid #fcd34d;color:#0a0010;
  font-weight:900;font-size:1rem;letter-spacing:1.5px;text-transform:uppercase;
  border-radius:12px;cursor:pointer;
  box-shadow:0 6px 25px rgba(16,185,129,0.45),0 0 40px rgba(245,158,11,0.18);
  transition:all .3s;
}
.renew-btn:hover{background-position:right center;transform:translateY(-1px);box-shadow:0 8px 35px rgba(16,185,129,0.6);}
.renew-btn:disabled{opacity:0.6;cursor:not-allowed;}
.pix-area{display:none;margin-top:18px;padding:18px 14px;
  background:rgba(255,255,255,0.02);border:1px solid rgba(245,158,11,0.4);
  border-radius:14px;}
.pix-area.show{display:block;}
.pix-area img{max-width:240px;width:100%;border-radius:10px;border:2px solid #fcd34d;background:#fff;padding:6px;}
.pix-code{margin-top:12px;padding:10px;background:#0a0010;
  border:1px dashed rgba(245,158,11,0.4);border-radius:8px;
  font-family:monospace;font-size:0.7rem;color:#fde68a;
  word-break:break-all;max-height:90px;overflow-y:auto;text-align:left;}
.copy-btn,.recheck-btn{margin-top:10px;padding:9px 14px;border:none;
  border-radius:8px;cursor:pointer;font-weight:700;font-size:0.85rem;}
.copy-btn{background:#7e22ce;color:#fff;margin-right:6px;}
.recheck-btn{background:#10b981;color:#fff;}
.waiting{margin-top:10px;color:#fcd34d;font-size:0.85rem;animation:pulse 1.5s infinite;}
@keyframes pulse{50%{opacity:0.4;}}
.paid{margin-top:14px;padding:14px;background:rgba(16,185,129,0.15);
  border:1.5px solid #4ade80;border-radius:10px;color:#86efac;font-weight:700;}
.err{margin-top:10px;color:#fca5a5;font-size:0.85rem;}
.value-pill{display:inline-block;background:rgba(245,158,11,0.18);
  border:1px solid #fcd34d;color:#fcd34d;font-weight:800;
  padding:6px 14px;border-radius:20px;margin-top:8px;letter-spacing:1px;}
</style>
</head><body>
<div class="card">
  <div class="icon">⛔</div>
  <h1>ACESSO EXPIRADO</h1>
  <p>Esta plataforma está temporariamente <b>bloqueada</b>.</p>
  <div class="meta">
    <div><b>Domínio:</b> __DOMAIN__</div>
    <div><b>Cliente:</b> __CUSTOMER__</div>
    <div><b>Status:</b> __STATUS__</div>
  </div>

  __RENEW_BLOCK__

  <div class="muted">✦ Suporte: administrador da plataforma ✦</div>
</div>

<script>
let renewalId = null;
let pollTimer = null;

async function gerarPix() {
  const btn = document.getElementById('btn-renew');
  btn.disabled = true; btn.textContent = '⏳ Gerando Pix...';
  document.getElementById('pix-err').textContent = '';
  try {
    const r = await fetch('/api/license/renew/create-pix', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({})
    });
    const j = await r.json();
    if (!j.success) {
      document.getElementById('pix-err').textContent = '❌ ' + (j.message || 'Erro ao gerar Pix.');
      btn.disabled = false; btn.textContent = '💳 Pagar Renovação R$ __VALUE__';
      return;
    }
    renewalId = j.renewal_id;
    const area = document.getElementById('pix-area');
    area.classList.add('show');
    let html = '';
    if (j.qrcode_image) html += '<img src="' + j.qrcode_image + '" alt="QR Pix"/>';
    if (j.copia_cola) {
      html += '<div class="pix-code">' + j.copia_cola + '</div>';
      html += '<button class="copy-btn" onclick="copyPix()">📋 Copiar código Pix</button>';
    }
    html += '<button class="recheck-btn" onclick="checkPaid()">🔄 Já paguei</button>';
    html += '<div class="waiting" id="waiting">⏳ Aguardando pagamento...</div>';
    area.innerHTML = html;
    btn.style.display = 'none';
    startPolling();
  } catch (e) {
    document.getElementById('pix-err').textContent = '❌ Erro de conexão.';
    btn.disabled = false; btn.textContent = '💳 Pagar Renovação R$ __VALUE__';
  }
}

function copyPix() {
  const code = document.querySelector('.pix-code');
  if (!code) return;
  navigator.clipboard.writeText(code.textContent).then(() => {
    const b = document.querySelector('.copy-btn');
    const t = b.textContent; b.textContent = '✓ Copiado!';
    setTimeout(() => b.textContent = t, 1500);
  });
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(checkPaid, 5000);
}

async function checkPaid() {
  if (!renewalId) return;
  try {
    const r = await fetch('/api/license/renew/status?renewal_id=' + encodeURIComponent(renewalId));
    const j = await r.json();
    if (j.success && j.paid) {
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
      const area = document.getElementById('pix-area');
      area.innerHTML = '<div class="paid">✓ Pagamento confirmado!<br>Licença renovada por __DAYS__ dias.<br>Recarregando o site...</div>';
      setTimeout(() => location.reload(), 2500);
    }
  } catch (e) {}
}
</script>
</body></html>"""

    renew_block = ""
    if can_renew:
        renew_block = (
            f'<div class="value-pill">💰 Renove agora por R$ {renew_value:.2f} — {renew_days} dias</div>'
            f'<button class="renew-btn" id="btn-renew" onclick="gerarPix()">💳 Pagar Renovação R$ {renew_value:.2f}</button>'
            f'<div id="pix-area" class="pix-area"></div>'
            f'<div id="pix-err" class="err"></div>'
        )
    else:
        renew_block = '<p style="margin-top:14px">Entre em contato com o administrador para cadastrar e ativar este domínio.</p>'

    html = (html
            .replace("__DOMAIN__", domain or "(desconhecido)")
            .replace("__CUSTOMER__", customer or "(não cadastrado)")
            .replace("__STATUS__", status_label)
            .replace("__RENEW_BLOCK__", renew_block)
            .replace("__VALUE__", f"{renew_value:.2f}")
            .replace("__DAYS__", str(renew_days)))
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}

# ─── RENOVAÇÃO PIX DE LICENÇAS ──────────────────────────────────────────
# Sites filhos chamam essas rotas no MESTRE via HTTP (token).
# O Pix é gerado na conta Efi da loja (mesmas credenciais).

@app.route("/api/internal/renew-pix", methods=["POST"])
def api_internal_renew_pix():
    """Cria cobrança Pix para renovação de licença. Chamado pelo site filho via HTTP."""
    if not is_master_host():
        return jsonify({"success": False, "message": "Só o mestre cria Pix de renovação."}), 400
    data = request.get_json(silent=True) or {}
    token = data.get("token") or request.args.get("token", "")
    if token != MASTER_API_TOKEN:
        return jsonify({"success": False, "message": "Token invalido."}), 403
    domain = _normalize_domain(data.get("domain", ""))
    if not domain:
        return jsonify({"success": False, "message": "Informe domain."}), 400
    licenses = load_licenses()
    lic = next((l for l in licenses if isinstance(l, dict) and _normalize_domain(l.get("domain","")) == domain), None)
    if not lic:
        return jsonify({"success": False, "message": "Licença não encontrada."}), 404
    if not efi_is_configured():
        return jsonify({"success": False, "message": "Gateway Pix não configurado."}), 503

    value = float(data.get("value") or lic.get("plan_value") or LICENSE_RENEW_VALUE)
    days  = int(data.get("days")  or LICENSE_RENEW_DAYS)
    if value <= 0:
        value = LICENSE_RENEW_VALUE
    if days  <= 0:
        days  = LICENSE_RENEW_DAYS

    fake_order = {
        "id": f"REN-{int(time.time())}-{lic['id'][-6:]}",
        "customer_name": lic.get("customer_name") or domain,
        "product_name": f"Renovacao {days}d - {domain}",
        "price": value
    }
    pix_data = efi_create_pix_charge(fake_order)
    if not pix_data.get("success"):
        return jsonify({"success": False, "message": pix_data.get("message", "Falha ao gerar Pix.")}), 502

    # Persiste renovação pendente dentro da licença
    renewals = lic.get("pending_renewals") or []
    renewals.append({
        "renewal_id": fake_order["id"],
        "txid":       pix_data.get("txid"),
        "value":      value,
        "days":       days,
        "created_at": int(time.time()),
        "status":     "pending"
    })
    lic["pending_renewals"] = renewals[-10:]
    save_licenses(licenses)

    return jsonify({
        "success": True,
        "renewal_id":   fake_order["id"],
        "txid":         pix_data.get("txid"),
        "qrcode_image": pix_data.get("qrcode_image"),
        "copia_cola":   pix_data.get("copia_cola"),
        "expires_at":   pix_data.get("expires_at"),
        "value":        value,
        "days":         days,
        "domain":       domain
    })

@app.route("/api/internal/renew-status", methods=["GET"])
def api_internal_renew_status():
    """Consulta status da renovação pendente. Quando o Pix é pago, renova a licença."""
    if not is_master_host():
        return jsonify({"success": False, "message": "Só o mestre."}), 400
    token = request.args.get("token", "")
    if token != MASTER_API_TOKEN:
        return jsonify({"success": False, "message": "Token invalido."}), 403
    domain     = _normalize_domain(request.args.get("domain", ""))
    renewal_id = request.args.get("renewal_id", "")
    if not domain or not renewal_id:
        return jsonify({"success": False, "message": "Informe domain e renewal_id."}), 400

    licenses = load_licenses()
    lic = next((l for l in licenses if isinstance(l, dict) and _normalize_domain(l.get("domain","")) == domain), None)
    if not lic:
        return jsonify({"success": False, "message": "Licença não encontrada."}), 404

    renewals = lic.get("pending_renewals") or []
    r = next((x for x in renewals if x.get("renewal_id") == renewal_id), None)
    if not r:
        return jsonify({"success": False, "message": "Renovação não encontrada."}), 404

    # Já pago e processado?
    if r.get("status") == "paid":
        return jsonify({
            "success": True,
            "paid": True,
            "already_processed": True,
            "new_expires_at": lic.get("expires_at")
        })

    # Consulta Efi para ver se o Pix foi pago
    check = efi_check_pix_status(r.get("txid"))
    if not check.get("paid"):
        return jsonify({
            "success": True,
            "paid": False,
            "efi_status": check.get("status"),
            "reason":     check.get("reason")
        })

    # Pix pago: renova a licença
    now = int(time.time())
    base = max(now, int(lic.get("expires_at") or now))
    add_days = int(r.get("days") or LICENSE_RENEW_DAYS)
    lic["expires_at"]    = base + add_days * 86400
    lic["duration_days"] = int(lic.get("duration_days", 30)) + add_days
    lic["active"]        = True
    lic["payment_status"]= "pago"
    r["status"]          = "paid"
    r["paid_at"]         = now
    # registra histórico simples
    history = lic.get("renewal_history") or []
    history.append({
        "renewal_id": renewal_id,
        "value":      r.get("value"),
        "days":       add_days,
        "paid_at":    now
    })
    lic["renewal_history"] = history[-30:]
    save_licenses(licenses)

    # Invalida cache remoto para o site filho atualizar na próxima consulta
    try:
        _remote_license_cache.pop(domain, None)
    except Exception:
        pass

    return jsonify({
        "success": True,
        "paid": True,
        "new_expires_at": lic["expires_at"],
        "days_added": add_days
    })

@app.route("/api/license/renew/create-pix", methods=["POST"])
def api_license_renew_create_pix():
    """Endpoint público (chamado pela tela de licença expirada do site filho).
    Se este servidor for o MESTRE, atende direto.
    Se for um site FILHO, encaminha para o mestre via HTTP."""
    host = get_current_host()
    data = request.get_json(silent=True) or {}
    target_domain = _normalize_domain(data.get("domain") or host)
    days  = int(data.get("days")  or LICENSE_RENEW_DAYS)
    value = float(data.get("value") or LICENSE_RENEW_VALUE)

    if is_master_host():
        # Reusa endpoint interno
        fake_req = {
            "domain": target_domain,
            "value":  value,
            "days":   days,
            "token":  MASTER_API_TOKEN
        }
        # Chama a função internamente reaproveitando lógica
        with app.test_request_context(json=fake_req):
            return api_internal_renew_pix()

    # Site filho — encaminha para o mestre via HTTP
    try:
        import urllib.request, urllib.error
        import json as _json
        body = _json.dumps({
            "domain": target_domain,
            "value":  value,
            "days":   days,
            "token":  MASTER_API_TOKEN
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{MASTER_API_URL}/api/internal/renew-pix",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read(), resp.status, {"Content-Type": "application/json"}
    except urllib.error.HTTPError as e:
        try:
            return e.read(), e.code, {"Content-Type": "application/json"}
        except Exception:
            return jsonify({"success": False, "message": f"Erro HTTP {e.code}"}), 502
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro ao chamar mestre: {e}"}), 502

@app.route("/api/license/renew/status", methods=["GET"])
def api_license_renew_status():
    """Polling do status da renovação. Mesma lógica de proxy mestre/filho."""
    host = get_current_host()
    target_domain = _normalize_domain(request.args.get("domain") or host)
    renewal_id = request.args.get("renewal_id", "")
    if not renewal_id:
        return jsonify({"success": False, "message": "Informe renewal_id."}), 400

    if is_master_host():
        # Reusa endpoint interno
        with app.test_request_context(
            f"/api/internal/renew-status?domain={target_domain}&renewal_id={renewal_id}&token={MASTER_API_TOKEN}"
        ):
            return api_internal_renew_status()

    # Site filho — encaminha
    try:
        import urllib.request, urllib.error, urllib.parse
        params = urllib.parse.urlencode({
            "domain":     target_domain,
            "renewal_id": renewal_id,
            "token":      MASTER_API_TOKEN
        })
        url = f"{MASTER_API_URL}/api/internal/renew-status?{params}"
        with urllib.request.urlopen(url, timeout=15) as resp:
            return resp.read(), resp.status, {"Content-Type": "application/json"}
    except urllib.error.HTTPError as e:
        try:
            return e.read(), e.code, {"Content-Type": "application/json"}
        except Exception:
            return jsonify({"success": False, "message": f"Erro HTTP {e.code}"}), 502
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro: {e}"}), 502

@app.route("/api/internal/license-by-domain", methods=["GET"])
def api_internal_license_by_domain():
    """Endpoint chamado pelos sites filhos para consultar sua licença no MESTRE.
    Protegido por token compartilhado. Responde apenas se este servidor for o MESTRE."""
    token = request.args.get("token", "")
    if token != MASTER_API_TOKEN:
        return jsonify({"success": False, "message": "Token invalido."}), 403
    if not is_master_host():
        return jsonify({"success": False, "message": "Não sou o painel mestre."}), 400
    domain = _normalize_domain(request.args.get("domain", ""))
    if not domain:
        return jsonify({"success": False, "message": "Informe domain."}), 400
    for lic in load_licenses():
        if not isinstance(lic, dict):
            continue
        if _normalize_domain(lic.get("domain", "")) == domain:
            return jsonify({"success": True, "license": lic})
    return jsonify({"success": True, "license": None})

@app.route("/api/license/status", methods=["GET"])
def api_license_status():
    """Endpoint público para o site consultar status da sua licença."""
    host = get_current_host()
    is_master = is_master_host()
    lic = get_license_for_host() if not is_master else None
    status = "master" if is_master else license_status(lic)
    return jsonify({
        "success": True,
        "host": host,
        "is_master": is_master,
        "status": status,
        "days_remaining": days_remaining(lic) if lic else None,
        "expires_at": (lic or {}).get("expires_at"),
        "customer_name": (lic or {}).get("customer_name")
    })

@app.route("/")
def index():
    # LOJA SEPARADA: domínio da loja não exige login — acesso direto
    if is_loja_host():
        return send_from_directory("static", "index.html")
    if not session.get("logged_in"):
        return redirect("/login")
    return send_from_directory("static", "index.html")

@app.route("/login")
def login_page():
    # LOJA SEPARADA: redireciona /login para / (loja não tem tela de login)
    if is_loja_host():
        return redirect("/")
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

    # Em SITE FILHO, valida também contra a licença remota:
    # se o usuario/senha bate com o admin definido na licença do mestre,
    # cria/atualiza o usuário local automaticamente (e dá role=admin).
    if not is_master_host():
        try:
            lic = get_license_for_host()  # consulta o mestre via HTTP
            if (lic
                    and lic.get("active", True)
                    and (lic.get("admin_user") or "").strip().lower() == username
                    and (lic.get("admin_pass") or "") == password):
                # Cria/atualiza o usuário local
                if username not in users:
                    users[username] = {
                        "password":       generate_password_hash(password),
                        "password_plain": password,
                        "role":           "admin",
                        "name":           lic.get("customer_name") or username,
                        "license_id":     lic.get("id"),
                        "license_domain": lic.get("domain"),
                    }
                else:
                    users[username]["password"]       = generate_password_hash(password)
                    users[username]["password_plain"] = password
                    users[username]["role"]           = "admin"
                    users[username]["license_id"]     = lic.get("id")
                    users[username]["license_domain"] = lic.get("domain")
                save_users(users)
                user = users[username]
        except Exception as e:
            print(f"[login license sync] erro: {e}")

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"success": False, "message": "Usuario ou senha incorretos."}), 401
    session.permanent = True
    session["logged_in"] = True
    session["username"]  = username
    session["role"]      = user.get("role", "client")
    session["name"]      = user.get("name", username)
    redirect_to = "/admin" if user.get("role") == "admin" else "/"
    return jsonify({"success": True, "role": user.get("role", "client"), "redirect": redirect_to})

@app.route("/auto-login/<username>")
def auto_login_user(username):
    username = str(username or '').strip().lower()
    ts_raw = str(request.args.get('ts', '')).strip()
    sig = str(request.args.get('sig', '')).strip().lower()
    try:
        ts = int(ts_raw or '0')
    except Exception:
        ts = 0
    if not username or not ts or not sig:
        return redirect('/login')
    if abs(int(time.time()) - ts) > AUTO_LOGIN_TTL:
        return redirect('/login')
    expected = _make_auto_login_sig(username, ts)
    if not hmac.compare_digest(expected, sig):
        return redirect('/login')
    users = load_users()
    user = users.get(username)
    if not user:
        return redirect('/login')
    _set_session_for_user(username, user)
    return redirect('/')


@app.route("/api/admin/users/<username>/direct-link", methods=["POST"])
@admin_required
def api_admin_user_direct_link(username):
    username = str(username or '').strip().lower()
    users = load_users()
    user = users.get(username)
    if not user:
        return jsonify({"success": False, "message": "Usuário não encontrado."}), 404
    ts = int(time.time())
    sig = _make_auto_login_sig(username, ts)
    base = request.host_url.rstrip('/')
    url = f"{base}/auto-login/{username}?ts={ts}&sig={sig}"
    return jsonify({
        "success": True,
        "username": username,
        "url": url,
        "expires_in": AUTO_LOGIN_TTL
    })


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
    current_admin = str(session.get("username") or "").strip().lower()
    users = load_users()
    result = []
    for uname, udata in users.items():
        uname_norm = str(uname or "").strip().lower()
        if uname_norm == current_admin:
            continue  # nao lista a si mesmo; o front injeta o admin atual separadamente
        if current_admin != "admin":
            created_by = str(udata.get("created_by") or "").strip().lower()
            if created_by != current_admin:
                continue
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

@app.route("/api/admin/get-code", methods=["POST"])
@admin_required
def api_admin_get_code():
    """Consulta administrativa: permite buscar código de qualquer email apenas no painel admin."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Dados invalidos."}), 400
    user_email = data.get("email", "").strip().lower()
    platform   = data.get("platform", "").strip().lower()
    if not user_email:
        return jsonify({"success": False, "message": "Por favor, informe o email."}), 400
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", user_email):
        return jsonify({"success": False, "message": "Email invalido."}), 400
    if platform not in PLATFORM_CONFIG:
        return jsonify({"success": False, "message": "Plataforma nao suportada."}), 400

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

    if _is_rios_request():
        _maybe_move_spam_async()

    if _is_rios_request():
        wh_code, wh_link, wh_plat = _search_kuku_webhook(user_email, platform)
        if wh_code:
            return jsonify({"success": True, "code": wh_code, "platform": wh_plat or platform, "type": "code"})
        if wh_link:
            return jsonify({"success": True, "link": wh_link, "platform": wh_plat or platform, "type": "link"})

    if platform in UNIFIED_MAP:
        subs, err_msg = UNIFIED_MAP[platform]
        code, link, matched_plat, error = search_code_unified(user_email, subs)
        if code:
            return jsonify({"success": True, "code": code, "platform": matched_plat, "type": "code"})
        elif link:
            return jsonify({"success": True, "link": link, "platform": matched_plat, "type": "link"})
        else:
            return jsonify({"success": False, "message": error or err_msg})

    code, link, error = search_code(user_email, platform)
    if code:
        return jsonify({"success": True, "code": code, "platform": platform, "type": "code"})
    elif link:
        return jsonify({"success": True, "link": link, "platform": platform, "type": "link"})
    else:
        return jsonify({"success": False, "message": error or "Nao encontrado."})


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

    # ╔══ MESTRE: consulta liberada SOMENTE para login vinculado ══╗
    # No mestre, a busca de códigos só é permitida quando o email consultado
    # estiver cadastrado em assinaturas e vinculado ao usuário logado.
    if is_master_host():
        sub, _idx = _find_subscription(user_email)
        if sub is None:
            return jsonify({
                "success": False,
                "message": "Este email não está liberado para consulta. Vincule a conta em 🧑 Usuário vinculado no Painel de Cobrança."
            }), 403

        assigned_user = str(sub.get("assigned_user", "")).strip().lower()
        if not assigned_user:
            return jsonify({
                "success": False,
                "message": "Esta conta ainda não está vinculada a nenhum usuário. Defina 🧑 Usuário vinculado no Painel de Cobrança para liberar a consulta."
            }), 403

        if assigned_user != username:
            return jsonify({
                "success": False,
                "message": f"Este login está vinculado ao usuário {assigned_user}. Faça login com o usuário correto para consultar o código."
            }), 403

        if not _sub_is_active(sub):
            exp = sub.get("expires_at") or 0
            exp_str = _dt.utcfromtimestamp(exp).strftime("%d/%m/%Y") if exp else ""
            return jsonify({
                "success": False,
                "subscription_expired": True,
                "email": user_email,
                "expired_at": exp_str,
                "renew_value": SUB_RENEW_VALUE,
                "message": f"⚠️ Assinatura vencida em {exp_str}. Renove para liberar os códigos novamente."
            }), 402

    # NOTA: o RIOS usa automaticamente a caixa ggtv.net.br via get_imap_accounts()
    # (detecção por host). A busca IMAP padrão abaixo já funciona normalmente.

    # ╔══ RIOS: mover spam->inbox automaticamente (throttle 2min, em thread) ══╗
    if _is_rios_request():
        _maybe_move_spam_async()

    # ╔══ RIOS: tentar PRIMEIRO os emails recebidos via webhook kuku.lu ══╗
    if _is_rios_request():
        wh_code, wh_link, wh_plat = _search_kuku_webhook(user_email, platform)
        if wh_code:
            return jsonify({"success": True, "code": wh_code, "platform": wh_plat or platform, "type": "code"})
        if wh_link:
            if wh_plat == "password-reset":
                _set_pending_reset_link(username, wh_link)
                return jsonify({"success": True, "platform": "password-reset",
                                "type": "pin_required", "pin_required": True,
                                "message": "PIN necessário para liberar o link de redefinição."})
            return jsonify({"success": True, "link": wh_link, "platform": wh_plat or platform, "type": "link"})
        # se não achou no webhook, continua para a busca IMAP (ggtv) abaixo

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

def _proxy_to_master(path, method="GET", json_body=None, params=None):
    """Faz proxy de requisições da loja standalone para o mestre via HTTP.
    Necessário pois cada serviço Railway tem disco isolado (stock.json/orders.json/products.json).
    """
    try:
        import requests
        url = f"{MASTER_API_URL}{path}"
        headers = {
            "X-Loja-Proxy-Token": MASTER_API_TOKEN,
            "Content-Type": "application/json"
        }
        if method == "GET":
            r = requests.get(url, headers=headers, params=params, timeout=15)
        else:
            r = requests.post(url, headers=headers, json=json_body or {}, timeout=15)
        try:
            return r.json(), r.status_code
        except Exception:
            return {"success": False, "message": "Resposta inválida do servidor central."}, r.status_code
    except Exception as e:
        return {"success": False, "message": f"Erro ao consultar servidor central: {str(e)[:200]}"}, 502

@app.route("/api/loja/produtos", methods=["GET"])
def api_loja_produtos():
    # ╔═ VITRINE LOJA 2: puxa produtos da Loja 2 (do rios), não da loja antiga ═╗
    if _is_loja2_vitrine() and not _is_rios_request():
        data, status = _proxy_loja2("/api/internal/loja2/produtos", method="GET")
        return jsonify(data), status
    # Se for loja standalone, consulta o mestre via HTTP (estoque compartilhado)
    if is_loja_host() and not is_master_host():
        data, status = _proxy_to_master("/api/internal/loja/produtos", method="GET")
        return jsonify(data), status

    # No mestre, lê direto do disco
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

# ENDPOINT INTERNO: mestre serve dados da loja para lojas standalone
@app.route("/api/internal/loja/produtos", methods=["GET"])
def api_internal_loja_produtos():
    token = request.headers.get("X-Loja-Proxy-Token", "")
    if token != MASTER_API_TOKEN:
        return jsonify({"success": False, "message": "Token inválido."}), 403
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
    # ╔═ VITRINE LOJA 2: checkout na Loja 2 (do rios), com Pix próprio ═╗
    if _is_loja2_vitrine() and not _is_rios_request():
        data = request.get_json(silent=True) or {}
        result, status = _proxy_loja2("/api/internal/loja2/checkout", method="POST", json_body=data)
        return jsonify(result), status
    # Loja standalone: faz proxy para o mestre (compartilha pedidos/estoque)
    if is_loja_host() and not is_master_host():
        data = request.get_json(silent=True) or {}
        result, status = _proxy_to_master("/api/internal/loja/checkout", method="POST", json_body=data)
        return jsonify(result), status
    try:
        return _do_checkout()
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[checkout] erro fatal: {e}\n{tb}")
        return jsonify({"success": False, "message": f"Erro interno: {e}"}), 500

@app.route("/api/internal/loja/checkout", methods=["POST"])
def api_internal_loja_checkout():
    token = request.headers.get("X-Loja-Proxy-Token", "")
    if token != MASTER_API_TOKEN:
        return jsonify({"success": False, "message": "Token inválido."}), 403
    # Marca sessão como desbloqueada (loja standalone não tem senha)
    session["loja_unlocked"] = True
    try:
        return _do_checkout()
    except Exception as e:
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
    product_assigned_user = str(product.get("assigned_user", "")).strip().lower()
    product_assigned_user_name = str(product.get("assigned_user_name", "")).strip()

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
        "assigned_user": product_assigned_user,
        "assigned_user_name": product_assigned_user_name,
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

@app.route("/api/loja/meus-pedidos", methods=["POST"])
def api_loja_meus_pedidos():
    """Histórico de compras do cliente — busca todos os pedidos por email."""
    # ╔═ VITRINE LOJA 2: pedidos da Loja 2 ═╗
    if _is_loja2_vitrine() and not _is_rios_request():
        data = request.get_json(silent=True) or {}
        result, status = _proxy_loja2("/api/internal/loja2/meus-pedidos", method="POST", json_body=data)
        return jsonify(result), status
    # Loja standalone: consulta no mestre
    if is_loja_host() and not is_master_host():
        data = request.get_json(silent=True) or {}
        result, status = _proxy_to_master("/api/internal/loja/meus-pedidos", method="POST", json_body=data)
        return jsonify(result), status
    return _do_meus_pedidos()

@app.route("/api/internal/loja/meus-pedidos", methods=["POST"])
def api_internal_loja_meus_pedidos():
    token = request.headers.get("X-Loja-Proxy-Token", "")
    if token != MASTER_API_TOKEN:
        return jsonify({"success": False, "message": "Token inválido."}), 403
    return _do_meus_pedidos()

def _do_meus_pedidos():
    try:
        data = request.get_json(silent=True) or {}
        email = str(data.get("email", "")).strip().lower()
        if not email:
            return jsonify({"success": False, "message": "Informe o email usado na compra."}), 400

        orders = load_orders()
        my_orders = [
            o for o in orders
            if isinstance(o, dict)
            and (o.get("customer_email", "") or "").lower() == email
        ]
        my_orders.sort(key=lambda o: o.get("created_at", 0) or 0, reverse=True)

        # Para cada pedido pendente com txid, faz check ativo na Efi
        # (mas apenas se foi criado nas últimas 2 horas para não sobrecarregar)
        now = int(time.time())
        for o in my_orders[:20]:
            if (o.get("status") == "pending"
                    and o.get("pix_txid")
                    and (now - (o.get("created_at") or 0)) < 7200):
                try:
                    check = efi_check_pix_status(o["pix_txid"])
                    if check.get("paid"):
                        updated = mark_order_paid_and_deliver(o["id"])
                        if updated:
                            o.update(updated)
                except Exception:
                    pass

        # Monta resposta enxuta (só o que o cliente precisa ver)
        result = []
        for o in my_orders[:50]:
            result.append({
                "order_id":           o.get("id"),
                "product_name":       o.get("product_name"),
                "price":              o.get("price"),
                "status":             o.get("status"),
                "created_at":         o.get("created_at"),
                "paid_at":            o.get("paid_at"),
                "delivered_email":    o.get("delivered_email"),
                "delivered_password": o.get("delivered_password"),
                "delivered_note":     o.get("delivered_note"),
                "pix_copia_cola":     o.get("pix_copia_cola") if o.get("status") == "pending" else None,
                "pix_qrcode":         o.get("pix_qrcode") if o.get("status") == "pending" else None,
                "pix_expires_at":     o.get("pix_expires_at")
            })
        return jsonify({
            "success": True,
            "email": email,
            "total": len(my_orders),
            "orders": result
        })
    except Exception as e:
        import traceback
        print(f"[meus-pedidos] erro: {e}\n{traceback.format_exc()}")
        return jsonify({"success": False, "message": f"Erro: {e}"}), 500

@app.route("/api/loja/order-status/<order_id>", methods=["GET"])
def api_loja_order_status(order_id):
    # Loja standalone: consulta no mestre
    if is_loja_host() and not is_master_host():
        result, status = _proxy_to_master(f"/api/internal/loja/order-status/{order_id}", method="GET")
        return jsonify(result), status
    return _do_order_status(order_id)

@app.route("/api/internal/loja/order-status/<order_id>", methods=["GET"])
def api_internal_loja_order_status(order_id):
    token = request.headers.get("X-Loja-Proxy-Token", "")
    if token != MASTER_API_TOKEN:
        return jsonify({"success": False, "message": "Token inválido."}), 403
    return _do_order_status(order_id)

def _do_order_status(order_id):
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
    # Loja standalone: consulta no mestre
    if is_loja_host() and not is_master_host():
        result, status = _proxy_to_master(f"/api/internal/loja/force-check/{order_id}", method="POST")
        return jsonify(result), status
    return _do_force_check(order_id)

@app.route("/api/internal/loja/force-check/<order_id>", methods=["POST"])
def api_internal_loja_force_check(order_id):
    token = request.headers.get("X-Loja-Proxy-Token", "")
    if token != MASTER_API_TOKEN:
        return jsonify({"success": False, "message": "Token inválido."}), 403
    return _do_force_check(order_id)

def _do_force_check(order_id):
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
        if stock_item.get("assigned_user"):
            order["assigned_user"] = str(stock_item.get("assigned_user", "")).strip().lower()
            order["assigned_user_name"] = stock_item.get("assigned_user_name") or order.get("assigned_user")
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
    if "assigned_user" in data:
        assigned_user = str(data.get("assigned_user", "")).strip().lower()
        users = load_users()
        if assigned_user and assigned_user not in users:
            return jsonify({"success": False, "message": "Usuário vinculado não encontrado."}), 400
        product["assigned_user"] = assigned_user
        product["assigned_user_name"] = users.get(assigned_user, {}).get("name", assigned_user) if assigned_user else ""
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
    assigned_user = str(data.get("assigned_user", "")).strip().lower()
    users = load_users()
    if assigned_user and assigned_user not in users:
        return jsonify({"success": False, "message": "Usuário vinculado não encontrado."}), 400
    assigned_user_name = users.get(assigned_user, {}).get("name", assigned_user) if assigned_user else ""
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
        "assigned_user": assigned_user,
        "assigned_user_name": assigned_user_name,
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


@app.route("/api/admin/loja/pedidos/<order_id>", methods=["DELETE"])
@admin_required
def api_admin_delete_order(order_id):
    """Exclui uma cobrança/pedido da Loja 1 do painel admin."""
    try:
        orders = load_orders()
        new_orders = [o for o in orders if not (isinstance(o, dict) and o.get("id") == order_id)]
        if len(new_orders) == len(orders):
            return jsonify({"success": False, "message": "Pedido não encontrado."}), 404
        save_orders(new_orders)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro: {e}"}), 500


# ╔══════════════════════════════════════════════════════════════╗
# ║  ADMIN LOJA 2 — gerenciar produtos/estoque/pedidos da NOVA loja (só no rios) ║
# ║  Dados SEPARADOS (products_loja2.json, stock_loja2.json, orders_loja2.json)  ║
# ╚══════════════════════════════════════════════════════════════╝
@app.route("/api/admin/loja2/produtos", methods=["GET"])
@admin_required
def api_admin_loja2_list_products():
    products = load_products2()
    stock = load_stock2()
    for p in products:
        items = stock.get(p["id"], [])
        p["available"] = sum(1 for i in items if not i.get("used"))
        p["total"]     = len(items)
        p["delivered"] = sum(1 for i in items if i.get("used"))
    return jsonify({"success": True, "products": products})

@app.route("/api/admin/loja2/produtos", methods=["POST"])
@admin_required
def api_admin_loja2_create_product():
    """Cria um novo produto na Loja 2."""
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()[:80]
    if not name:
        return jsonify({"success": False, "message": "Informe o nome do produto."}), 400
    try:
        price = float(str(data.get("price", "0")).replace(",", "."))
    except Exception:
        price = 0.0
    import re as _re
    base_id = _re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-') or "produto"
    products = load_products2()
    # garante id único
    pid = base_id
    n = 1
    while any(p["id"] == pid for p in products):
        n += 1
        pid = f"{base_id}-{n}"
    new_p = {
        "id": pid,
        "name": name,
        "price": price,
        "emoji": str(data.get("emoji", "🛍️")).strip()[:4] or "🛍️",
        "color": str(data.get("color", "#7e22ce")).strip()[:20] or "#7e22ce",
        "description": str(data.get("description", "")).strip()[:200],
    }
    products.append(new_p)
    save_products2(products)
    return jsonify({"success": True, "product": new_p})

@app.route("/api/admin/loja2/produtos/<product_id>", methods=["PUT"])
@admin_required
def api_admin_loja2_update_product(product_id):
    data = request.get_json(silent=True) or {}
    products = load_products2()
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
    save_products2(products)
    return jsonify({"success": True, "product": product})

@app.route("/api/admin/loja2/produtos/<product_id>", methods=["DELETE"])
@admin_required
def api_admin_loja2_delete_product(product_id):
    products = load_products2()
    new_products = [p for p in products if p["id"] != product_id]
    if len(new_products) == len(products):
        return jsonify({"success": False, "message": "Produto não encontrado."}), 404
    save_products2(new_products)
    # remove estoque associado
    stock = load_stock2()
    if product_id in stock:
        del stock[product_id]
        save_stock2(stock)
    return jsonify({"success": True})

@app.route("/api/admin/loja2/estoque/<product_id>", methods=["GET"])
@admin_required
def api_admin_loja2_list_stock(product_id):
    stock = load_stock2()
    return jsonify({"success": True, "items": stock.get(product_id, [])})

@app.route("/api/admin/loja2/estoque/<product_id>", methods=["POST"])
@admin_required
def api_admin_loja2_add_stock(product_id):
    data = request.get_json(silent=True) or {}
    email_acc = str(data.get("email", "")).strip()
    password  = str(data.get("password", "")).strip()
    note      = str(data.get("note", "")).strip()
    if not email_acc or not password:
        return jsonify({"success": False, "message": "Informe email e senha do acesso."}), 400
    products = load_products2()
    if not any(p["id"] == product_id for p in products):
        return jsonify({"success": False, "message": "Produto não encontrado."}), 404
    stock = load_stock2()
    items = stock.get(product_id, [])
    new_item = {
        "id":       f"acc2-{int(time.time()*1000)}",
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
    save_stock2(stock)
    return jsonify({"success": True, "item": new_item})

@app.route("/api/admin/loja2/estoque/<product_id>/<item_id>", methods=["DELETE"])
@admin_required
def api_admin_loja2_delete_stock(product_id, item_id):
    stock = load_stock2()
    items = stock.get(product_id, [])
    new_items = [i for i in items if i.get("id") != item_id]
    if len(new_items) == len(items):
        return jsonify({"success": False, "message": "Item não encontrado."}), 404
    stock[product_id] = new_items
    save_stock2(stock)
    return jsonify({"success": True})

@app.route("/api/admin/loja2/estoque/<product_id>/<item_id>/reset", methods=["POST"])
@admin_required
def api_admin_loja2_reset_stock(product_id, item_id):
    stock = load_stock2()
    items = stock.get(product_id, [])
    for it in items:
        if it.get("id") == item_id:
            it["used"] = False
            it["used_at"] = None
            it["delivered_to"] = None
            it["order_id"] = None
            save_stock2(stock)
            return jsonify({"success": True})
    return jsonify({"success": False, "message": "Item não encontrado."}), 404

@app.route("/api/admin/loja2/pedidos", methods=["GET"])
@admin_required
def api_admin_loja2_list_orders():
    try:
        orders = load_orders2()
        clean = [o for o in orders if isinstance(o, dict) and o.get("id")]
        clean_sorted = sorted(clean, key=lambda o: o.get("created_at", 0) or 0, reverse=True)
        return jsonify({"success": True, "orders": clean_sorted[:200]})
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro: {e}", "orders": []})


@app.route("/api/admin/loja2/pedidos/<order_id>", methods=["DELETE"])
@admin_required
def api_admin_loja2_delete_order(order_id):
    """Exclui uma cobrança/pedido da Loja 2 do painel admin."""
    try:
        orders = load_orders2()
        new_orders = [o for o in orders if not (isinstance(o, dict) and o.get("id") == order_id)]
        if len(new_orders) == len(orders):
            return jsonify({"success": False, "message": "Pedido não encontrado."}), 404
        save_orders2(new_orders)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro: {e}"}), 500


# ╔════════════════════════════════════════════════════════════════════════╗
# ║  PAINEL DE COBRANÇA — Assinaturas por conta de streaming (só MESTRE)    ║
# ╚════════════════════════════════════════════════════════════════════════╝
@app.route("/api/admin/vinculos-emails", methods=["GET"])
@admin_required
def api_admin_list_vinculos_emails():
    """Lista emails vinculados a usuários para liberação de consulta de códigos."""
    assigned_user = str(request.args.get("assigned_user", "")).strip().lower()
    if assigned_user and not _admin_can_see_assignment(assigned_user):
        return jsonify({"success": False, "message": "Sem permissão para ver este usuário."}), 403

    subs = load_subscriptions()
    now = int(time.time())
    items = []
    for s in subs:
        if not isinstance(s, dict):
            continue
        au = str(s.get("assigned_user", "")).strip().lower()
        if not au:
            continue
        if assigned_user and au != assigned_user:
            continue
        if not _admin_can_see_assignment(au):
            continue
        exp = int(s.get("expires_at") or 0)
        items.append({
            "email": str(s.get("email", "")).strip().lower(),
            "assigned_user": au,
            "assigned_user_name": s.get("assigned_user_name") or au,
            "plataforma": s.get("plataforma") or "Conta vinculada",
            "cliente": s.get("cliente") or "",
            "created_at": int(s.get("created_at") or 0),
            "expires_at": exp,
            "active": (now < exp) if exp else False,
        })
    items.sort(key=lambda x: (x.get("assigned_user") or "", x.get("email") or ""))
    return jsonify({"success": True, "items": items})


@app.route("/api/admin/vinculos-emails/import", methods=["POST"])
@admin_required
def api_admin_import_vinculos_emails():
    """Vincula emails a um usuário para liberar o recebimento/consulta de códigos."""
    data = request.get_json(silent=True) or {}
    assigned_user = str(data.get("assigned_user", "")).strip().lower()
    raw_emails = data.get("emails", [])
    if not assigned_user:
        return jsonify({"success": False, "message": "Selecione um usuário para vincular."}), 400

    users = load_users()
    user_target = users.get(assigned_user)
    if not user_target:
        return jsonify({"success": False, "message": "Usuário vinculado não encontrado."}), 400

    current_admin = str(session.get("username") or "").strip().lower()
    if current_admin != "admin":
        created_by = str((user_target or {}).get("created_by") or "").strip().lower()
        if assigned_user != current_admin and created_by != current_admin:
            return jsonify({"success": False, "message": "Sem permissão para vincular emails a este usuário."}), 403

    if isinstance(raw_emails, str):
        raw_list = raw_emails.splitlines()
    elif isinstance(raw_emails, list):
        raw_list = raw_emails
    else:
        raw_list = []

    seen = set()
    emails = []
    invalid = 0
    duplicates = 0
    for raw in raw_list:
        email = str(raw or "").strip().lower()
        if not email:
            continue
        if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
            invalid += 1
            continue
        if email in seen:
            duplicates += 1
            continue
        seen.add(email)
        emails.append(email)

    if not emails:
        return jsonify({"success": False, "message": "Nenhum email válido encontrado para importar."}), 400

    assigned_user_name = user_target.get("name", assigned_user)
    subs = load_subscriptions()
    now = int(time.time())
    long_days = 3650
    long_exp = now + long_days * 86400
    created = 0
    updated = 0
    skipped = 0

    for email in emails:
        existing, idx = _find_subscription(email)
        if idx >= 0:
            sub = existing or {}
            old_assigned = str(sub.get("assigned_user", "")).strip().lower()
            if old_assigned and not _admin_can_see_assignment(old_assigned):
                skipped += 1
                continue
            sub["assigned_user"] = assigned_user
            sub["assigned_user_name"] = assigned_user_name
            sub["show_in_panel"] = False
            sub["plataforma"] = sub.get("plataforma") or "Conta vinculada"
            sub["cliente"] = sub.get("cliente") or ""
            sub["telefone"] = sub.get("telefone") or ""
            sub["senha"] = sub.get("senha") or ""
            sub["valor"] = float(sub.get("valor") or 0)
            sub["dur_days"] = int(sub.get("dur_days") or long_days)
            if not sub.get("expires_at") or not _sub_is_active(sub):
                sub["start_at"] = now
                sub["expires_at"] = long_exp
                sub["dur_days"] = long_days
            if not sub.get("created_at"):
                sub["created_at"] = now
            subs[idx] = sub
            updated += 1
        else:
            subs.append({
                "email": email,
                "senha": "",
                "plataforma": "Conta vinculada",
                "cliente": "",
                "telefone": "",
                "valor": 0.0,
                "dur_days": long_days,
                "assigned_user": assigned_user,
                "assigned_user_name": assigned_user_name,
                "start_at": now,
                "expires_at": long_exp,
                "created_at": now,
                "show_in_panel": False,
                "renew_pix_txid": None,
                "renew_count": 0,
            })
            created += 1

    save_subscriptions(subs)
    return jsonify({
        "success": True,
        "message": f"Emails vinculados com sucesso ao usuário {assigned_user_name}.",
        "assigned_user": assigned_user,
        "assigned_user_name": assigned_user_name,
        "created": created,
        "updated": updated,
        "invalid": invalid,
        "duplicates": duplicates,
        "skipped": skipped,
        "total": len(emails)
    })


@app.route("/api/admin/vinculos-emails/<path:email>", methods=["DELETE"])
@admin_required
def api_admin_delete_vinculo_email(email):
    email = str(email or "").strip().lower()
    sub, idx = _find_subscription(email)
    if idx < 0:
        return jsonify({"success": False, "message": "Email não encontrado."}), 404
    assigned_user = str((sub or {}).get("assigned_user", "")).strip().lower()
    if assigned_user and not _admin_can_see_assignment(assigned_user):
        return jsonify({"success": False, "message": "Sem permissão para remover este vínculo."}), 403
    subs = load_subscriptions()
    subs.pop(idx)
    save_subscriptions(subs)
    return jsonify({"success": True, "message": "Email removido com sucesso."})


@app.route("/api/admin/assinaturas", methods=["GET"])
@admin_required
def api_admin_list_subscriptions():
    """Lista assinaturas. Por padrão mostra SOMENTE as PAGAS/ATIVAS.
    Use ?all=1 para listar todas (inclusive vencidas)."""
    show_all = request.args.get("all", "") in ("1", "true", "yes")
    subs = load_subscriptions()
    now = int(time.time())
    out = []
    for s in subs:
        if not isinstance(s, dict):
            continue
        if not _admin_can_see_assignment(s.get("assigned_user")):
            continue
        # Contas cadastradas manualmente devem aparecer apenas em Compras.
        # Só renderiza no quadro superior quando houver flag explícita show_in_panel=True.
        if s.get("show_in_panel") is not True:
            continue
        exp = s.get("expires_at") or 0
        active = now < exp
        # Por padrão, só mostra as ATIVAS (pagas)
        if not show_all and not active:
            continue
        s2 = dict(s)
        s2["active"] = active
        s2["days_left"] = max(0, int((exp - now) / 86400)) if exp else 0
        out.append(s2)
    # ordena: as que vencem antes primeiro
    out.sort(key=lambda x: x.get("expires_at", 0))
    return jsonify({"success": True, "subscriptions": out, "default_days": SUB_DEFAULT_DAYS, "renew_value": SUB_RENEW_VALUE})


@app.route("/api/admin/assinaturas", methods=["POST"])
@admin_required
def api_admin_add_subscription():
    """Cadastra uma nova assinatura (conta de streaming com vencimento)."""
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    if not email or "@" not in email:
        return jsonify({"success": False, "message": "Informe um email válido."}), 400
    plataforma = str(data.get("plataforma", "Netflix")).strip()[:40]
    cliente = str(data.get("cliente", "")).strip()[:80]
    telefone = str(data.get("telefone", "")).strip()[:30]
    senha = str(data.get("senha", "")).strip()[:80]  # senha do login da conta
    assigned_user = str(data.get("assigned_user", "")).strip().lower()
    users = load_users()
    if assigned_user and assigned_user not in users:
        return jsonify({"success": False, "message": "Usuário vinculado não encontrado."}), 400
    assigned_user_name = users.get(assigned_user, {}).get("name", assigned_user) if assigned_user else ""
    try:
        valor = float(str(data.get("valor", SUB_RENEW_VALUE)).replace(",", "."))
    except Exception:
        valor = SUB_RENEW_VALUE
    try:
        dur_days = int(data.get("dur_days", SUB_DEFAULT_DAYS))
    except Exception:
        dur_days = SUB_DEFAULT_DAYS
    # data de inicio: agora (ou custom)
    now = int(time.time())
    start_at = now
    # se enviou data de vencimento custom (YYYY-MM-DD), usa o fim do dia
    exp_custom = str(data.get("expires_date", "")).strip()
    if exp_custom:
        try:
            import datetime as _dtmod
            dt = _dtmod.datetime.strptime(exp_custom, "%Y-%m-%d")
            dt = dt.replace(hour=23, minute=59, second=59)
            expires_at = int(dt.timestamp())
        except Exception:
            expires_at = now + dur_days * 86400
    else:
        expires_at = now + dur_days * 86400

    subs = load_subscriptions()
    # não permite cadastrar email repetido
    existing, idx = _find_subscription(email)
    if idx >= 0:
        return jsonify({"success": False, "message": "Este email já está cadastrado."}), 409

    sub = {
        "email": email, "senha": senha, "plataforma": plataforma, "cliente": cliente,
        "telefone": telefone, "valor": valor, "dur_days": dur_days,
        "assigned_user": assigned_user,
        "assigned_user_name": assigned_user_name,
        "start_at": start_at, "expires_at": expires_at,
        "created_at": now,
        "show_in_panel": False,
        "renew_pix_txid": None, "renew_count": 0,
    }
    subs.append(sub)
    save_subscriptions(subs)
    return jsonify({"success": True, "subscription": sub})


@app.route("/api/admin/assinaturas/<path:email>/renovar", methods=["POST"])
@admin_required
def api_admin_renew_subscription(email):
    """Renova manualmente (admin) uma assinatura por +dur_days."""
    sub, idx = _find_subscription(email)
    if idx < 0:
        return jsonify({"success": False, "message": "Assinatura não encontrada."}), 404
    now = int(time.time())
    base = max(now, sub.get("expires_at") or now)  # estende a partir do maior entre agora e vencimento
    dur = sub.get("dur_days", SUB_DEFAULT_DAYS)
    sub["expires_at"] = base + dur * 86400
    sub["renew_count"] = sub.get("renew_count", 0) + 1
    subs = load_subscriptions()
    subs[idx] = sub
    save_subscriptions(subs)
    return jsonify({"success": True, "subscription": sub})


@app.route("/api/admin/assinaturas/<path:email>", methods=["DELETE"])
@admin_required
def api_admin_delete_subscription(email):
    """Remove uma assinatura."""
    subs = load_subscriptions()
    el = (email or "").strip().lower()
    new_subs = [s for s in subs if (s.get("email", "") or "").lower() != el]
    if len(new_subs) == len(subs):
        return jsonify({"success": False, "message": "Não encontrada."}), 404
    save_subscriptions(new_subs)
    return jsonify({"success": True})


# ── RENOVAÇÃO VIA PIX (público — cliente paga e renova sozinho) ──
@app.route("/api/renovar/pix", methods=["POST"])
def api_renovar_pix():
    """Cliente solicita renovação: gera cobrança Pix para a conta vencida."""
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    sub, idx = _find_subscription(email)
    if idx < 0:
        return jsonify({"success": False, "message": "Conta não encontrada no sistema."}), 404
    valor = sub.get("valor", SUB_RENEW_VALUE)
    fake_order = {
        "id": f"RENOV-{int(time.time())}-{email[:8]}",
        "price": valor,
        "product_name": f"Renovacao {sub.get('plataforma','Netflix')} - {email}",
    }
    try:
        pix = efi_create_pix_charge(fake_order)
    except Exception as e:
        pix = {"success": False, "message": f"Erro Efi: {e}"}
    if not pix.get("success"):
        return jsonify({"success": False, "message": pix.get("message", "Erro ao gerar Pix.")}), 502
    # guarda o txid para conferir depois
    sub["renew_pix_txid"] = pix.get("txid")
    sub["renew_order_id"] = fake_order["id"]
    subs = load_subscriptions()
    subs[idx] = sub
    save_subscriptions(subs)
    return jsonify({
        "success": True, "valor": valor,
        "pix_qrcode": pix.get("qrcode_image"),
        "pix_copia_cola": pix.get("copia_cola"),
        "txid": pix.get("txid"),
    })


@app.route("/api/renovar/status", methods=["POST"])
def api_renovar_status():
    """Cliente confere se o Pix de renovação foi pago. Se pago, renova +dur_days."""
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    sub, idx = _find_subscription(email)
    if idx < 0:
        return jsonify({"success": False, "message": "Conta não encontrada."}), 404
    txid = sub.get("renew_pix_txid")
    if not txid:
        return jsonify({"success": False, "paid": False, "message": "Nenhuma renovação pendente."})
    try:
        check = efi_check_pix_status(txid)
    except Exception as e:
        return jsonify({"success": False, "paid": False, "message": f"Erro: {e}"})
    if check.get("paid"):
        now = int(time.time())
        base = max(now, sub.get("expires_at") or now)
        dur = sub.get("dur_days", SUB_DEFAULT_DAYS)
        sub["expires_at"] = base + dur * 86400
        sub["renew_count"] = sub.get("renew_count", 0) + 1
        sub["renew_pix_txid"] = None
        subs = load_subscriptions()
        subs[idx] = sub
        save_subscriptions(subs)
        exp_str = _dt.utcfromtimestamp(sub["expires_at"]).strftime("%d/%m/%Y")
        return jsonify({"success": True, "paid": True, "new_expires": exp_str,
                        "message": f"✅ Renovado! Nova validade: {exp_str}"})
    return jsonify({"success": True, "paid": False, "message": "Pagamento ainda não confirmado."})


# ── COMPRAS AGRUPADAS POR DATA (admin) ──

@app.route("/api/admin/backup-volume", methods=["GET"])
@admin_required
def api_admin_backup_volume():
    """Baixa TODOS os arquivos JSON do volume /data em um unico ZIP.
    Use para clonar a aplicacao em outro projeto Railway."""
    import io as _io, zipfile as _zf, os as _os, datetime as _dt
    try:
        base = _data_dir
        if not _os.path.isdir(base):
            return jsonify({"success": False, "message": f"Diretorio {base} nao existe"}), 500
        buf = _io.BytesIO()
        nomes = []
        with _zf.ZipFile(buf, "w", _zf.ZIP_DEFLATED) as zf:
            for nome in _os.listdir(base):
                caminho = _os.path.join(base, nome)
                if _os.path.isfile(caminho):
                    try:
                        zf.write(caminho, arcname=nome)
                        nomes.append(nome)
                    except Exception:
                        pass
        buf.seek(0)
        ts = _dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        from flask import send_file
        resp = send_file(
            buf,
            mimetype="application/zip",
            as_attachment=True,
            download_name=f"volume-backup-{ts}.zip",
        )
        # adiciona lista dos arquivos no header (debug)
        resp.headers["X-Backup-Files"] = ",".join(nomes)[:500]
        return resp
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro: {e}"}), 500


@app.route("/api/admin/restore-volume", methods=["POST"])
@admin_required
def api_admin_restore_volume():
    """Restaura o volume /data a partir de um ZIP enviado via upload (campo 'file').
    SOBRESCREVE arquivos existentes - use com cuidado. Protegido por admin."""
    import io as _io, zipfile as _zf, os as _os
    try:
        if "file" not in request.files:
            return jsonify({"success": False, "message": "Envie o arquivo ZIP no campo 'file'."}), 400
        upload = request.files["file"]
        if not upload or not upload.filename:
            return jsonify({"success": False, "message": "Arquivo invalido."}), 400
        # le tudo em memoria
        raw = upload.read()
        if not raw:
            return jsonify({"success": False, "message": "ZIP vazio."}), 400
        # confirma com parametro ?confirm=SIM (evita restauracao acidental)
        if request.args.get("confirm", "") != "SIM":
            return jsonify({
                "success": False,
                "message": "Adicione ?confirm=SIM na URL para confirmar a restauracao (sobrescreve arquivos)."
            }), 400
        base = _data_dir
        if not _os.path.isdir(base):
            try:
                _os.makedirs(base, exist_ok=True)
            except Exception as e:
                return jsonify({"success": False, "message": f"Nao foi possivel criar {base}: {e}"}), 500
        restored = []
        skipped = []
        with _zf.ZipFile(_io.BytesIO(raw), "r") as zf:
            for info in zf.infolist():
                nome = _os.path.basename(info.filename)
                if not nome or info.is_dir():
                    skipped.append(info.filename)
                    continue
                # so aceita arquivos .json (seguranca)
                if not nome.lower().endswith(".json"):
                    skipped.append(nome + " (nao .json)")
                    continue
                destino = _os.path.join(base, nome)
                try:
                    with zf.open(info) as src, open(destino, "wb") as dst:
                        dst.write(src.read())
                    restored.append(nome)
                except Exception as e:
                    skipped.append(f"{nome} (erro: {e})")
        return jsonify({
            "success": True,
            "restored": restored,
            "skipped": skipped,
            "data_dir": base,
            "message": f"{len(restored)} arquivo(s) restaurado(s) em {base}. Reinicie o servico (ja recarrega na proxima leitura)."
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro: {e}"}), 500


@app.route("/api/admin/compras-por-data", methods=["GET"])
@admin_required
def api_admin_compras_por_data():
    """Agrupa pedidos online + contas pagas cadastradas manualmente por data."""
    try:
        orders = load_orders()
        clean = [o for o in orders if isinstance(o, dict) and o.get("id")]
        import datetime as _dtmod
        now = int(time.time())
        subs = load_subscriptions()
        subs_idx = {}
        for s in subs:
            if isinstance(s, dict) and s.get("email"):
                subs_idx[s.get("email", "").lower()] = s

        grupos = {}
        linked_emails = set()

        def _add_compra_row(o2, paid_total=0.0):
            ts = o2.get("created_at", 0) or 0
            dia = _dtmod.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d") if ts else "sem-data"
            grupos.setdefault(dia, {"data": dia, "pedidos": [], "total": 0.0, "qtd": 0, "pagos": 0})
            grupos[dia]["pedidos"].append(o2)
            grupos[dia]["qtd"] += 1
            if o2.get("status") == "paid":
                grupos[dia]["pagos"] += 1
                grupos[dia]["total"] += float(paid_total or 0)

        for o in clean:
            o2 = dict(o)
            login_email = o.get("delivered_email") or ""
            login_senha = o.get("delivered_password") or ""
            customer_email = (o.get("customer_email", "") or "").lower()
            sub = subs_idx.get((login_email or "").lower()) or subs_idx.get(customer_email)
            visible_assigned_user = str(o.get("assigned_user", "")).strip().lower()
            if sub and not visible_assigned_user:
                visible_assigned_user = str(sub.get("assigned_user", "")).strip().lower()
            if not visible_assigned_user:
                legacy_owner = str(o.get("customer_name", "")).strip().lower()
                if legacy_owner and legacy_owner in load_users():
                    visible_assigned_user = legacy_owner
            if not _admin_can_see_assignment(visible_assigned_user):
                continue
            reset_at = _get_user_compras_reset_at(visible_assigned_user)
            if reset_at and int(o.get("created_at", 0) or 0) <= reset_at:
                continue
            if sub:
                if not login_email:
                    login_email = sub.get("email", "")
                if not login_senha:
                    login_senha = sub.get("senha", "")
                exp = sub.get("expires_at") or 0
                o2["sub_email"] = sub.get("email", "")
                o2["sub_active"] = now < exp if exp else False
                o2["sub_expires_at"] = exp
                o2["sub_days_left"] = max(0, int((exp - now) / 86400)) if exp else 0
                o2["sub_dur_days"] = sub.get("dur_days", 30)
            else:
                o2["sub_email"] = ""
                o2["sub_active"] = None
                o2["sub_expires_at"] = 0
                o2["sub_days_left"] = 0
                o2["sub_dur_days"] = 30
            o2["login_email"] = login_email
            o2["login_senha"] = login_senha
            o2["manual_entry"] = False
            if login_email:
                linked_emails.add(str(login_email).strip().lower())
            if customer_email:
                linked_emails.add(customer_email)
            _add_compra_row(o2, float(o.get("price", 0) or 0))

        for sub in subs:
            if not isinstance(sub, dict):
                continue
            manual_owner = str(sub.get("assigned_user", "")).strip().lower()
            if not manual_owner:
                legacy_owner = str(sub.get("cliente", "")).strip().lower()
                if legacy_owner and legacy_owner in load_users():
                    manual_owner = legacy_owner
            if not _admin_can_see_assignment(manual_owner):
                continue
            reset_at = _get_user_compras_reset_at(manual_owner)
            created_at = int(sub.get("created_at") or sub.get("start_at") or 0)
            if reset_at and created_at <= reset_at:
                continue
            email_sub = str(sub.get("email", "")).strip().lower()
            if not email_sub or email_sub in linked_emails:
                continue
            exp = sub.get("expires_at") or 0
            manual_row = {
                "product_name": f"{sub.get('plataforma', 'Conta Paga')} (Manual)",
                "customer_name": sub.get("cliente") or sub.get("assigned_user_name") or "Cadastro manual",
                "customer_email": "",
                "created_at": sub.get("created_at") or sub.get("start_at") or 0,
                "status": "paid",
                "price": float(sub.get("valor", 0) or 0),
                "login_email": sub.get("email", ""),
                "login_senha": sub.get("senha", ""),
                "sub_email": sub.get("email", ""),
                "sub_active": now < exp if exp else False,
                "sub_expires_at": exp,
                "sub_days_left": max(0, int((exp - now) / 86400)) if exp else 0,
                "sub_dur_days": sub.get("dur_days", 30),
                "manual_entry": True,
            }
            _add_compra_row(manual_row, manual_row["price"])

        blocos = sorted(grupos.values(), key=lambda g: g["data"], reverse=True)
        for b in blocos:
            b["pedidos"].sort(key=lambda o: o.get("created_at", 0) or 0, reverse=True)
        return jsonify({"success": True, "blocos": blocos})
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro: {e}", "blocos": []})


# ── Endpoints INTERNOS: rios serve dados da Loja 2 para a nova loja vitrine ──
@app.route("/api/internal/loja2/produtos", methods=["GET"])
def api_internal_loja2_produtos():
    token = request.headers.get("X-Loja-Proxy-Token", "")
    if token != LOJA2_PROXY_TOKEN:
        return jsonify({"success": False, "message": "Token inválido."}), 403
    products = load_products2()
    stock = load_stock2()
    result = []
    for p in products:
        items = stock.get(p["id"], [])
        avail = sum(1 for i in items if not i.get("used"))
        result.append({
            "id": p["id"], "name": p["name"], "price": p.get("price", 0),
            "emoji": p.get("emoji", "🛍️"), "color": p.get("color", "#7e22ce"),
            "description": p.get("description", ""),
            "available": avail, "has_stock": avail > 0
        })
    return jsonify({"success": True, "products": result})


def _get_next_stock_item2(product_id):
    """Pega o proximo acesso nao usado da Loja 2 e marca como usado."""
    stock = load_stock2()
    for item in stock.get(product_id, []):
        if not item.get("used"):
            item["used"] = True
            item["used_at"] = int(time.time())
            save_stock2(stock)
            return item
    return None


def _mark_order2_paid_and_deliver(order_id):
    """Marca pedido da Loja 2 como pago e entrega o proximo acesso do estoque."""
    orders = load_orders2()
    order = next((o for o in orders if isinstance(o, dict) and o.get("id") == order_id), None)
    if not order or order.get("status") != "pending":
        return order
    stock_item = _get_next_stock_item2(order.get("product_id"))
    order["status"]  = "paid"
    order["paid_at"] = int(time.time())
    if stock_item:
        order["delivered_email"]    = stock_item.get("email")
        order["delivered_password"] = stock_item.get("password")
        order["delivered_note"]     = stock_item.get("note")
        st = load_stock2()
        for it in st.get(order.get("product_id"), []):
            if isinstance(it, dict) and it.get("id") == stock_item.get("id"):
                it["delivered_to"] = order.get("customer_email")
                it["order_id"]     = order_id
                break
        save_stock2(st)
    else:
        order["delivered_note"] = "Pagamento confirmado. Aguarde - entrega manual."
    save_orders2(orders)
    return order


def _do_checkout2():
    """Checkout da Loja 2 (dados separados). Cria pedido + cobranca Pix."""
    data = request.get_json(silent=True) or {}
    product_id = str(data.get("product_id", "")).strip()
    customer_name  = str(data.get("name", "")).strip()
    customer_email = str(data.get("email", "")).strip().lower()
    customer_phone = str(data.get("phone", "")).strip()
    if not product_id:
        return jsonify({"success": False, "message": "Produto invalido."}), 400
    if not customer_name or not customer_email:
        return jsonify({"success": False, "message": "Informe nome e email."}), 400
    products = load_products2()
    product = next((p for p in products if p["id"] == product_id), None)
    if not product:
        return jsonify({"success": False, "message": "Produto nao encontrado."}), 404
    stock = load_stock2()
    items = stock.get(product_id, [])
    avail = sum(1 for i in items if not i.get("used"))
    if avail <= 0:
        return jsonify({"success": False, "message": "Produto temporariamente sem estoque."}), 409
    order_id = f"L2-{int(time.time())}-{product_id[:6].upper()}"
    order = {
        "id": order_id, "product_id": product_id, "product_name": product["name"],
        "price": product.get("price", 0), "customer_name": customer_name,
        "customer_email": customer_email, "customer_phone": customer_phone,
        "status": "pending", "created_at": int(time.time()), "paid_at": None,
        "delivered_email": None, "delivered_password": None, "delivered_note": None,
        "pix_txid": None, "pix_qrcode": None, "pix_copia_cola": None,
    }
    try:
        pix_data = efi_create_pix_charge(order)
    except Exception as e:
        print(f"[checkout2] excecao efi: {e}")
        pix_data = {"success": False, "message": f"Erro Efi: {e}"}
    if pix_data.get("success"):
        order["pix_txid"]      = pix_data.get("txid")
        order["pix_qrcode"]    = pix_data.get("qrcode_image")
        order["pix_copia_cola"]= pix_data.get("copia_cola")
        order["pix_expires_at"]= pix_data.get("expires_at")
    else:
        order["pix_txid"]    = order_id
        order["pix_warning"] = pix_data.get("message", "Gateway Pix nao configurado.")
    orders = load_orders2()
    orders.append(order)
    save_orders2(orders)
    return jsonify({
        "success": True, "order_id": order_id, "product_name": product["name"],
        "price": product.get("price", 0), "pix_qrcode": order.get("pix_qrcode"),
        "pix_copia_cola": order.get("pix_copia_cola"), "pix_warning": order.get("pix_warning")
    })


LOJA2_MASTER_URL = os.environ.get("LOJA2_MASTER_URL", "https://rios.up.railway.app").rstrip("/")

# Hosts hard-coded reconhecidos como vitrine da Loja 2
_LOJA2_VITRINE_HOSTS = {
    "lojario.up.railway.app",
}

def _is_loja2_vitrine():
    """True se este servico e a loja vitrine 2.
    Detecção: env LOJA2_VITRINE=true OU host contendo 'loja2'/'lojario' OU host na lista."""
    if os.environ.get("LOJA2_VITRINE", "").strip().lower() in ("1", "true", "yes", "sim"):
        return True
    try:
        h = (request.host or "").lower()
        if h in _LOJA2_VITRINE_HOSTS:
            return True
        return ("loja2" in h) or ("lojario" in h)
    except Exception:
        return False

def _proxy_loja2(path, method="GET", json_body=None, params=None):
    """A loja vitrine 2 faz proxy para o rios (servidor central da loja 2)."""
    try:
        import requests
        url = f"{LOJA2_MASTER_URL}{path}"
        headers = {"X-Loja-Proxy-Token": LOJA2_PROXY_TOKEN, "Content-Type": "application/json"}
        if method == "GET":
            r = requests.get(url, headers=headers, params=params, timeout=15)
        else:
            r = requests.post(url, headers=headers, json=json_body or {}, timeout=15)
        try:
            return r.json(), r.status_code
        except Exception:
            return {"success": False, "message": "Resposta invalida do servidor central."}, r.status_code
    except Exception as e:
        return {"success": False, "message": f"Erro ao consultar servidor central: {str(e)[:200]}"}, 502


@app.route("/api/loja2/produtos", methods=["GET"])
def api_loja2_produtos():
    if _is_loja2_vitrine() and not _is_rios_request():
        data, status = _proxy_loja2("/api/internal/loja2/produtos", method="GET")
        return jsonify(data), status
    products = load_products2()
    stock = load_stock2()
    result = []
    for p in products:
        items = stock.get(p["id"], [])
        avail = sum(1 for i in items if not i.get("used"))
        result.append({
            "id": p["id"], "name": p["name"], "price": p.get("price", 0),
            "emoji": p.get("emoji", "\U0001f6cd\ufe0f"), "color": p.get("color", "#7e22ce"),
            "description": p.get("description", ""), "available": avail, "has_stock": avail > 0
        })
    return jsonify({"success": True, "products": result})


@app.route("/api/loja2/checkout", methods=["POST"])
def api_loja2_checkout():
    if _is_loja2_vitrine() and not _is_rios_request():
        data = request.get_json(silent=True) or {}
        result, status = _proxy_loja2("/api/internal/loja2/checkout", method="POST", json_body=data)
        return jsonify(result), status
    try:
        return _do_checkout2()
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro interno: {e}"}), 500


@app.route("/api/internal/loja2/checkout", methods=["POST"])
def api_internal_loja2_checkout():
    token = request.headers.get("X-Loja-Proxy-Token", "")
    if token != LOJA2_PROXY_TOKEN:
        return jsonify({"success": False, "message": "Token invalido."}), 403
    try:
        return _do_checkout2()
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro interno: {e}"}), 500


def _do_meus_pedidos2():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    if not email:
        return jsonify({"success": False, "message": "Informe o email usado na compra."}), 400
    orders = load_orders2()
    my = [o for o in orders if isinstance(o, dict) and (o.get("customer_email", "") or "").lower() == email]
    now = int(time.time())
    for o in my[:20]:
        if o.get("status") == "pending" and o.get("pix_txid") and (now - (o.get("created_at") or 0)) < 7200:
            try:
                check = efi_check_pix_status(o["pix_txid"])
                if check.get("paid"):
                    _mark_order2_paid_and_deliver(o["id"])
            except Exception:
                pass
    orders = load_orders2()
    my = [o for o in orders if isinstance(o, dict) and (o.get("customer_email", "") or "").lower() == email]
    my.sort(key=lambda o: o.get("created_at", 0) or 0, reverse=True)
    return jsonify({"success": True, "orders": my[:20]})


@app.route("/api/loja2/meus-pedidos", methods=["POST"])
def api_loja2_meus_pedidos():
    if _is_loja2_vitrine() and not _is_rios_request():
        data = request.get_json(silent=True) or {}
        result, status = _proxy_loja2("/api/internal/loja2/meus-pedidos", method="POST", json_body=data)
        return jsonify(result), status
    return _do_meus_pedidos2()


@app.route("/api/internal/loja2/meus-pedidos", methods=["POST"])
def api_internal_loja2_meus_pedidos():
    token = request.headers.get("X-Loja-Proxy-Token", "")
    if token != LOJA2_PROXY_TOKEN:
        return jsonify({"success": False, "message": "Token invalido."}), 403
    return _do_meus_pedidos2()


@app.route("/api/loja2/webhook/efi", methods=["POST", "GET"])
@app.route("/api/loja2/webhook/efi/pix", methods=["POST", "GET"])
def api_loja2_webhook_efi():
    if request.method == "GET":
        return jsonify({"success": True}), 200
    data = request.get_json(silent=True) or {}
    for px in data.get("pix", []):
        txid = px.get("txid")
        if not txid:
            continue
        orders = load_orders2()
        order = next((o for o in orders if o.get("pix_txid") == txid), None)
        if order and order["status"] == "pending":
            _mark_order2_paid_and_deliver(order["id"])
    return jsonify({"success": True})



# ─── ROTAS ADMIN: LICENÇAS DE SITES FILHOS (só disponível no MESTRE) ────────────────
def _master_admin_required(f):
    """Decorator: exige admin E que esteja no domínio MESTRE."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"success": False, "message": "Nao autenticado.", "redirect": "/login"}), 401
        if session.get("role") != "admin":
            return jsonify({"success": False, "message": "Acesso restrito ao administrador."}), 403
        if not is_master_host():
            return jsonify({
                "success": False,
                "message": "Gerenciamento de licenças disponível apenas no painel MESTRE."
            }), 403
        return f(*args, **kwargs)
    return decorated

@app.route("/api/admin/licencas", methods=["GET"])
@_master_admin_required
def api_admin_list_licenses():
    """Lista todas as licenças cadastradas."""
    licenses = load_licenses()
    now = int(time.time())
    result = []
    for lic in licenses:
        if not isinstance(lic, dict):
            continue
        out = dict(lic)
        out["status"] = license_status(lic)
        out["days_remaining"] = days_remaining(lic)
        # Por segurança, não devolve senha em texto claro na listagem
        # (mantemos `admin_pass` para o admin master ver/copiar quando precisar)
        result.append(out)
    # ordena por data de criação desc
    result.sort(key=lambda l: l.get("created_at", 0) or 0, reverse=True)
    return jsonify({"success": True, "licenses": result, "now": now, "master_domains": MASTER_DOMAINS})

@app.route("/api/admin/licencas", methods=["POST"])
@_master_admin_required
def api_admin_create_license():
    data = request.get_json(silent=True) or {}
    domain      = _normalize_domain(data.get("domain", ""))
    admin_user  = str(data.get("admin_user", "")).strip().lower()
    admin_pass  = str(data.get("admin_pass", "")).strip()
    dur_days    = int(data.get("duration_days") or 30)
    customer    = str(data.get("customer_name", "")).strip()
    plan_value  = float(str(data.get("plan_value") or 0).replace(",", "."))
    pay_method  = str(data.get("payment_method", "")).strip()
    pay_status  = str(data.get("payment_status", "pendente")).strip()
    notes       = str(data.get("notes", "")).strip()
    assigned_user = str(data.get("assigned_user", "")).strip().lower()
    users = load_users()
    if assigned_user and assigned_user not in users:
        return jsonify({"success": False, "message": "Usuário vinculado não encontrado."}), 400
    assigned_user_name = users.get(assigned_user, {}).get("name", assigned_user) if assigned_user else ""
    start_at    = int(data.get("start_at") or time.time())

    if not domain:
        return jsonify({"success": False, "message": "Informe o domínio do site."}), 400
    if not admin_user or not admin_pass:
        return jsonify({"success": False, "message": "Informe usuário e senha do admin."}), 400
    if dur_days <= 0 or dur_days > 3650:
        return jsonify({"success": False, "message": "Duração inválida (1-3650 dias)."}), 400

    # impede cadastrar domínio do próprio mestre
    if any(domain == _normalize_domain(d) for d in MASTER_DOMAINS):
        return jsonify({"success": False, "message": "Não é possível cadastrar licença para o próprio domínio MESTRE."}), 400

    licenses = load_licenses()
    # impede domínio duplicado
    if any(_normalize_domain((l or {}).get("domain", "")) == domain for l in licenses):
        return jsonify({"success": False, "message": "Já existe licença para este domínio. Use editar."}), 409

    expires_at = compute_expiration(start_at, dur_days)
    lic = {
        "id":              f"LIC-{int(time.time()*1000)}",
        "domain":          domain,
        "customer_name":   customer,
        "admin_user":      admin_user,
        "admin_pass":      admin_pass,
        "duration_days":   dur_days,
        "start_at":        start_at,
        "expires_at":      expires_at,
        "plan_value":      plan_value,
        "payment_method":  pay_method,
        "payment_status":  pay_status,
        "notes":           notes,
        "assigned_user":   assigned_user,
        "assigned_user_name": assigned_user_name,
        "active":          True,
        "created_at":      int(time.time()),
        "created_by":      session.get("username")
    }
    licenses.append(lic)
    save_licenses(licenses)

    # Cria/atualiza usuário admin no banco principal de usuários
    # Importante: o usuário só "funciona" quando a licença estiver ativa
    # (o bloqueio acontece no middleware before_request).
    users = load_users()
    if admin_user not in users:
        users[admin_user] = {
            "password":   generate_password_hash(admin_pass),
            "password_plain": admin_pass,
            "role":       "admin",
            "name":       customer or admin_user,
            "created_by": session.get("username"),
            "license_id": lic["id"],
            "license_domain": domain
        }
    else:
        # atualiza senha mantendo papel
        users[admin_user]["password"]       = generate_password_hash(admin_pass)
        users[admin_user]["password_plain"] = admin_pass
        users[admin_user]["license_id"]     = lic["id"]
        users[admin_user]["license_domain"] = domain
    save_users(users)

    return jsonify({"success": True, "license": lic})

@app.route("/api/admin/licencas/<license_id>", methods=["PUT"])
@_master_admin_required
def api_admin_update_license(license_id):
    data = request.get_json(silent=True) or {}
    licenses = load_licenses()
    lic = next((l for l in licenses if isinstance(l, dict) and l.get("id") == license_id), None)
    if not lic:
        return jsonify({"success": False, "message": "Licença não encontrada."}), 404

    if "customer_name" in data:
        lic["customer_name"] = str(data["customer_name"]).strip()
    if "admin_user" in data:
        new_user = str(data["admin_user"]).strip().lower()
        if new_user:
            lic["admin_user"] = new_user
    if "admin_pass" in data and str(data["admin_pass"]).strip():
        lic["admin_pass"] = str(data["admin_pass"]).strip()
    if "duration_days" in data:
        try:
            lic["duration_days"] = int(data["duration_days"])
        except Exception:
            pass
    if "plan_value" in data:
        try:
            lic["plan_value"] = float(str(data["plan_value"]).replace(",", "."))
        except Exception:
            pass
    if "payment_method" in data:
        lic["payment_method"] = str(data["payment_method"]).strip()
    if "payment_status" in data:
        lic["payment_status"] = str(data["payment_status"]).strip()
    if "notes" in data:
        lic["notes"] = str(data["notes"]).strip()
    if "assigned_user" in data:
        assigned_user = str(data.get("assigned_user", "")).strip().lower()
        users = load_users()
        if assigned_user and assigned_user not in users:
            return jsonify({"success": False, "message": "Usuário vinculado não encontrado."}), 400
        lic["assigned_user"] = assigned_user
        lic["assigned_user_name"] = users.get(assigned_user, {}).get("name", assigned_user) if assigned_user else ""
    if "active" in data:
        lic["active"] = bool(data["active"])
    if "start_at" in data:
        try:
            lic["start_at"] = int(data["start_at"])
        except Exception:
            pass
    # recalcula expiração sempre que mudar duração ou início
    lic["expires_at"] = compute_expiration(lic.get("start_at", time.time()), lic.get("duration_days", 30))

    save_licenses(licenses)

    # sincroniza usuário admin
    users = load_users()
    user_key = lic.get("admin_user")
    if user_key and user_key in users and lic.get("admin_pass"):
        users[user_key]["password"]       = generate_password_hash(lic["admin_pass"])
        users[user_key]["password_plain"] = lic["admin_pass"]
        users[user_key]["license_id"]     = lic["id"]
        users[user_key]["license_domain"] = lic.get("domain")
        save_users(users)

    return jsonify({"success": True, "license": lic})

@app.route("/api/admin/licencas/<license_id>/renovar", methods=["POST"])
@_master_admin_required
def api_admin_renew_license(license_id):
    data = request.get_json(silent=True) or {}
    add_days = int(data.get("days") or 30)
    licenses = load_licenses()
    lic = next((l for l in licenses if isinstance(l, dict) and l.get("id") == license_id), None)
    if not lic:
        return jsonify({"success": False, "message": "Licença não encontrada."}), 404
    now = int(time.time())
    # se já expirou, renova a partir de agora; caso contrário, soma ao final
    base = max(now, int(lic.get("expires_at") or now))
    lic["expires_at"]    = base + add_days * 86400
    lic["duration_days"] = int(lic.get("duration_days", 30)) + add_days
    lic["active"]        = True
    save_licenses(licenses)
    return jsonify({"success": True, "license": lic})

@app.route("/api/admin/licencas/<license_id>/toggle", methods=["POST"])
@_master_admin_required
def api_admin_toggle_license(license_id):
    licenses = load_licenses()
    lic = next((l for l in licenses if isinstance(l, dict) and l.get("id") == license_id), None)
    if not lic:
        return jsonify({"success": False, "message": "Licença não encontrada."}), 404
    lic["active"] = not bool(lic.get("active", True))
    save_licenses(licenses)
    return jsonify({"success": True, "active": lic["active"]})

@app.route("/api/admin/licencas/<license_id>", methods=["DELETE"])
@_master_admin_required
def api_admin_delete_license(license_id):
    licenses = load_licenses()
    new_list = [l for l in licenses if isinstance(l, dict) and l.get("id") != license_id]
    if len(new_list) == len(licenses):
        return jsonify({"success": False, "message": "Licença não encontrada."}), 404
    save_licenses(new_list)
    return jsonify({"success": True})

# ─── BACKUP / RESTORE COMPLETO ───────────────────────────────────────────────
# Permite duplicar todo o projeto para um novo domínio mantendo TUDO

def _read_json_safe(filepath, default=None):
    """Lê um arquivo JSON com fallback seguro."""
    try:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print(f"[backup] erro lendo {filepath}: {e}")
    return default if default is not None else {}

def _count_users(u):
    """Conta usuários independente de ser dict ({username: data}) ou list."""
    if isinstance(u, dict):
        return len(u)
    if isinstance(u, list):
        return len(u)
    return 0

@app.route("/api/admin/backup/export", methods=["GET"])
@admin_required
def api_admin_backup_export():
    """Exporta TODOS os dados do sistema em um único JSON: usuários, produtos,
    estoque, pedidos, licenças. Para usar no /restore em outro projeto.
    """
    try:
        # users.json é um DICT no formato {username: {password, role, name}}
        backup = {
            "version": "1.1",
            "exported_at": int(time.time()),
            "source_host": get_current_host(),
            "is_master_source": is_master_host(),
            "data": {
                "users":     _read_json_safe(USERS_FILE, {}),
                "products":  _read_json_safe(PRODUCTS_FILE, []),
                "stock":     _read_json_safe(STOCK_FILE, {}),
                "orders":    _read_json_safe(ORDERS_FILE, []),
                "licenses":  _read_json_safe(LICENSES_FILE, []),
            }
        }
        backup["summary"] = {
            "users_count":     _count_users(backup["data"]["users"]),
            "products_count":  len(backup["data"]["products"]) if isinstance(backup["data"]["products"], list) else 0,
            "stock_items":     sum(len(v) for v in backup["data"]["stock"].values()) if isinstance(backup["data"]["stock"], dict) else 0,
            "orders_count":    len(backup["data"]["orders"]) if isinstance(backup["data"]["orders"], list) else 0,
            "licenses_count":  len(backup["data"]["licenses"]) if isinstance(backup["data"]["licenses"], list) else 0,
        }
        # Headers para download direto como arquivo
        from flask import Response
        filename = f"backup-{get_current_host().replace('.', '-')}-{int(time.time())}.json"
        return Response(
            json.dumps(backup, ensure_ascii=False, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        import traceback
        return jsonify({"success": False, "message": f"Erro: {e}", "trace": traceback.format_exc()[:500]}), 500

@app.route("/api/admin/backup/import", methods=["POST"])
@admin_required
def api_admin_backup_import():
    """Restaura backup completo. Aceita JSON no body ou arquivo upload.
    Opção 'mode': 'replace' (sobrescreve tudo) ou 'merge' (mescla).
    """
    try:
        mode = request.args.get("mode", "replace").lower()
        backup = None
        # Tenta pegar do body JSON
        if request.is_json:
            backup = request.get_json(silent=True)
        # Ou de arquivo upload
        if not backup and "file" in request.files:
            f = request.files["file"]
            backup = json.loads(f.read().decode("utf-8"))
        # Ou da query string (raw body)
        if not backup:
            raw = request.get_data(as_text=True)
            if raw:
                backup = json.loads(raw)

        if not backup or "data" not in backup:
            return jsonify({"success": False, "message": "Backup inválido: estrutura não reconhecida (esperado JSON com chave 'data')."}), 400

        data = backup["data"]
        result = {"restored": {}}

        # USERS — formato é DICT {username: data} OU lista (compat)
        if "users" in data:
            src = data["users"]
            # Normaliza: se vier como lista, converte para dict
            if isinstance(src, list):
                src_dict = {}
                for u in src:
                    if isinstance(u, dict) and u.get("username"):
                        src_dict[u["username"]] = u
                src = src_dict
            if isinstance(src, dict):
                if mode == "replace":
                    _write_json_file(USERS_FILE, src)
                    result["restored"]["users"] = len(src)
                else:  # merge por username
                    existing = _read_json_safe(USERS_FILE, {})
                    if isinstance(existing, list):
                        # converte lista antiga para dict
                        existing = {u.get("username"): u for u in existing if isinstance(u, dict) and u.get("username")}
                    existing.update(src)
                    _write_json_file(USERS_FILE, existing)
                    result["restored"]["users"] = len(existing)

        # PRODUCTS
        if "products" in data and isinstance(data["products"], list):
            if mode == "replace":
                _write_json_file(PRODUCTS_FILE, data["products"])
                result["restored"]["products"] = len(data["products"])
            else:
                existing = _read_json_safe(PRODUCTS_FILE, [])
                ex_by_id = {p.get("id"): p for p in existing if isinstance(p, dict)}
                for p in data["products"]:
                    if isinstance(p, dict) and p.get("id"):
                        ex_by_id[p["id"]] = p
                _write_json_file(PRODUCTS_FILE, list(ex_by_id.values()))
                result["restored"]["products"] = len(ex_by_id)

        # STOCK
        if "stock" in data and isinstance(data["stock"], dict):
            if mode == "replace":
                _write_json_file(STOCK_FILE, data["stock"])
                result["restored"]["stock_items"] = sum(len(v) for v in data["stock"].values())
            else:
                existing = _read_json_safe(STOCK_FILE, {})
                for prod_id, items in data["stock"].items():
                    if prod_id not in existing:
                        existing[prod_id] = []
                    # Evita duplicar pelo campo 'email' do item
                    ex_emails = {i.get("email") for i in existing[prod_id] if isinstance(i, dict)}
                    for item in items:
                        if isinstance(item, dict) and item.get("email") and item["email"] not in ex_emails:
                            existing[prod_id].append(item)
                            ex_emails.add(item["email"])
                _write_json_file(STOCK_FILE, existing)
                result["restored"]["stock_items"] = sum(len(v) for v in existing.values())

        # ORDERS
        if "orders" in data and isinstance(data["orders"], list):
            if mode == "replace":
                _write_json_file(ORDERS_FILE, data["orders"])
                result["restored"]["orders"] = len(data["orders"])
            else:
                existing = _read_json_safe(ORDERS_FILE, [])
                ex_by_id = {o.get("id"): o for o in existing if isinstance(o, dict)}
                for o in data["orders"]:
                    if isinstance(o, dict) and o.get("id"):
                        ex_by_id[o["id"]] = o
                _write_json_file(ORDERS_FILE, list(ex_by_id.values()))
                result["restored"]["orders"] = len(ex_by_id)

        # LICENSES
        if "licenses" in data and isinstance(data["licenses"], list):
            if mode == "replace":
                _write_json_file(LICENSES_FILE, data["licenses"])
                result["restored"]["licenses"] = len(data["licenses"])
            else:
                existing = _read_json_safe(LICENSES_FILE, [])
                ex_by_id = {l.get("id"): l for l in existing if isinstance(l, dict)}
                for l in data["licenses"]:
                    if isinstance(l, dict) and l.get("id"):
                        ex_by_id[l["id"]] = l
                _write_json_file(LICENSES_FILE, list(ex_by_id.values()))
                result["restored"]["licenses"] = len(ex_by_id)

        # Invalida caches
        try:
            _remote_license_cache.clear()
        except Exception:
            pass

        result["success"] = True
        result["mode"] = mode
        result["source_host"] = backup.get("source_host")
        result["target_host"] = get_current_host()
        return jsonify(result)
    except Exception as e:
        import traceback
        return jsonify({"success": False, "message": f"Erro: {e}", "trace": traceback.format_exc()[:500]}), 500

@app.route("/api/admin/backup/summary", methods=["GET"])
@admin_required
def api_admin_backup_summary():
    """Mostra resumo dos dados atuais sem fazer download."""
    try:
        users    = _read_json_safe(USERS_FILE, {})
        products = _read_json_safe(PRODUCTS_FILE, [])
        stock    = _read_json_safe(STOCK_FILE, {})
        orders   = _read_json_safe(ORDERS_FILE, [])
        licenses = _read_json_safe(LICENSES_FILE, [])
        # Lista de usernames para preview
        users_list = list(users.keys()) if isinstance(users, dict) else [u.get("username") for u in users if isinstance(u, dict)]
        return jsonify({
            "success": True,
            "host": get_current_host(),
            "users_count":     _count_users(users),
            "users_list":      users_list,
            "products_count":  len(products) if isinstance(products, list) else 0,
            "stock_items":     sum(len(v) for v in stock.values()) if isinstance(stock, dict) else 0,
            "orders_count":    len(orders) if isinstance(orders, list) else 0,
            "licenses_count":  len(licenses) if isinstance(licenses, list) else 0,
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/admin/wipe-users", methods=["POST"])
@admin_required
def api_admin_wipe_users():
    """Remove TODOS os usuarios do users.json, exceto os listados em 'keep'.
    Bypassa a regra de 'created_by' - so o admin do sistema deve usar.
    Body JSON: {"keep": ["ceara","outro"], "confirm": "SIM"}
    """
    data = request.get_json(silent=True) or {}
    if data.get("confirm") != "SIM":
        return jsonify({"success": False, "message": "Adicione confirm=SIM no body para confirmar."}), 400
    keep_raw = data.get("keep") or []
    if not isinstance(keep_raw, list):
        return jsonify({"success": False, "message": "Campo 'keep' deve ser uma lista de usernames."}), 400
    keep = {str(u).strip().lower() for u in keep_raw if u}
    # sempre preserva o admin logado para nao ficar trancado fora
    current_admin = session.get("username")
    if current_admin:
        keep.add(str(current_admin).strip().lower())
    users = load_users()
    antes = len(users)
    removidos = []
    novos = {}
    for uname, udata in users.items():
        if str(uname).strip().lower() in keep:
            novos[uname] = udata
        else:
            removidos.append(uname)
    save_users(novos)
    return jsonify({
        "success": True,
        "antes": antes,
        "depois": len(novos),
        "removidos_total": len(removidos),
        "removidos_amostra": removidos[:10],
        "mantidos": list(novos.keys()),
    })




@app.route("/api/admin/migrate-users", methods=["POST"])
@admin_required
def api_admin_migrate_users():
    """Migra usuários de outro domínio para este via HTTP.
    Recebe: { source_url, source_admin_user, source_admin_pass, mode='merge'|'replace' }
    """
    try:
        import requests
        body = request.get_json(silent=True) or {}
        source_url = (body.get("source_url") or "").strip().rstrip("/")
        src_user   = body.get("source_admin_user") or "admin"
        src_pass   = body.get("source_admin_pass") or ""
        mode       = body.get("mode", "merge").lower()

        if not source_url or not src_pass:
            return jsonify({"success": False, "message": "Informe source_url e source_admin_pass."}), 400
        if not source_url.startswith("http"):
            source_url = "https://" + source_url

        # 1) Login no projeto de origem
        sess = requests.Session()
        r = sess.post(f"{source_url}/api/auth/login",
                      json={"username": src_user, "password": src_pass},
                      timeout=15)
        if not r.ok or not r.json().get("success"):
            return jsonify({"success": False, "message": f"Falha ao logar em {source_url}: {r.text[:200]}"}), 400

        # 2) Baixa backup da origem
        r2 = sess.get(f"{source_url}/api/admin/backup/export", timeout=30)
        if not r2.ok:
            return jsonify({"success": False, "message": f"Falha ao baixar backup: HTTP {r2.status_code}"}), 500

        backup = r2.json()
        if "data" not in backup:
            return jsonify({"success": False, "message": "Backup inválido."}), 500
        src_users = backup["data"].get("users", {})
        # Normaliza lista → dict
        if isinstance(src_users, list):
            src_users = {u.get("username"): u for u in src_users if isinstance(u, dict) and u.get("username")}
        if not isinstance(src_users, dict) or not src_users:
            return jsonify({"success": False, "message": f"Nenhum usuário encontrado em {source_url}", "source_users_count": 0}), 200

        # 3) Aplica no destino (este servidor)
        if mode == "replace":
            _write_json_file(USERS_FILE, src_users)
            migrated = len(src_users)
            kept = 0
        else:  # merge
            existing = _read_json_safe(USERS_FILE, {})
            if isinstance(existing, list):
                existing = {u.get("username"): u for u in existing if isinstance(u, dict) and u.get("username")}
            kept = len(existing)
            existing.update(src_users)
            _write_json_file(USERS_FILE, existing)
            migrated = len(existing) - kept

        return jsonify({
            "success": True,
            "source_host": backup.get("source_host"),
            "target_host": get_current_host(),
            "mode": mode,
            "source_users_count": len(src_users),
            "users_kept_in_target": kept,
            "users_added": migrated,
            "final_total": len(_read_json_safe(USERS_FILE, {})),
            "users_migrated": list(src_users.keys()),
        })
    except Exception as e:
        import traceback
        return jsonify({"success": False, "message": f"Erro: {e}", "trace": traceback.format_exc()[:500]}), 500

# ╔═══════════════════════════════════════════════════════════════╗
# ║  WEBHOOK KUKU.LU — recebe emails encaminhados do InstAddr (apenas rios) ║
# ╚═══════════════════════════════════════════════════════════════╝
def _kuku_forward_to_mailbox(to_addr, from_addr, subject, body, original_raw=""):
    """Repassa o email recebido via webhook para a caixa KUKU_FORWARD_TO por SMTP.
    Assim TODOS os emails caem em mestre@ggtv.net.br SEM o limite de 200/dia do kuku.
    """
    if not KUKU_FORWARD_ENABLE or not KUKU_FORWARD_TO:
        return False
    try:
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.utils import formatdate

        # Monta o assunto preservando info do destinatário original
        subj = subject or "(sem assunto)"
        # Corpo: inclui o destinatário original p/ a busca conseguir filtrar
        full_body = body or ""
        if original_raw and original_raw not in full_body:
            full_body = full_body + "\n\n----- Original -----\n" + original_raw
        # Garante que o destinatário original apareça no corpo (p/ filtro por email)
        header_line = f"X-Original-To: {to_addr}\nPara original: {to_addr}\nDe: {from_addr}\n\n"
        full_body = header_line + full_body

        msg = MIMEMultipart()
        msg["From"] = KUKU_SMTP_USER
        msg["To"] = KUKU_FORWARD_TO
        # Reply-To traz o remetente original (netflix etc)
        if from_addr:
            msg["Reply-To"] = from_addr
        msg["Subject"] = subj
        msg["Date"] = formatdate(localtime=True)
        msg.attach(MIMEText(full_body, "plain", "utf-8"))

        if KUKU_SMTP_PORT == 465:
            srv = smtplib.SMTP_SSL(KUKU_SMTP_SERVER, KUKU_SMTP_PORT, timeout=20)
        else:
            srv = smtplib.SMTP(KUKU_SMTP_SERVER, KUKU_SMTP_PORT, timeout=20)
            srv.starttls()
        srv.login(KUKU_SMTP_USER, KUKU_SMTP_PASS)
        srv.sendmail(KUKU_SMTP_USER, [KUKU_FORWARD_TO], msg.as_string())
        srv.quit()
        print(f"[kuku-forward] ✅ repassado p/ {KUKU_FORWARD_TO}: to={to_addr} subj='{subj[:40]}'")
        return True
    except Exception as e:
        print(f"[kuku-forward] erro SMTP: {type(e).__name__}: {e}")
        return False


def _load_kuku_mails():
    return _read_json_safe(KUKU_WEBHOOK_FILE, [])

def _save_kuku_mails(mails):
    try:
        parent = os.path.dirname(KUKU_WEBHOOK_FILE)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(KUKU_WEBHOOK_FILE, "w") as f:
            json.dump(mails, f, ensure_ascii=False)
    except Exception as e:
        print(f"[kuku-webhook] erro salvar: {e}")

@app.route("/api/kuku-webhook", methods=["POST", "GET"])
def api_kuku_webhook():
    """Recebe emails encaminhados do kuku.lu via webhook.
    Aceita JSON, form-data ou query params. Campos flexíveis:
      - to / para / recipient / address  -> destinatário
      - from / de / sender                -> remetente
      - subject / assunto                 -> assunto
      - body / text / html / message      -> corpo
      - token                             -> validação (opcional)
    Armazena os últimos 500 emails para consulta.
    """
    # Coletar dados de qualquer formato
    data = {}
    if request.is_json:
        data = request.get_json(silent=True) or {}
    if not data:
        data = request.form.to_dict() if request.form else {}
    if not data:
        data = request.args.to_dict() if request.args else {}
    # raw body fallback
    raw_body = ""
    try:
        raw_body = request.get_data(as_text=True) or ""
    except Exception:
        pass

    # token opcional
    token = data.get("token") or request.args.get("token") or request.headers.get("X-Webhook-Token", "")
    if KUKU_WEBHOOK_TOKEN and token != KUKU_WEBHOOK_TOKEN:
        # não bloqueia totalmente (kuku pode não mandar token), mas loga
        print(f"[kuku-webhook] token ausente/invalido (recebido: '{token[:10]}')")

    def _pick(*keys):
        for k in keys:
            v = data.get(k)
            if v:
                return str(v)
        return ""

    to_addr  = _pick("to", "para", "recipient", "address", "mailaddr", "endereco").lower()
    from_addr = _pick("from", "de", "sender", "remetente", "username")
    subject  = _pick("subject", "assunto", "titulo", "title")
    body     = _pick("body", "text", "textbody", "html", "message", "conteudo", "content") or raw_body
    original = _pick("originaldata", "original", "raw")

    # ╔═ Formato PADRÃO do kuku.lu: {"content": "#subject#\n#textbody#", "username": "#from#"} ═╗
    # Nesse caso 'content' traz assunto+corpo juntos e não há 'to' nem 'subject' separados.
    content_field = _pick("content")
    if content_field:
        # primeira linha = assunto, resto = corpo
        parts = content_field.split("\n", 1)
        if not subject:
            subject = parts[0].strip()
        if len(parts) > 1 and (not body or body == content_field):
            body = content_field  # mantém tudo para extração
        else:
            body = content_field

    # Se nada veio estruturado, tenta extrair do raw
    if not (to_addr or subject or body):
        body = raw_body

    # ╔═ Tentar achar o destinatário dentro do corpo/raw se não veio em 'to' ═╗
    if not to_addr:
        search_src = f"{body}\n{raw_body}\n{from_addr}"
        # procura padrão 'Para: xxx@yyy' ou qualquer email de domínio descartável conhecido
        m = re.search(r'(?:para|to)[:\s]+([\w\.\+\-]+@[\w\.\-]+)', search_src, re.IGNORECASE)
        if m:
            to_addr = m.group(1).lower()
        else:
            # pega qualquer email que NÃO seja de remetente conhecido (netflix/disney/etc)
            for em in re.findall(r'[\w\.\+\-]+@[\w\.\-]+\.[a-z]+', search_src):
                eml = em.lower()
                if not any(b in eml for b in ["netflix", "disney", "account", "noreply", "no-reply", "info@", "mail2"]):
                    to_addr = eml
                    break

    entry = {
        "to": to_addr,
        "from": from_addr,
        "subject": subject,
        "body": body[:20000],   # limita tamanho
        "received_at": int(time.time()),
    }

    mails = _load_kuku_mails()
    mails.append(entry)
    # mantém só os últimos 500
    if len(mails) > 500:
        mails = mails[-500:]
    _save_kuku_mails(mails)

    # ╔═ REPASSE para mestre@ggtv.net.br (SEM limite de 200/dia) ═╗
    # Roda em thread para não atrasar a resposta ao kuku.lu
    if KUKU_FORWARD_ENABLE:
        def _do_forward():
            _kuku_forward_to_mailbox(to_addr, from_addr, subject, body, original or raw_body)
        try:
            threading.Thread(target=_do_forward, daemon=True).start()
        except Exception as _e:
            print(f"[kuku-webhook] erro thread forward: {_e}")

    # ╔═ MODO DEBUG: salva a ÚLTIMA requisição crua para diagnóstico ═╗
    try:
        debug_info = {
            "received_at": int(time.time()),
            "method": request.method,
            "content_type": request.content_type or "",
            "headers": {k: v for k, v in request.headers.items()},
            "args": request.args.to_dict(),
            "form": request.form.to_dict(),
            "is_json": request.is_json,
            "json_parsed": data if isinstance(data, dict) else {},
            "raw_body": raw_body[:5000],
            "parsed_result": {"to": to_addr, "from": from_addr, "subject": subject, "body": body[:500]},
        }
        dbg_path = os.path.join(os.path.dirname(KUKU_WEBHOOK_FILE), "kuku_webhook_debug.json")
        with open(dbg_path, "w") as f:
            json.dump(debug_info, f, ensure_ascii=False, indent=2)
    except Exception as _e:
        print(f"[kuku-webhook] erro debug: {_e}")

    print(f"[kuku-webhook] ✅ email recebido: to={to_addr} subj='{subject[:40]}'")
    return jsonify({"success": True, "stored": True, "total": len(mails)})

@app.route("/api/admin/kuku-webhook-status", methods=["GET"])
@admin_required
def api_kuku_webhook_status():
    """Mostra os últimos emails recebidos via webhook (diagnóstico)."""
    mails = _load_kuku_mails()
    recent = mails[-15:][::-1]
    return jsonify({
        "total": len(mails),
        "webhook_url": f"https://rios.up.railway.app/api/kuku-webhook?token={KUKU_WEBHOOK_TOKEN}",
        "recent": [{
            "to": m.get("to", ""),
            "from": m.get("from", ""),
            "subject": m.get("subject", "")[:60],
            "received_at": m.get("received_at", 0),
        } for m in recent]
    })

@app.route("/api/admin/kuku-webhook-debug", methods=["GET"])
@admin_required
def api_kuku_webhook_debug():
    """Mostra a ÚLTIMA requisição crua recebida no webhook (para diagnosticar formato)."""
    dbg_path = os.path.join(os.path.dirname(KUKU_WEBHOOK_FILE), "kuku_webhook_debug.json")
    return jsonify(_read_json_safe(dbg_path, {"message": "nenhuma requisição capturada ainda"}))


_last_spam_move = {"ts": 0}

def _maybe_move_spam_async():
    """Dispara mover_spam em thread, no máximo 1x a cada 2 minutos (throttle)."""
    import time as _t
    now = _t.time()
    if now - _last_spam_move["ts"] < 120:
        return
    _last_spam_move["ts"] = now
    accs = get_imap_accounts()
    def _job():
        for acc in accs:
            try:
                _move_spam_to_inbox(acc)
            except Exception as e:
                print(f"[spam-auto] erro: {e}")
    try:
        threading.Thread(target=_job, daemon=True).start()
    except Exception as e:
        print(f"[spam-auto] erro thread: {e}")


def _move_spam_to_inbox(account_cfg, max_msgs=200):
    """Move todos os emails das pastas de spam/junk para a INBOX.
    Retorna (movidos, erro)."""
    moved = 0
    mail = None
    try:
        mail = connect_imap(account_cfg)
        spam_boxes = _get_spam_boxes(mail, account_cfg)
        for sbox in spam_boxes:
            try:
                st, _ = mail.select(sbox)
                if st != "OK":
                    continue
                typ, data = mail.search(None, "ALL")
                if typ != "OK" or not data[0]:
                    continue
                ids = data[0].split()[-max_msgs:]
                if not ids:
                    continue
                id_str = b",".join(ids)
                # COPY para INBOX e marca como deletado na pasta spam
                try:
                    mail.copy(id_str, "INBOX")
                    mail.store(id_str, "+FLAGS", "\\Deleted")
                    mail.expunge()
                    moved += len(ids)
                    print(f"[spam->inbox] movidos {len(ids)} de {sbox}")
                except Exception as ce:
                    print(f"[spam->inbox] erro copiar de {sbox}: {ce}")
            except Exception as se:
                print(f"[spam->inbox] erro pasta {sbox}: {se}")
        _safe_logout(mail)
        return moved, None
    except Exception as e:
        try:
            if mail: _safe_logout(mail)
        except Exception:
            pass
        return moved, f"{type(e).__name__}: {e}"


@app.route("/api/admin/mover-spam", methods=["POST", "GET"])
@admin_required
def api_admin_mover_spam():
    """Move manualmente todos os emails de spam/junk para a INBOX (todas as caixas do host)."""
    total = 0
    detalhes = []
    for acc in get_imap_accounts():
        moved, err = _move_spam_to_inbox(acc)
        total += moved
        detalhes.append({"caixa": acc.get("name"), "movidos": moved, "erro": err})
    return jsonify({"success": True, "total_movidos": total, "detalhes": detalhes})

@app.route("/api/health", methods=["GET"])
def health():
    host = get_current_host()
    is_master = is_master_host()
    is_loja = is_loja_host()
    return jsonify({
        "status": "ok",
        "service": "Central dos Codigos",
        "loja_enabled": True,
        "efi_configured": efi_is_configured(),
        "host": host,
        "is_master": is_master,
        "is_loja": is_loja
    })

@app.route("/api/site-mode", methods=["GET"])
def api_site_mode():
    """Frontend consulta para saber se o site está em modo LOJA (sem login)."""
    return jsonify({
        "is_master": is_master_host(),
        "is_loja": is_loja_host(),
        "is_loja2_vitrine": _is_loja2_vitrine(),
        "host": get_current_host()
    })


@app.route("/api/debug/imap", methods=["GET"])
def api_debug_imap():
    """Debug: mostra estado de todas as caixas IMAP configuradas (admin only)."""
    if not session.get("logged_in") or session.get("role") != "admin":
        return jsonify({"success": False, "message": "Apenas admin."}), 403
    result = []
    accounts = get_imap_accounts()
    for acc in accounts:
        info = {
            "name": acc.get("name"),
            "server": acc.get("server"),
            "user": acc.get("user"),
        }
        mail = None
        try:
            mail = imaplib.IMAP4_SSL(acc["server"], int(acc["port"]), timeout=10)
            mail.login(acc["user"], acc["password"])
            info["login"] = "OK"
            # INBOX count
            sel_st, sel_data = mail.select("INBOX", readonly=True)
            info["inbox_total"] = int(sel_data[0]) if sel_data and sel_data[0] else 0
            # Lista pastas
            st, mbs = mail.list()
            folders = []
            if st == "OK":
                for mb in mbs[:20]:
                    mb_str = mb.decode("utf-8") if isinstance(mb, bytes) else str(mb)
                    folders.append(mb_str[:120])
            info["folders_raw"] = folders
            # Detectar spam boxes
            spam = _get_spam_boxes(mail, acc)
            info["spam_boxes_detected"] = spam
            try: mail.logout()
            except Exception: pass
        except Exception as e:
            info["login"] = f"ERRO: {type(e).__name__}: {str(e)[:200]}"
            try:
                if mail: mail.logout()
            except Exception: pass
        result.append(info)
    return jsonify({"success": True, "accounts": result})

@app.route("/api/keepalive", methods=["GET"])
def api_keepalive():
    """Keep-alive: mantém IMAP conectado e evita cold-start.
    Frontend chama esse endpoint ao carregar a página, antes do usuário buscar.
    """
    try:
        accounts = get_imap_accounts()
        if accounts:
            # Aquece a conexão IMAP (vai para o cache)
            mail = connect_imap(accounts[0])
            return jsonify({"success": True, "imap_ready": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)[:200]})
    return jsonify({"success": True, "imap_ready": False})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(debug=False, host="0.0.0.0", port=port)
