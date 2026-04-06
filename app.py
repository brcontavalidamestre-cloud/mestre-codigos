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

PLATFORM_CONFIG = {
    # ── NETFLIX: código de acesso (PT/EN/ES) ──────────────────────────────────
    "netflix": {
        "from_keyword": "netflix.com",
        "subject_keywords": [
            # Português
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
            # Inglês
            "temporary access",
            "temp access",
            "your temporary access",
            "netflix temporary code",
            # Espanhol
            "acceso temporal",
            "código de acceso temporal",
            "tu código de acceso temporal",
            "codigo de acceso temporal",
            "acceso temporal de netflix"
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
        "name": "Disney+",
        "type": "code"
    },
    # ── MAX: código único ──────────────────────────────────────────────────────
    "max": {
        "from_keyword": "max.com",
        "subject_keywords": [
            # Português
            "seu código único",
            "seu codigo unico",
            # Inglês
            "your unique code",
            "your max unique code",
            "your verification code",
            # Espanhol
            "tu código único",
            "tu codigo unico",
            "tu código único de max",
            "tu codigo unico de max"
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

def subject_matches(subject, keywords, negative_keywords=None):
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
    # 1. Dígitos separados por espaço/nbsp dentro de span/td estilizado (ex: "0 4 6 4")
    m = re.search(
        r"letter-spacing[^>]{0,200}>\s*((?:[0-9]\s*){4,8})<",
        html_body, re.IGNORECASE | re.DOTALL
    )
    if m:
        code = re.sub(r"\s+", "", m.group(1)).strip()
        if code.isdigit() and 4 <= len(code) <= 8:
            return code

    # 2. Dígitos em fonte grande (só numérico)
    m = re.search(
        r"font-size\s*:\s*(?:[3-9]\d|[12]\d\d)px[^>]*>\s*((?:[0-9]\s*){4,8})\s*<",
        html_body, re.IGNORECASE
    )
    if m:
        code = re.sub(r"\s+", "", m.group(1)).strip()
        if code.isdigit():
            return code

    # 3. Qualquer elemento com letter-spacing que contenha SOMENTE dígitos
    for m in re.finditer(
        r"letter-spacing[^>]{0,300}>\s*((?:[0-9][\s\u00a0]*){4,8})\s*<",
        html_body, re.IGNORECASE | re.DOTALL
    ):
        candidate = re.sub(r"[\s\u00a0]+", "", m.group(1)).strip()
        if candidate.isdigit() and 4 <= len(candidate) <= 8:
            return candidate

    # 4. Texto limpo — padrões semânticos
    clean = re.sub(r"<[^>]+>", " ", html_body)
    clean = re.sub(r"\s+", " ", clean)
    patterns_text = [
        r"c[o\u00f3]digo\s*(?:de acesso)?\s*[:\-]?\s*([0-9]{4,8})",
        r"access\s*code\s*[:\-]?\s*([0-9]{4,8})",
        r"\b([0-9]{4,8})\b(?=\s*(?:é seu|é o seu|para entrar|para acessar|es tu|es el))",
        r"\b([0-9]{4})\b",
    ]
    for pat in patterns_text:
        m = re.search(pat, clean, re.IGNORECASE)
        if m:
            return m.group(1).strip()
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
        # Botão "Receber código" no email de acesso temporário
        patterns = [
            r'href=["\'](https://www\.netflix\.com/[^"\' ]*(?:temporary|tempor|receive|receber|acesso)[^"\' ]*)["\']',
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
_spam_boxes_cache = None

def connect_imap():
    """Conecta ao IMAP com timeout um pouco maior e sem vazar socket auxiliar."""
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT, timeout=20)
    try:
        mail.sock.settimeout(20)
    except Exception:
        pass
    mail.login(EMAIL_USER, EMAIL_PASS)
    return mail


def _safe_logout(mail):
    """Encerra a sessão IMAP sem deixar exceções de timeout vazarem ao usuário."""
    try:
        if mail is not None:
            mail.logout()
    except Exception:
        pass

def _get_spam_boxes(mail):
    """Descobre caixas de spam uma única vez e armazena em cache."""
    global _spam_boxes_cache
    if _spam_boxes_cache is not None:
        return _spam_boxes_cache
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
        _spam_boxes_cache = result
    except Exception:
        _spam_boxes_cache = []
    return _spam_boxes_cache

FWD_PREFIXES_SEARCH = ["ENC:", "FW:", "Fwd:"]
FWD_PREFIXES_STRIP  = ["ENC:", "FW:", "FWD:", "RES:", "ENC: ", "FW: "]

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
                            subj_clean = subj3
                            for pfx in FWD_PREFIXES_STRIP:
                                if subj_clean.upper().startswith(pfx.upper()):
                                    subj_clean = subj_clean[len(pfx):].strip()
                                    break
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
                if not any(subj_upper.startswith(pfx.upper()) for pfx in FWD_PREFIXES_STRIP):
                    idx += 1
                    continue
                subj_clean = subj
                for pfx in FWD_PREFIXES_STRIP:
                    if subj_clean.upper().startswith(pfx.upper()):
                        subj_clean = subj_clean[len(pfx):].strip()
                        break
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
    Usa batch-fetch de headers → muito mais rápido que N chamadas sequenciais.
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

    try:
        mail = connect_imap()
        today     = _dt.utcnow().strftime("%d-%b-%Y")
        since_2d  = (_dt.utcnow() - _td(days=2)).strftime("%d-%b-%Y")
        spam_boxes = _get_spam_boxes(mail)
        seen_ids   = set()

        for sender, plat_configs in by_sender.items():
            # 1ª tentativa: INBOX hoje
            matched = _batch_search_mailbox(
                mail, "INBOX", sender, plat_configs, seen_ids,
                use_date_filter=True, since_date=today)

            # 2ª tentativa: INBOX 48h
            if not matched:
                matched = _batch_search_mailbox(
                    mail, "INBOX", sender, plat_configs, seen_ids,
                    use_date_filter=True, since_date=since_2d)

            # 3ª tentativa: INBOX sem filtro
            if not matched:
                matched = _batch_search_mailbox(
                    mail, "INBOX", sender, plat_configs, seen_ids,
                    use_date_filter=False)

            # 4ª tentativa: spam
            if not matched:
                for mb in spam_boxes:
                    matched.extend(_batch_search_mailbox(
                        mail, mb, sender, plat_configs, seen_ids,
                        use_date_filter=False))
                    if matched:
                        break

            # matched já vem do mais recente para o mais antigo
            found_result = None
            for mb, plat_key, eid in matched:
                code, link = _fetch_and_extract(mail, mb, eid, plat_key, user_email)
                if code or link:
                    found_result = (code, link, plat_key)
                    break

            if found_result:
                _safe_logout(mail)
                return found_result[0], found_result[1], found_result[2], None

            # 5ª tentativa: busca direcionada por SUBJECT para password-reset / netflix-residence
            # Necessária porque emails raros ou encaminhados podem sair do top recente
            # OU o top conter emails de outros clientes que não correspondem ao user_email digitado.
            targeted_platforms = []
            if "password-reset" in plat_configs:
                targeted_platforms.append(("password-reset", ["redefini", "password", "reset", "restablec", "i-reset"]))
            if "netflix-residence" in plat_configs:
                targeted_platforms.append(("netflix-residence", ["residencia", "atualizar", "household", "hogar", "importante"]))

            if targeted_platforms:
                # Usa uma conexão nova só para a fase direcionada.
                # Isso evita que um socket já cansado/expirado derrube a consulta inteira.
                _safe_logout(mail)
                mail = connect_imap()
                spam_boxes = _get_spam_boxes(mail)

            for target_plat, targeted_terms in targeted_platforms:
                since_7d = (_dt.utcnow() - _td(days=7)).strftime("%d-%b-%Y")
                targeted_matches = []

                # 5a. emails diretos do remetente oficial
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

                # 5b. fallback forte para emails encaminhados (ENC:/FW:/Fwd:)
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
        return None, None, None, "Nenhum email encontrado para este endereco."
    except imaplib.IMAP4.error as e:
        _safe_logout(locals().get("mail"))
        return None, None, None, "Erro de conexao com servidor de email: " + str(e)
    except Exception as e:
        _safe_logout(locals().get("mail"))
        if "timed out object" in str(e).lower() or "timed out" in str(e).lower():
            return None, None, None, "Tempo de consulta excedido no servidor de email. Tente novamente."
        return None, None, None, "Erro interno: " + str(e)


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
            "username":      uname,
            "name":          udata.get("name", uname),
            "role":          udata.get("role", "client"),
            "reset_pin_set": bool(udata.get("reset_pin"))
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
    """Define ou remove o PIN de 4 dígitos que protege acesso à redefinição de senha."""
    username = username.strip().lower()
    current_admin = session.get("username")
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Dados invalidos."}), 400

    action = data.get("action", "set")   # "set" ou "remove"
    users  = load_users()

    if username not in users:
        return jsonify({"success": False, "message": "Usuario nao encontrado."}), 404
    if users[username].get("created_by") != current_admin and username != current_admin:
        return jsonify({"success": False, "message": "Sem permissao."}), 403

    if action == "remove":
        users[username].pop("reset_pin", None)
        save_users(users)
        return jsonify({"success": True, "message": "Bloqueio removido."})

    pin = str(data.get("pin", "")).strip()
    if not re.match(r"^\d{4}$", pin):
        return jsonify({"success": False, "message": "PIN deve ter exatamente 4 digitos numericos."}), 400

    users[username]["reset_pin"] = generate_password_hash(pin)
    save_users(users)
    return jsonify({"success": True, "message": "PIN de bloqueio definido com sucesso."})


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

    stored_pin = user.get("reset_pin")
    if not stored_pin:
        # Sem PIN configurado no momento da verificação: libera o link pendente do servidor.
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

    if not re.match(r"^\d{4}$", pin):
        return jsonify({"success": False, "message": "PIN invalido."}), 400

    if not check_password_hash(stored_pin, pin):
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
    """Informa se o usuario logado precisa de PIN para redefinicao de senha."""
    username = session.get("username")
    users    = load_users()
    user     = users.get(username, {})
    return jsonify({
        "locked": bool(user.get("reset_pin")),
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
                users = load_users()
                user = users.get(username, {})
                if user.get("reset_pin"):
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
            users = load_users()
            user = users.get(username, {})
            if user.get("reset_pin"):
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

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "Central dos Codigos"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(debug=False, host="0.0.0.0", port=port)
