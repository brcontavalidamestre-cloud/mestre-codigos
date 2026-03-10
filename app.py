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
    "netflix": {
        "from_keyword": "netflix.com",
        "subject_keywords": ["digo de acesso"],
        "negative_keywords": ["temporario", "temporário", "temporal", "temporary"],
        "name": "Netflix",
        "type": "code"
    },
    "netflix-login": {
        "from_keyword": "netflix.com",
        "subject_keywords": [
            "digo de in",
            "icio de sess",
            "inicio de sess",
            "código de início",
            "code to sign in",
            "sign in code",
            "sign-in code",
            "login code"
        ],
        "name": "Netflix Login",
        "type": "code"
    },
    "netflix-temp": {
        "from_keyword": "netflix.com",
        "subject_keywords": [
            "acesso tempor",
            "acesso temporário",
            "acesso temporario",
            "código de acesso temporário",
            "temporary access",
            "temp access",
            "acceso temporal",
            "código de acceso temporal",
            "tu código de acceso temporal",
            "codigo de acceso temporal"
        ],
        "name": "Codigo Temporario Netflix",
        "type": "link"
    },
    "disney": {
        "from_keyword": "disneyplus.com",
        "subject_keywords": [
            "digo de acesso",
            "your one-time passcode for disney+"
        ],
        "name": "Disney+",
        "type": "code"
    },
    "netflix-residence": {
        "from_keyword": "netflix.com",
        "subject_keywords": [
            "pediu para atualizar",
            "atualizar sua resid",
            "update your Netflix",
            "Netflix Home",
            "atualizar resid",
            "atualizar"
        ],
        "name": "Residencia Netflix",
        "type": "link"
    },
    "password-reset": {
        "from_keyword": "netflix.com",
        "subject_keywords": [
            "Complete a solicitacao de redefinicao de senha",
            "redefinicao de senha",
            "Completa tu solicitud de restablecimiento de contrasena",
            "restablecimiento de contrasena",
            "Tapusin ang request mong i-reset ang password",
            "reset ang password",
            "reset password",
            "password reset",
            "redefini"
        ],
        "name": "Redefinicao de Senha Netflix",
        "type": "link"
    },
    "disney-residence": {
        "from_keyword": "disneyplus.com",
        "subject_keywords": [
            "Quer atualizar sua Residencia do Disney+",
            "atualizar sua Residencia do Disney",
            "Residencia do Disney",
            "update your Disney+ Home",
            "Disney+ Home"
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
    if user_lower in html_body.lower():
        return True
    for header in ["To", "Delivered-To", "X-Original-To"]:
        if user_lower in decode_str(msg.get(header, "")).lower():
            return True
    return False

def connect_imap():
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(EMAIL_USER, EMAIL_PASS)
    return mail

def search_code(user_email, platform):
    config = PLATFORM_CONFIG.get(platform)
    if not config:
        return None, None, "Plataforma nao suportada."
    try:
        mail = connect_imap()
        from_kw     = config["from_keyword"]
        subj_kws    = config["subject_keywords"]
        result_type = config.get("type", "code")

        # Lista de caixas para pesquisar: INBOX + pasta de Spam/Lixo
        MAILBOXES_TO_SEARCH = ["INBOX", "Spam", "Junk", "SPAM", "JUNK",
                                "[Gmail]/Spam", "[Gmail]/Lixo Eletrônico",
                                "Junk Email", "Bulk Mail", "Lixo Eletronico"]

        # Descobre quais caixas existem neste servidor
        status_list, mailbox_list = mail.list()
        available_boxes = []
        if status_list == "OK":
            for mb in mailbox_list:
                try:
                    mb_str = mb.decode("utf-8") if isinstance(mb, bytes) else str(mb)
                    # Extrai o nome da caixa (ultima parte apos o separador)
                    parts = mb_str.split('"')
                    if len(parts) >= 3:
                        box_name = parts[-2].strip()
                    else:
                        box_name = mb_str.split()[-1].strip('"')
                    available_boxes.append(box_name)
                except Exception:
                    continue

        # Filtra as caixas para pesquisar (INBOX sempre + spam se existir)
        boxes_to_try = ["INBOX"]
        for candidate in MAILBOXES_TO_SEARCH[1:]:  # skip INBOX, ja incluido
            for avail in available_boxes:
                if candidate.lower() == avail.lower():
                    boxes_to_try.append(avail)
                    break

        all_matched = []  # (mailbox, eid) tuples

        for mailbox in boxes_to_try:
            try:
                sel_status, _ = mail.select(mailbox, readonly=True)
                if sel_status != "OK":
                    continue
                status, msgs = mail.search(None, "FROM", from_kw)
                if status != "OK" or not msgs[0]:
                    continue
                all_ids    = msgs[0].split()
                recent_ids = all_ids[-100:]
                recent_ids.reverse()
                for eid in recent_ids:
                    try:
                        status, data = mail.fetch(eid, "(BODY[HEADER.FIELDS (SUBJECT)])")
                        if status != "OK":
                            continue
                        hdr  = email.message_from_bytes(data[0][1])
                        subj = decode_str(hdr.get("Subject", ""))
                        if subject_matches(subj, subj_kws, config.get("negative_keywords")):
                            all_matched.append((mailbox, eid))
                    except Exception:
                        continue
            except Exception:
                continue

        if not all_matched:
            mail.logout()
            return None, None, ("Nenhum email de " + config["name"] + " encontrado. Verifique se o email ja chegou.")

        for mailbox, eid in all_matched:
            try:
                mail.select(mailbox, readonly=True)
                status, data = mail.fetch(eid, "(RFC822)")
                if status != "OK":
                    continue
                msg       = email.message_from_bytes(data[0][1])
                html_body = get_html_body(msg)
                if email_matches_user(msg, html_body, user_email):
                    if result_type == "link":
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
        return None, None, ("Email da conta nao encontrado. Verifique se digitou o email correto.")
    except imaplib.IMAP4.error as e:
        return None, None, "Erro de conexao com servidor de email: " + str(e)
    except Exception as e:
        return None, None, "Erro interno: " + str(e)

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
            "username": uname,
            "name":     udata.get("name", uname),
            "role":     udata.get("role", "client")
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
    code, link, error = search_code(user_email, platform)
    if code:
        return jsonify({"success": True, "code": code, "platform": platform, "type": "code"})
    elif link:
        return jsonify({"success": True, "link": link, "platform": platform, "type": "link"})
    else:
        return jsonify({"success": False, "message": error or "Nao encontrado."})

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "Central dos Codigos"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(debug=False, host="0.0.0.0", port=port)
