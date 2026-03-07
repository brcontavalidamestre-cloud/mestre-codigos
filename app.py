from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import imaplib
import email
from email.header import decode_header
import re
import os

app = Flask(__name__, static_folder='static')
CORS(app)

IMAP_SERVER = "imap.hostinger.com"
IMAP_PORT   = 993
EMAIL_USER  = "mestre@codigo.log.br"
EMAIL_PASS  = "Mcodigo10@"

PLATFORM_CONFIG = {
    "netflix": {"from_keyword": "account.netflix.com", "subject_keyword": "digo de acesso", "name": "Netflix"},
    "disney":  {"from_keyword": "disneyplus", "subject_keyword": "digo de acesso", "name": "Disney+"}
}

def decode_str(s):
    if not s: return ""
    parts = decode_header(s)
    result = ""
    for part, enc in parts:
        if isinstance(part, bytes): result += part.decode(enc or "utf-8", errors="ignore")
        else: result += str(part)
    return result

def get_html_body(msg):
    html = ""
    plain = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" in cd: continue
            payload = part.get_payload(decode=True)
            if not payload: continue
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="ignore")
            if ct == "text/html": html += text
            elif ct == "text/plain" and not plain: plain += text
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="ignore")
            if msg.get_content_type() == "text/html": html = text
            else: plain = text
    return html or plain

def extract_code_from_html(html_body):
    m = re.search(r'letter-spacing\s*:\s*[^"\']+["\'][^>]*>\s*([A-Z0-9]{4,8})\s*<', html_body, re.IGNORECASE)
    if m: return m.group(1).strip()
    m = re.search(r'font-size\s*:\s*(?:[3-9]\d|[12]\d\d)px[^>]*>\s*([A-Z0-9]{4,8})\s*<', html_body, re.IGNORECASE)
    if m: return m.group(1).strip()
    m = re.search(r'class=["\'][^"\']*cod[^"\']*["\'][^>]*>\s*([A-Z0-9]{4,8})\s*<', html_body, re.IGNORECASE)
    if m: return m.group(1).strip()
    clean = re.sub(r'<[^>]+>', ' ', html_body)
    clean = re.sub(r'\s+', ' ', clean)
    for pat in [r'c[oó]digo\s*(?:de acesso)?\s*[:\-]?\s*([A-Z0-9]{4,8})', r'access\s*code\s*[:\-]?\s*([A-Z0-9]{4,8})']:
        m = re.search(pat, clean, re.IGNORECASE)
        if m: return m.group(1).strip()
    return None

def search_code(user_email, platform):
    config = PLATFORM_CONFIG.get(platform)
    if not config: return None, "Plataforma não suportada."
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(EMAIL_USER, EMAIL_PASS)
        mail.select("INBOX")
        status, msgs = mail.search(None, "FROM", config["from_keyword"])
        if status != "OK" or not msgs[0]:
            mail.logout()
            return None, "Nenhum email da plataforma encontrado."
        all_ids = msgs[0].split()
        recent_ids = list(reversed(all_ids[-100:]))
        code_email_ids = []
        for eid in recent_ids:
            try:
                status, data = mail.fetch(eid, "(BODY[HEADER.FIELDS (SUBJECT)])")
                if status != "OK": continue
                hdr = email.message_from_bytes(data[0][1])
                subj = decode_str(hdr.get("Subject", ""))
                if config["subject_keyword"].lower() in subj.lower():
                    code_email_ids.append(eid)
            except: continue
        if not code_email_ids:
            mail.logout()
            return None, f"Nenhum email de código {config['name']} encontrado. Solicite o código no app primeiro."
        for eid in code_email_ids:
            try:
                status, data = mail.fetch(eid, "(RFC822)")
                if status != "OK": continue
                msg = email.message_from_bytes(data[0][1])
                html_body = get_html_body(msg)
                if user_email.lower() in html_body.lower():
                    code = extract_code_from_html(html_body)
                    if code:
                        mail.logout()
                        return code, None
            except: continue
        mail.logout()
        return None, f"Email não encontrado nos emails recentes de {config['name']}. Verifique o email e solicite um novo código."
    except imaplib.IMAP4.error as e:
        return None, f"Erro de conexão: {str(e)}"
    except Exception as e:
        return None, f"Erro interno: {str(e)}"

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/get-code", methods=["POST"])
def get_code():
    data = request.get_json(silent=True)
    if not data: return jsonify({"success": False, "message": "Dados inválidos."}), 400
    user_email = data.get("email", "").strip().lower()
    platform   = data.get("platform", "").strip().lower()
    if not user_email: return jsonify({"success": False, "message": "Informe seu email."}), 400
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", user_email): return jsonify({"success": False, "message": "Email inválido."}), 400
    if platform not in PLATFORM_CONFIG: return jsonify({"success": False, "message": "Plataforma não suportada."}), 400
    code, error = search_code(user_email, platform)
    if code: return jsonify({"success": True, "code": code, "platform": platform})
    return jsonify({"success": False, "message": error or "Código não encontrado."})

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "Mestre Códigos"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
