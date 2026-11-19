import email
from email.utils import getaddresses
from email.header import decode_header, make_header
import unicodedata
from datetime import datetime, timedelta, timezone
import imaplib
import re
import ssl
from concurrent.futures import ThreadPoolExecutor


STATUS_FILTERS = {
    'password-reset': ('redefin', 'restable', 'reset', 'recuperar', 'esqueceu'),
    'residence': ('residencia', 'household', 'domicilio', 'hogar'),
    'temporary': ('temporario', 'temporary', 'temporal'),
    'sign-in': ('inicio de sesion', 'iniciar sesion', 'iniciar sessao', 'inicio de sessao', 'sign-in', 'sign in', 'login', 'entrar', 'acessar'),
    'access': ('codigo', 'code'),
}

def classify(subject):
    try: subject = str(make_header(decode_header(subject or '')))
    except (UnicodeError, ValueError): return None
    normalized = ''.join(c for c in unicodedata.normalize('NFKD', subject.casefold()) if not unicodedata.combining(c))
    normalized = ' '.join(normalized.split())
    for key, terms in STATUS_FILTERS.items():
        if any(term in normalized for term in terms):
            if key != 'password-reset' or any(term in normalized for term in ('senha', 'contrasena', 'password')):
                return key
    return None


def lookup(accounts, address):
    since = datetime.now(timezone.utc) - timedelta(days=30)
    months = 'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()
    day = f'{since.day:02d}-{months[since.month-1]}-{since.year}'
    quoted = '"' + address.replace('\\', '\\\\').replace('"', '\\"') + '"'
    def scan(cfg):
        conn = None
        try:
            conn = imaplib.IMAP4_SSL(cfg['server'], int(cfg['port']), ssl_context=ssl.create_default_context(), timeout=5)
            conn.login(cfg['user'], cfg['password'])
            if conn.select('INBOX', readonly=True)[0] != 'OK': return False, None, {}
            headers = ('TO', 'Delivered-To', 'X-Original-To')
            typ, rows = conn.uid('search', None, 'SINCE', day, 'FROM', '"netflix.com"',
                                 'OR', 'TO', quoted, 'OR', 'HEADER', 'Delivered-To', quoted,
                                 'HEADER', 'X-Original-To', quoted)
            if typ != 'OK': return False, None, {}
            best = None
            by_filter = {}
            ids = (rows[0] or b'').split()
            for i in range(0,len(ids),200):
                typ, parts = conn.uid('fetch', b','.join(ids[i:i+200]), '(INTERNALDATE BODY.PEEK[HEADER.FIELDS (FROM TO DELIVERED-TO X-ORIGINAL-TO SUBJECT)])')
                if typ != 'OK': return False, None, {}
                for part in parts:
                    if not isinstance(part,tuple): continue
                    msg = email.message_from_bytes(part[1])
                    if address not in {a.strip().lower() for _,a in getaddresses([v for h in headers for v in msg.get_all(h,[])])}: continue
                    domains = [a.lower().rpartition('@')[2] for _,a in getaddresses(msg.get_all('From',[]))]
                    if not any(d=='netflix.com' or d.endswith('.netflix.com') for d in domains): continue
                    stamp = re.search(rb'INTERNALDATE "([^"]+)"',part[0])
                    if not stamp: return False, None, {}
                    dt = datetime.strptime(stamp[1].decode().strip(),'%d-%b-%Y %H:%M:%S %z')
                    if dt < since: continue
                    if best is None or dt>best: best=dt
                    category=classify(msg.get('Subject'))
                    if category and (category not in by_filter or dt>by_filter[category]): by_filter[category]=dt
            return True,best,by_filter
        except Exception:
            return False, None, {}
        finally:
            if conn is not None:
                try: conn.logout()
                except Exception: pass
    if not accounts: return {'status':'unavailable','received_at':None}
    with ThreadPoolExecutor(max_workers=min(8,len(accounts))) as pool:
        results=list(pool.map(scan,accounts))
    complete = all(ok for ok,_,_ in results)
    best=max((dt for ok,dt,_ in results if ok and dt),default=None)
    by_filter={}
    for category in STATUS_FILTERS:
        value=max((dates[category] for ok,_,dates in results if ok and category in dates),default=None)
        if value: by_filter[category]=value.isoformat()
    if best:
        return {'status':'received' if complete else 'received_partial','received_at':best.isoformat(),'filters':by_filter}
    return {'status':'not_found' if complete else 'unavailable','received_at':None}
