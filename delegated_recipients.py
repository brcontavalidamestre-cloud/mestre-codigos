"""Exact original-recipient extraction shared by central and JMP policies."""
import html
import quopri
import re
from email.utils import getaddresses


def recipients(msg,body=''):
    values=[]
    for name in ('To','Cc','Bcc','Delivered-To','X-Original-To','X-Forwarded-To','Envelope-To','Apparently-To','Resent-To'):
        values.extend(str(value) for value in msg.get_all(name,[]))
    addresses={address.strip().lower() for _,address in getaddresses(values) if address}
    for received in msg.get_all('Received',[]):
        addresses.update(value.lower() for value in re.findall(r"(?i)\bfor\s+<?([a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,})",str(received)))
    texts=[body or '']
    for part in msg.walk():
        if part.get_content_type() in ('text/plain','text/html'):
            payload=part.get_payload(decode=True)
            if payload:
                try:texts.append(payload.decode(part.get_content_charset() or 'utf-8',errors='ignore'))
                except LookupError:texts.append(payload.decode('utf-8',errors='ignore'))
    for text in texts:
        text=html.unescape(quopri.decodestring(text.encode('utf-8')).decode('utf-8',errors='ignore')).lower()
        text=re.sub(r'<(?:br\b[^>]*|/p|/div|/tr)>','\n',text)
        text=re.sub(r'</?[a-z][a-z0-9]*(?:\s[^>]*?)?/?>','',text)
        for line in text.splitlines():
            if re.match(r'^\s*(?:>\s*)?(?:to|para|destinat[aá]rio|delivered-to|x-original-to)\s*:',line):
                addresses.update(re.findall(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}",line))
    return addresses
