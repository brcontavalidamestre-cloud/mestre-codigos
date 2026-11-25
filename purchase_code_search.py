"""Private read-only IMAP sessions for paid-account streaming code links."""
import imaplib
import time
from datetime import datetime, timedelta, timezone


def make_purchase_code_search(configs, get_accounts, batch_search, fetch_extract, spam_boxes, body_extract):
    def search(user_email, platforms):
        groups = {}
        for platform in platforms:
            cfg = configs.get(platform) or {}
            sender = cfg.get('from_keyword')
            if sender:
                groups.setdefault(sender, {})[platform] = cfg
        found = {};errors = [];successful_accounts = 0
        since = (datetime.now(timezone.utc) - timedelta(days=2)).strftime('%d-%b-%Y')
        started = time.monotonic();seen_accounts = set()
        for account in get_accounts():
            key = (account.get('server'), account.get('user'), account.get('port', 993))
            if key in seen_accounts:
                continue
            seen_accounts.add(key);mail = None
            if time.monotonic() - started > 60:
                break
            try:
                mail = imaplib.IMAP4_SSL(account['server'], int(account.get('port', 993)), timeout=8)
                mail.login(account['user'], account['password']);successful_accounts += 1
                boxes = list(dict.fromkeys(['INBOX'] + list(spam_boxes(mail, account))))
                for sender, group in groups.items():
                    missing = {p: cfg for p,cfg in group.items() if p not in found}
                    seen_ids = set()
                    for box in boxes:
                        if not missing or time.monotonic() - started > 60:
                            break
                        matches = batch_search(mail, box, sender, missing, seen_ids, use_date_filter=True,
                                               since_date=since, max_age_minutes=15, max_emails=120)
                        for mailbox, platform, eid in matches:
                            if platform not in missing:
                                continue
                            code, link = fetch_extract(mail, mailbox, eid, platform, user_email)
                            if code or link:
                                found[platform] = dict(platform=platform, code=code, link=link);missing.pop(platform, None)
                    if not found and time.monotonic() - started < 50:
                        for platform,cfg in list(missing.items()):
                            if not cfg.get('body_keywords'):
                                continue
                            code,link = body_extract(mail,'INBOX',sender,platform,user_email,since_date=since,max_emails=20)
                            if code or link:
                                found[platform] = dict(platform=platform,code=code,link=link)
                if all(platform in found for platform in platforms):
                    break
            except Exception:
                errors.append('Mailbox unavailable')
            finally:
                if mail is not None:
                    try:
                        mail.logout()
                    except Exception:
                        pass
        return [found[p] for p in platforms if p in found], errors if found or not successful_accounts else []
    return search
