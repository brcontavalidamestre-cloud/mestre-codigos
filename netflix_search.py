"""Read-only multi-filter Netflix lookup for individual bearer links only.
Reuse the application's registered subject/body filters and exact-email guard,
but use private IMAP connections so simultaneous clients cannot switch folders
on one shared cached connection.
"""
import imaplib
import time
from datetime import datetime, timedelta, timezone


def make_netflix_batch_search(configs, get_accounts, batch_search, fetch_extract, spam_boxes, body_extract):
    def collect(user_email, platforms):
        allowed = [p for p in platforms if p in configs and configs[p].get('from_keyword') == 'netflix.com']
        found, errors = {}, []
        successful_accounts = 0
        accounts, seen_accounts = [], set()
        for account in get_accounts():
            key = (str(account.get('server', '')).lower(), str(account.get('port', '993')),
                   str(account.get('user', '')).lower(), account.get('password', ''))
            if key not in seen_accounts:
                seen_accounts.add(key)
                accounts.append(account)
        if not accounts:
            return [], ['No mailbox configured']
        since = (datetime.now(timezone.utc) - timedelta(days=2)).strftime('%d-%b-%Y')
        started = time.monotonic()
        for account in accounts:
            mail = None
            try:
                if time.monotonic() - started > 60:
                    errors.append('Lookup time limit reached')
                    break
                mail = imaplib.IMAP4_SSL(account['server'], int(account.get('port', 993)), timeout=8)
                mail.login(account['user'], account['password'])
                successful_accounts += 1
                boxes = ['INBOX']
                for box in spam_boxes(mail, account):
                    if box and box not in boxes:
                        boxes.append(box)
                missing = {key: configs[key] for key in allowed if key not in found}
                seen_ids = set()
                for box in boxes:
                    if not missing or time.monotonic() - started > 60:
                        break
                    matched = batch_search(mail, box, 'netflix.com', missing, seen_ids,
                                           use_date_filter=True, since_date=since,
                                           max_age_minutes=15, max_emails=120)
                    for mailbox, platform, eid in matched:
                        if time.monotonic() - started > 60:
                            break
                        if platform not in missing:
                            continue
                        code, link = fetch_extract(mail, mailbox, eid, platform, user_email)
                        if code or link:
                            found[platform] = {'platform': platform, 'code': code, 'link': link}
                            missing.pop(platform, None)
                # Preserve the existing body-keyword fallback for forwarded codes.
                if not found and time.monotonic() - started < 50:
                    for platform, cfg in list(missing.items()):
                        if not cfg.get('body_keywords'):
                            continue
                        code, link = body_extract(mail, 'INBOX', 'netflix.com', platform, user_email,
                                                  since_date=since, max_emails=20)
                        if code or link:
                            found[platform] = {'platform': platform, 'code': code, 'link': link}
                if len(found) == len(allowed):
                    break
            except Exception:
                # Never expose server names, usernames, passwords, or IMAP details.
                errors.append('Mailbox lookup failed')
            finally:
                if mail is not None:
                    try:
                        mail.logout()
                    except Exception:
                        pass
        # One unavailable legacy mailbox must not turn an otherwise empty,
        # successful lookup in the configured mailboxes into a service error.
        return [found[p] for p in allowed if p in found], errors if found or not successful_accounts else []
    return collect
