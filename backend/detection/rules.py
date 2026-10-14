from collections import defaultdict
from datetime import datetime, timedelta


def dt(x):
    return datetime.fromisoformat(x.replace('Z','+00:00'))


def detect(events):
    alerts = []
    by_user = defaultdict(list)
    by_ip = defaultdict(list)
    for e in events:
        by_user[e.get('user')].append(e)
        by_ip[e.get('source_ip')].append(e)

    for user, rows in by_user.items():
        rows = sorted(rows, key=lambda x: dt(x['timestamp']))
        for i, e in enumerate(rows):
            start = dt(e['timestamp'])
            window = [r for r in rows if start - timedelta(minutes=5) <= dt(r['timestamp']) <= start + timedelta(minutes=5)]
            failed = [r for r in window if r['event_type'] == 'LOGIN_FAILED']
            if len(failed) >= 5:
                alerts.append({'type':'BRUTE_FORCE','severity':'HIGH','event_ids':[r['id'] for r in window if r.get('id')], 'user':user, 'source_ip':e.get('source_ip'), 'reason':f'{len(failed)} failed logins within 5 minutes'})
                break

    for user, rows in by_user.items():
        rows = sorted(rows, key=lambda x: dt(x['timestamp']))
        for i,e in enumerate(rows):
            if e['event_type'] == 'LOGIN_SUCCESS' and e.get('country') in {'Russia','China','North Korea'}:
                alerts.append({'type':'SUSPICIOUS_LOGIN','severity':'HIGH','event_ids':[e.get('id')], 'user':user, 'source_ip':e.get('source_ip'), 'reason':'Successful login from a high-risk/unusual country'})
            if e['event_type'] == 'PRIVILEGE_CHANGE' and e.get('action') == 'USER_TO_ADMIN':
                alerts.append({'type':'PRIVILEGE_ESCALATION','severity':'CRITICAL','event_ids':[e.get('id')], 'user':user, 'source_ip':e.get('source_ip'), 'reason':'User account changed to administrator'})
            if e['event_type'] == 'SENSITIVE_FILE_ACCESS':
                alerts.append({'type':'SENSITIVE_ACCESS','severity':'HIGH','event_ids':[e.get('id')], 'user':user, 'source_ip':e.get('source_ip'), 'reason':'Sensitive resource accessed'})
            if e['event_type'] == 'DATA_TRANSFER' and e.get('bytes_out',0) > 500_000_000:
                alerts.append({'type':'POSSIBLE_EXFILTRATION','severity':'CRITICAL','event_ids':[e.get('id')], 'user':user, 'source_ip':e.get('source_ip'), 'reason':'Outbound transfer exceeded 500 MB'})
            if e['event_type'] == 'PROCESS_EXECUTION' and e.get('action') == 'SUSPICIOUS_COMMAND':
                alerts.append({'type':'SUSPICIOUS_EXECUTION','severity':'HIGH','event_ids':[e.get('id')], 'user':user, 'source_ip':e.get('source_ip'), 'reason':'Suspicious process execution detected'})
    return alerts
