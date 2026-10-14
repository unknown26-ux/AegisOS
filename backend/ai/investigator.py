def investigate(incident, events, reasons):
    user=incident.get('user','unknown'); ip=incident.get('source_ip','unknown')
    types=[a['type'] for a in incident.get('alerts',[])]
    title='Possible security incident'
    if 'BRUTE_FORCE' in types and 'PRIVILEGE_ESCALATION' in types: title='Possible account takeover with privilege escalation'
    elif 'POSSIBLE_EXFILTRATION' in types: title='Possible data exfiltration'
    elif 'BRUTE_FORCE' in types: title='Possible brute-force attack'
    elif 'PRIVILEGE_ESCALATION' in types: title='Possible privilege escalation'
    summary=f'{title} involving user {user} and source {ip}. AegisOS correlated multiple security signals instead of treating them as isolated alerts.'
    evidence=[a['reason'] for a in incident.get('alerts',[])]
    recommendations=['Review the affected account and recent authentication history','Revoke active sessions if compromise is suspected','Force a password reset for the affected user','Investigate the source IP and related devices']
    if 'POSSIBLE_EXFILTRATION' in types: recommendations.insert(0,'Preserve outbound-transfer evidence and review accessed data')
    return {'title':title,'bluf':summary,'evidence':evidence,'recommendations':recommendations,'confidence':min(98,70+len(types)*7)}
