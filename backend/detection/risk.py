WEIGHTS = {
    'BRUTE_FORCE':15,'SUSPICIOUS_LOGIN':20,'PRIVILEGE_ESCALATION':25,
    'SENSITIVE_ACCESS':20,'POSSIBLE_EXFILTRATION':30,'SUSPICIOUS_EXECUTION':20
}

def score(alerts, anomaly=0):
    reasons=[]
    total=0
    seen=set()
    for a in alerts:
        t=a['type']
        if t not in seen:
            w=WEIGHTS.get(t,10); total += w; seen.add(t)
            reasons.append({'label':a['reason'],'points':w})
    if anomaly > 0.7:
        total += 10
        reasons.append({'label':'Behavioral anomaly score exceeded 0.70','points':10})
    total=min(100,total)
    severity='CRITICAL' if total>=80 else 'HIGH' if total>=60 else 'MEDIUM' if total>=30 else 'LOW'
    return total,severity,reasons
