from collections import defaultdict
from datetime import datetime

def correlate(events, alerts):
    groups=defaultdict(list)
    for a in alerts:
        key=(a.get('user') or 'unknown', a.get('source_ip') or 'unknown')
        groups[key].append(a)
    incidents=[]
    for (user,ip), rows in groups.items():
        types={r['type'] for r in rows}
        if len(types)>=2 or any(r['severity']=='CRITICAL' for r in rows):
            incidents.append({'user':user,'source_ip':ip,'alerts':rows,'event_ids':sorted({i for r in rows for i in r.get('event_ids',[]) if i})})
    return incidents
