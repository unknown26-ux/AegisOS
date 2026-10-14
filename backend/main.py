from advanced import router as advanced_router
import json, uuid
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database.db import connect, init_db
from models.schemas import EventIn, SimulateRequest, ResponseAction
from simulator.generator import generate
from detection.rules import detect
from detection.correlation import correlate
from detection.risk import score
from detection.anomaly import anomaly_score
from ai.investigator import investigate

app=FastAPI(title='AegisOS API', version='1.0.0')
app.include_router(advanced_router)
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])
init_db()

def save_events(events):
    conn=connect(); ids=[]
    for e in events:
        cur=conn.execute('''INSERT INTO events(timestamp,event_type,user,source_ip,destination_ip,device,country,action,resource,bytes_out,success,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
        (e['timestamp'],e['event_type'],e.get('user'),e.get('source_ip'),e.get('destination_ip'),e.get('device'),e.get('country'),e.get('action'),e.get('resource'),e.get('bytes_out',0),int(e.get('success',True)),json.dumps(e.get('metadata',{}))))
        ids.append(cur.lastrowid)
    conn.commit(); conn.close()
    for e,i in zip(events,ids): e['id']=i
    return events

def process(events):
    alerts=detect(events)
    anomaly=anomaly_score(events)
    incidents=correlate(events,alerts)
    created=[]
    conn=connect()
    for group in incidents:
        risk,severity,reasons=score(group['alerts'],anomaly)
        key=f"{group['user']}|{group['source_ip']}|{datetime.now().strftime('%Y%m%d%H%M')}"
        summary=investigate(group,events,reasons)['bluf']
        mitre=[]
        types={a['type'] for a in group['alerts']}
        if 'BRUTE_FORCE' in types: mitre.append('T1110 - Brute Force')
        if 'SUSPICIOUS_LOGIN' in types: mitre.append('T1078 - Valid Accounts')
        if 'PRIVILEGE_ESCALATION' in types: mitre.append('T1068 - Exploitation for Privilege Escalation')
        if 'POSSIBLE_EXFILTRATION' in types: mitre.append('T1041 - Exfiltration Over C2 Channel')
        try:
            cur=conn.execute('''INSERT INTO incidents(incident_key,title,severity,risk_score,status,user,source_ip,summary,mitre,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)''',
            (key,'; '.join(sorted(types)),severity,risk,'OPEN',group['user'],group['source_ip'],summary,json.dumps(mitre),datetime.now(timezone.utc).isoformat()))
            iid=cur.lastrowid
            for eid in group['event_ids']:
                conn.execute('INSERT OR IGNORE INTO incident_events(incident_id,event_id) VALUES(?,?)',(iid,eid))
            created.append({'id':iid,'title':'; '.join(sorted(types)),'severity':severity,'risk_score':risk,'status':'OPEN','user':group['user'],'source_ip':group['source_ip'],'summary':summary,'mitre':mitre,'reasons':reasons})
        except Exception:
            pass
    conn.commit(); conn.close()
    return {'events_created':len(events),'alerts':alerts,'anomaly_score':anomaly,'incidents':created}

@app.get('/api/health')
def health(): return {'status':'ok','service':'AegisOS'}

@app.post('/api/events')
def create_event(e:EventIn):
    saved=save_events([e.model_dump()]); result=process(saved); return {'event':saved[0],'analysis':result}

@app.get('/api/events')
def list_events(limit:int=200):
    conn=connect(); rows=[dict(r) for r in conn.execute('SELECT * FROM events ORDER BY id DESC LIMIT ?', (min(limit,1000),)).fetchall()]; conn.close(); return rows


@app.post('/api/simulator/generate')
def simulator(req: SimulateRequest):
    run_id = str(uuid.uuid4())
    rows = generate(req.scenario, req.count, req.seed)

    for index, event in enumerate(rows):
        event.setdefault('metadata', {})
        event['metadata']['run_id'] = run_id
        event['metadata']['run_index'] = index

    saved = save_events(rows)
    result = process(saved)

    return {
        'run_id': run_id,
        'scenario': req.scenario,
        'seed': req.seed,
        'events_created': len(saved),
        'alerts_detected': len(result['alerts']),
        'incidents_created': len(result['incidents']),
        'anomaly_score': result['anomaly_score'],
        'alerts': result['alerts'],
        'incidents': result['incidents'],
    }

@app.get('/api/incidents')
def list_incidents():
    conn=connect(); rows=[dict(r) for r in conn.execute('SELECT * FROM incidents ORDER BY id DESC').fetchall()]; conn.close()
    for r in rows: r['mitre']=json.loads(r['mitre'] or '[]')
    return rows

@app.get('/api/incidents/{incident_id}')
def incident_detail(incident_id:int):
    conn=connect(); inc=conn.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
    if not inc: return {'error':'Incident not found'}
    data=dict(inc); data['mitre']=json.loads(data['mitre'] or '[]')
    events=[dict(r) for r in conn.execute('SELECT e.* FROM events e JOIN incident_events ie ON e.id=ie.event_id WHERE ie.incident_id=? ORDER BY e.timestamp',(incident_id,)).fetchall()]
    conn.close()
    alerts=detect(events); group={'user':data['user'],'source_ip':data['source_ip'],'alerts':alerts}
    return {**data,'events':events,'investigation':investigate(group,events,[]) }

@app.post('/api/incidents/{incident_id}/response')
def response_action(incident_id:int, req:ResponseAction):
    return {'incident_id':incident_id,'action':req.action,'mode':'SIMULATION','message':f'{req.action.replace("_"," ").title()} would be executed in a connected environment. No real system was modified.'}

@app.get('/api/metrics')
def metrics():
    conn=connect()
    total=conn.execute('SELECT COUNT(*) c FROM events').fetchone()['c']; incidents=conn.execute('SELECT COUNT(*) c FROM incidents').fetchone()['c']; critical=conn.execute("SELECT COUNT(*) c FROM incidents WHERE severity='CRITICAL'").fetchone()['c']; open_i=conn.execute("SELECT COUNT(*) c FROM incidents WHERE status='OPEN'").fetchone()['c'];
    conn.close(); return {'events':total,'incidents':incidents,'critical':critical,'open_incidents':open_i,'users':5}
