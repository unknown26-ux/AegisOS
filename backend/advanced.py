import asyncio, json, statistics
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from database.db import connect

router = APIRouter(prefix="/api/advanced", tags=["Advanced Lab"])

def ensure_tables():
    c=connect()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS simulator_runs(run_id TEXT PRIMARY KEY, scenario TEXT, seed INTEGER, event_count INTEGER, alert_count INTEGER, incident_count INTEGER, anomaly_score REAL, created_at TEXT);
    CREATE TABLE IF NOT EXISTS behavior_baseline(metric TEXT PRIMARY KEY, value TEXT, trained_at TEXT, sample_count INTEGER);
    CREATE TABLE IF NOT EXISTS response_audit(id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER, action TEXT, target TEXT, status TEXT, approved INTEGER, created_at TEXT, details TEXT);
    """)
    c.commit(); c.close()
ensure_tables()

class ResponseRequest(BaseModel):
    incident_id: int
    action: str
    target: str = ""
    approved: bool = False

@router.get("/runs")
def runs(limit:int=50):
    c=connect(); rows=c.execute("SELECT * FROM simulator_runs ORDER BY created_at DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall(); c.close()
    return [dict(x) for x in rows]

@router.get("/runs/compare")
def compare(first:str, second:str):
    c=connect()
    a=c.execute("SELECT * FROM simulator_runs WHERE run_id=?",(first,)).fetchone()
    b=c.execute("SELECT * FROM simulator_runs WHERE run_id=?",(second,)).fetchone()
    c.close()
    if not a or not b: raise HTTPException(404,"Run not found. Generate new runs after installing this upgrade.")
    a,b=dict(a),dict(b)
    return {"first":a,"second":b,"delta":{"events":b["event_count"]-a["event_count"],"alerts":b["alert_count"]-a["alert_count"],"incidents":b["incident_count"]-a["incident_count"],"anomaly_score":round(b["anomaly_score"]-a["anomaly_score"],4)}}

@router.get("/graph")
def graph(limit:int=250):
    c=connect()
    ev=[dict(x) for x in c.execute("SELECT id,event_type,user,source_ip,device FROM events ORDER BY id DESC LIMIT ?",(max(10,min(limit,1000)),)).fetchall()]
    inc=[dict(x) for x in c.execute("SELECT id,title,severity,user,source_ip FROM incidents ORDER BY id DESC LIMIT 100").fetchall()]
    c.close(); nodes=[]; edges=[]; seen=set()
    def add(k,label,typ):
        if k not in seen: seen.add(k); nodes.append({"id":k,"label":str(label or "Unknown"),"type":typ})
    for e in reversed(ev):
        ek=f"event:{e['id']}"; add(ek,f"{e['event_type']} #{e['id']}","event")
        for field,typ,edge in [("user","user","generated"),("source_ip","ip","source"),("device","device","on device")]:
            if e.get(field):
                k=f"{typ}:{e[field]}"; add(k,e[field],typ)
                edges.append({"source":k if typ!="device" else ek,"target":ek if typ!="device" else k,"label":edge})
    for i in inc:
        ik=f"incident:{i['id']}"; add(ik,f"{i['severity']}: {i['title']}","incident")
        for field,typ in [("user","user"),("source_ip","ip")]:
            k=f"{typ}:{i.get(field)}"
            if i.get(field) and k in seen: edges.append({"source":k,"target":ik,"label":"associated"})
    return {"nodes":nodes,"edges":edges}

@router.post("/baseline/train")
def train():
    c=connect(); rows=[dict(x) for x in c.execute("SELECT event_type,user,bytes_out,success FROM events ORDER BY id DESC LIMIT 5000").fetchall()]
    if len(rows)<10: c.close(); raise HTTPException(400,"Generate at least 10 events first.")
    types={}; users={}; bs=[int(x.get("bytes_out") or 0) for x in rows]
    for x in rows:
        types[x["event_type"]]=types.get(x["event_type"],0)+1
        if x.get("user"): users[x["user"]]=users.get(x["user"],0)+1
    profile={"event_type_frequency":{k:round(v/len(rows),4) for k,v in types.items()},"user_event_counts":users,"mean_bytes_out":statistics.mean(bs),"stdev_bytes_out":statistics.pstdev(bs),"failure_rate":sum(not x["success"] for x in rows)/len(rows)}
    now=datetime.now(timezone.utc).isoformat()
    c.execute("INSERT OR REPLACE INTO behavior_baseline VALUES('profile',?,?,?)",(json.dumps(profile),now,len(rows))); c.commit(); c.close()
    return {"trained":True,"sample_count":len(rows),"trained_at":now,"profile":profile}

@router.get("/baseline")
def baseline():
    c=connect(); r=c.execute("SELECT * FROM behavior_baseline WHERE metric='profile'").fetchone(); c.close()
    return {"trained":False,"message":"Train a baseline first."} if not r else {"trained":True,"trained_at":r["trained_at"],"sample_count":r["sample_count"],"profile":json.loads(r["value"])}

@router.get("/baseline/check")
def baseline_check(limit:int=100):
    c=connect(); r=c.execute("SELECT * FROM behavior_baseline WHERE metric='profile'").fetchone()
    ev=[dict(x) for x in c.execute("SELECT id,event_type,user,source_ip,bytes_out,success FROM events ORDER BY id DESC LIMIT ?",(max(10,min(limit,500)),)).fetchall()]; c.close()
    if not r: raise HTTPException(400,"Train baseline first.")
    p=json.loads(r["value"]); out=[]
    for e in ev:
        reasons=[]; b=int(e.get("bytes_out") or 0)
        if b>max(p["mean_bytes_out"]+3*p["stdev_bytes_out"],500_000_000): reasons.append("Outbound volume far above baseline")
        if e["event_type"] not in p["event_type_frequency"]: reasons.append("Event type absent from training baseline")
        if not e["success"] and p["failure_rate"]<.05: reasons.append("Failure compared with low baseline failure rate")
        if reasons: out.append({"event_id":e["id"],"event_type":e["event_type"],"user":e["user"],"source_ip":e["source_ip"],"reasons":reasons})
    return {"events_checked":len(ev),"deviation_count":len(out),"deviations":out}

@router.get("/stream")
async def stream():
    async def gen():
        last=0
        while True:
            c=connect(); rows=[dict(x) for x in c.execute("SELECT * FROM events WHERE id>? ORDER BY id LIMIT 100",(last,)).fetchall()]; c.close()
            for r in rows:
                last=r["id"]
                try: r["metadata"]=json.loads(r["metadata"] or "{}")
                except Exception: pass
                yield "data: "+json.dumps(r,default=str)+"\\n\\n"
            if not rows: yield ": keep-alive\\n\\n"
            await asyncio.sleep(1)
    return StreamingResponse(gen(),media_type="text/event-stream",headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@router.post("/response")
def response(req:ResponseRequest):
    allowed={"disable_user","block_ip","revoke_sessions","isolate_device","force_password_reset"}
    if req.action not in allowed: raise HTTPException(400,"Unsupported action")
    c=connect(); inc=c.execute("SELECT * FROM incidents WHERE id=?",(req.incident_id,)).fetchone()
    if not inc: c.close(); raise HTTPException(404,"Incident not found")
    status="SIMULATED_EXECUTION" if req.approved else "AWAITING_APPROVAL"
    now=datetime.now(timezone.utc).isoformat()
    target=req.target or inc["user"] or inc["source_ip"]
    c.execute("INSERT INTO response_audit(incident_id,action,target,status,approved,created_at,details) VALUES(?,?,?,?,?,?,?)",(req.incident_id,req.action,target,status,int(req.approved),now,"Simulation only; no real system was modified."))
    c.commit(); c.close()
    return {"status":status,"incident_id":req.incident_id,"action":req.action,"target":target,"message":"SIMULATION ONLY — no real system was changed."}

@router.get("/response/audit")
def audit(limit:int=50):
    c=connect(); rows=c.execute("SELECT * FROM response_audit ORDER BY id DESC LIMIT ?",(max(1,min(limit,200)),)).fetchall(); c.close()
    return [dict(x) for x in rows]
