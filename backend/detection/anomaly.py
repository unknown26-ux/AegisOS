import numpy as np
from sklearn.ensemble import IsolationForest

def anomaly_score(events):
    if not events: return 0.0
    X=[]
    for e in events:
        X.append([
            1 if e.get('event_type')=='LOGIN_FAILED' else 0,
            1 if e.get('event_type')=='PRIVILEGE_CHANGE' else 0,
            1 if e.get('event_type') in ('SENSITIVE_FILE_ACCESS','DATA_TRANSFER') else 0,
            min(int(e.get('bytes_out',0))/1_000_000_000, 10),
            1 if e.get('country') in {'Russia','China','North Korea'} else 0
        ])
    if len(X)<10: return 0.0
    model=IsolationForest(contamination='auto', random_state=42)
    pred=model.fit_predict(np.array(X))
    return round(float(np.mean(pred==-1)),3)
