# AegisOS
AI-assisted security monitoring and incident response platform for small and medium-sized organizations.

## Features
- Synthetic normal/suspicious/multi-stage security event generation
- Event normalization and SQLite persistence
- Rule-based detection
- Event correlation by user/IP/time window
- Explainable 0-100 risk scoring
- Basic Isolation Forest anomaly detection
- Incident timeline and MITRE ATT&CK mapping
- AI-style investigation summaries and recommendations without requiring an API key
- Simulated response actions
- React dashboard

## Run
### Backend
```bash
cd backend
python -m venv venv
venv\\Scripts\\activate       # Windows
pip install -r requirements.txt
uvicorn main:app --reload
```
Backend: http://127.0.0.1:8000/docs

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Frontend: http://localhost:5173
