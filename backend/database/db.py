import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "aegisos.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = connect()
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        user TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        device TEXT,
        country TEXT,
        action TEXT,
        resource TEXT,
        bytes_out INTEGER DEFAULT 0,
        success INTEGER DEFAULT 1,
        metadata TEXT DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_key TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'OPEN',
        user TEXT,
        source_ip TEXT,
        summary TEXT,
        mitre TEXT DEFAULT '[]',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incident_events (
        incident_id INTEGER,
        event_id INTEGER,
        PRIMARY KEY (incident_id,event_id)
    );
    ''')
    conn.commit()
    conn.close()
