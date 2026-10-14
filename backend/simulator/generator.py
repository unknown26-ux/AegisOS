
from datetime import datetime, timedelta, timezone
import random
import uuid

USERS = ["rahul", "priya", "arjun", "neha", "admin"]
DEVICES = ["LAPTOP-01", "LAPTOP-02", "DESKTOP-04", "SERVER-01"]
SENSITIVE = [
    "employee_salary.xlsx",
    "customer_db.sql",
    "finance_report.xlsx",
    "password_vault.db",
]


def event(ts, typ, user, ip, device, country="India",
          action=None, resource=None, bytes_out=0, success=True):
    return {
        "timestamp": ts.isoformat(),
        "event_type": typ,
        "user": user,
        "source_ip": ip,
        "destination_ip": "10.0.0.20",
        "device": device,
        "country": country,
        "action": action,
        "resource": resource,
        "bytes_out": bytes_out,
        "success": success,
        "metadata": {},
    }


def generate(scenario="multi_stage", count=100, seed=None):
    count = max(10, min(int(count), 1000))
    rng = random.Random(seed)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    rows = []

    if scenario == "normal":
        for i in range(count):
            t = now - timedelta(seconds=count - i)
            user = rng.choice(USERS[:-1])
            ip = f"10.0.0.{rng.randint(10, 80)}"
            typ = rng.choice([
                "LOGIN_SUCCESS", "FILE_ACCESS",
                "DNS_QUERY", "APPLICATION_ACCESS"
            ])
            rows.append(event(
                t, typ, user, ip, rng.choice(DEVICES),
                resource="internal-app" if typ == "APPLICATION_ACCESS" else None
            ))

    elif scenario in ("brute_force", "account_takeover", "multi_stage"):
        user, ip, device = "rahul", "185.23.91.21", "LAPTOP-99"

        for i in range(8):
            rows.append(event(
                now - timedelta(minutes=5, seconds=(8-i)*10),
                "LOGIN_FAILED", user, ip, device, "Russia",
                "AUTH_FAILURE", success=False
            ))

        if scenario != "brute_force":
            rows.append(event(
                now - timedelta(minutes=2), "LOGIN_SUCCESS",
                user, ip, device, "Russia", "AUTH_SUCCESS"
            ))

        if scenario in ("account_takeover", "multi_stage"):
            rows.append(event(
                now - timedelta(minutes=1, seconds=30),
                "PRIVILEGE_CHANGE", user, ip, device, "Russia",
                "USER_TO_ADMIN"
            ))
            rows.append(event(
                now - timedelta(minutes=1),
                "SENSITIVE_FILE_ACCESS", user, ip, device, "Russia",
                "READ", rng.choice(SENSITIVE)
            ))
            rows.append(event(
                now - timedelta(seconds=30),
                "DATA_TRANSFER", user, ip, device, "Russia",
                "UPLOAD", "sensitive-data", 750_000_000
            ))

        while len(rows) < count:
            rows.append(event(
                now - timedelta(seconds=rng.randint(1, 600)),
                "LOGIN_SUCCESS", rng.choice(USERS[:-1]),
                f"10.0.0.{rng.randint(10, 80)}",
                rng.choice(DEVICES), "India", "AUTH_SUCCESS"
            ))

    elif scenario == "privilege_escalation":
        for i in range(count):
            t = now - timedelta(seconds=count-i)
            typ = "PRIVILEGE_CHANGE" if i % 8 == 0 else "LOGIN_SUCCESS"
            rows.append(event(
                t, typ, rng.choice(USERS[:-1]),
                f"10.0.0.{rng.randint(10, 80)}",
                rng.choice(DEVICES), "India",
                "USER_TO_ADMIN" if typ == "PRIVILEGE_CHANGE" else "AUTH_SUCCESS"
            ))

    elif scenario == "exfiltration":
        for i in range(count):
            t = now - timedelta(seconds=count-i)
            transfer = i >= int(count * 0.7)
            rows.append(event(
                t,
                "DATA_TRANSFER" if transfer else "FILE_ACCESS",
                "neha", "10.0.0.45", "LAPTOP-02",
                "India", "UPLOAD" if transfer else "READ",
                "sensitive-data" if transfer else None,
                rng.randint(600, 900) * 1_000_000 if transfer else 0
            ))

    # Give every event a stable position in the generated run.
    rows.sort(key=lambda e: e["timestamp"])
    return rows[:count]
