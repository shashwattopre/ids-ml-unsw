import csv
import os
import time
from typing import Dict, Any
from .settings import SETTINGS

# Optional Mongo support
try:
    from pymongo import MongoClient
except Exception:
    MongoClient = None

_mongo = None
if SETTINGS.mongo_uri and MongoClient:
    try:
        _mongo = MongoClient(SETTINGS.mongo_uri)
    except Exception:
        _mongo = None

def _ensure_csv(path: str, header: list[str]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(header)


def write_log_csv(row: Dict[str, Any]):
    _ensure_csv(SETTINGS.local_logs, list(row.keys()))
    with open(SETTINGS.local_logs, 'a', newline='') as f:
        csv.DictWriter(f, fieldnames=row.keys()).writerow(row)


def write_alert_csv(row: Dict[str, Any]):
    _ensure_csv(SETTINGS.local_alerts, list(row.keys()))
    with open(SETTINGS.local_alerts, 'a', newline='') as f:
        csv.DictWriter(f, fieldnames=row.keys()).writerow(row)


def write_mongo(collection: str, doc: Dict[str, Any]):
    if _mongo:
        try:
            _mongo[SETTINGS.mongo_db][collection].insert_one(doc)
        except Exception:
            pass


# backend/storage.py (append these helpers)
import os
import pandas as pd

def read_latest_logs(limit=200):
    csv_path = os.path.join("backend", "data", "logs.csv")
    if not os.path.exists(csv_path):
        return []
    df = pd.read_csv(csv_path)
    return df.tail(limit).to_dict(orient="records")[::-1]

def read_latest_alerts(limit=200):
    csv_path = os.path.join("backend", "data", "alerts.csv")
    if not os.path.exists(csv_path):
        return []
    df = pd.read_csv(csv_path)
    return df.tail(limit).to_dict(orient="records")[::-1]

def stats():
    # quick stats: counts
    logs = read_latest_logs(limit=100000)
    alerts = read_latest_alerts(limit=100000)
    total_flows = len(logs)
    total_alerts = len(alerts)
    # basic throughput estimate (if fields exist)
    avg_bps = None
    return {"total_flows": total_flows, "total_alerts": total_alerts, "avg_bps": avg_bps}
