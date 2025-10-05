import csv
import os
from typing import Dict, Any
from .settings import SETTINGS
import pymongo

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

# -------------------------
# Define fixed schemas
# -------------------------
LOG_FIELDS = [
    "time", "src_ip", "dst_ip", "srcport", "dstport",
    "protocol", "l7proto", "inbytes", "outbytes", "inpkts", "outpkts",
    "tcpflags", "flowdurationms", "maliciousprob", "direction"
]

ALERT_FIELDS = [
    "time", "src_ip", "dst_ip", "srcport", "dstport",
    "protocol", "l7proto", "maliciousprob", "severity", "details"
]

# -------------------------
# Ignore list (imported from app)
# -------------------------
try:
    from .app import IGNORE_IPS
except Exception:
    IGNORE_IPS = set()


def _ensure_csv(path: str, header: list[str]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)


def _normalize_row(row: Dict[str, Any], fields: list[str]) -> Dict[str, Any]:
    """Fill missing fields with empty values so schema stays consistent."""
    return {field: row.get(field, "") for field in fields}


def _is_ignored(row: Dict[str, Any]) -> bool:
    """Check if row involves an ignored IP."""
    src = row.get("src_ip")
    dst = row.get("dst_ip")
    return (src in IGNORE_IPS) or (dst in IGNORE_IPS)


# -------------------------
# Write helpers
# -------------------------
def write_log_csv(row: Dict[str, Any]):
    if _is_ignored(row):
        return
    _ensure_csv(SETTINGS.local_logs, LOG_FIELDS)
    row = _normalize_row(row, LOG_FIELDS)
    with open(SETTINGS.local_logs, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=LOG_FIELDS).writerow(row)


def write_alert_csv(row: Dict[str, Any]):
    if _is_ignored(row):
        return
    _ensure_csv(SETTINGS.local_alerts, ALERT_FIELDS)
    row = _normalize_row(row, ALERT_FIELDS)
    with open(SETTINGS.local_alerts, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=ALERT_FIELDS).writerow(row)


def write_mongo(db_name, doc):
    if _is_ignored(doc):
        return
    col_name = "alerts" if "SEVERITY" in doc else "logs"
    client = pymongo.MongoClient(SETTINGS.mongo_uri)
    db = client[db_name]
    db[col_name].insert_one(doc)


# -------------------------
# Read helpers
# -------------------------
import pandas as pd

def read_latest_logs(limit=200):
    csv_path = SETTINGS.local_logs
    if not os.path.exists(csv_path):
        return []
    try:
        df = pd.read_csv(csv_path)
    except pd.errors.EmptyDataError:
        return []
    return df.tail(limit).to_dict(orient="records")[::-1]


def read_latest_alerts(limit=200):
    csv_path = SETTINGS.local_alerts
    if not os.path.exists(csv_path):
        return []
    try:
        df = pd.read_csv(csv_path)
    except pd.errors.EmptyDataError:
        return []
    return df.tail(limit).to_dict(orient="records")[::-1]


def stats():
    logs = read_latest_logs(limit=100000)
    alerts = read_latest_alerts(limit=100000)
    total_flows = len(logs)
    total_alerts = len(alerts)
    avg_bps = None  # TODO: compute from in/out_bytes if needed
    return {"total_flows": total_flows, "total_alerts": total_alerts, "avg_bps": avg_bps}
