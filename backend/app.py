# backend/app.py (append or merge into your existing FastAPI app) 
from fastapi import FastAPI, HTTPException 
from fastapi import Body
from fastapi import APIRouter
from fastapi.middleware.cors import CORSMiddleware 
from .settings import SETTINGS
import psutil 
import pandas as pd 
import requests 
import time 
import json 
import os 
import csv
import logging
from pathlib import Path

from backend.capture import CaptureThread
capture_thread = None  # will be created dynamically

# logging config
logger = logging.getLogger("ids.app")
if not logger.handlers:
    # basic config if the application hasn't configured logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

IGNORE_FILE = Path("./backend/data/ignored_ips.json")
IGNORE_IPS = set()

def _load_ignore_file():
    global IGNORE_IPS
    if IGNORE_FILE.exists():
        try:
            with open(IGNORE_FILE, "r") as f:
                data = json.load(f)
                IGNORE_IPS = set(data.get("ignored", []))
        except Exception:
            IGNORE_IPS = set()

def _save_ignore_file():
    IGNORE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(IGNORE_FILE, "w") as f:
        json.dump({"ignored": list(IGNORE_IPS)}, f)

# Load once at startup
_load_ignore_file()


# === Callback for captured features ===
def handle_features(feats: dict):
    if not feats:
        return
    
    # ignore if src or dst IP is in ignore list
    src_ip = feats.get("SRC_IP")
    dst_ip = feats.get("DST_IP")

    # Skip ignored IPs
    if src_ip in IGNORE_IPS or dst_ip in IGNORE_IPS:
        logger.debug(f"Ignored flow {src_ip} -> {dst_ip}")
        return
    
    # Ensure direction is included
    local_ips = capture_thread.local_ips if capture_thread else set()
    if src_ip in local_ips:
        feats["DIRECTION"] = "outgoing"
    elif dst_ip in local_ips:
        feats["DIRECTION"] = "incoming"
    else:
        feats["DIRECTION"] = "unknown"

    # 1. Log to storage or fallback CSV
    if storage_mod and hasattr(storage_mod, "log_flow"):
        storage_mod.log_flow(feats)
    else:
        csv_path = "data/logs.csv"
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)
        with open(csv_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(feats.keys()))
            if f.tell() == 0:
                writer.writeheader()
            writer.writerow(feats)

    # 2. Run classifier
    try:
        if clf_mod and hasattr(clf_mod, "CLASSIFIER"):
            import pandas as pd
            X = pd.DataFrame([feats])
            probs = clf_mod.CLASSIFIER.predict_proba(X)[0]
            malicious_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            feats["MALICIOUS_PROB"] = malicious_prob

            # 3. Raise alert if exceeds threshold
            threshold = float(os.getenv("ALERT_THRESHOLD", "0.85"))
            if malicious_prob >= threshold:
                alert = {**feats, "ALERT": True}
                print(f"[ALERT] Suspicious flow detected: prob={malicious_prob:.3f}")

                # write alert to CSV so /alerts/recent can pick it up
                csv_path = "data/alerts.csv"
                os.makedirs(os.path.dirname(csv_path), exist_ok=True)
                with open(csv_path, "a", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=list(alert.keys()))
                    if f.tell() == 0:
                        writer.writeheader()
                    writer.writerow(alert)

                # write to Mongo if storage exposes write_mongo
                try:
                    if storage_mod and hasattr(storage_mod, "write_mongo"):
                        doc = {
                            "timestamp": alert.get("timestamp", time.time()),
                            "src_ip": alert.get("src_ip"),
                            "dst_ip": alert.get("dst_ip"),
                            "score": alert.get("malicious_prob"),
                            "severity": alert.get("severity"),
                            "details": feats,
                        }
                        storage_mod.write_mongo(getattr(SETTINGS, "mongo_db", "ids_db"), doc)
                except Exception:
                    logger.exception("storage.write_mongo failed")

                # also call storage if available
                if storage_mod and hasattr(storage_mod, "log_alert"):
                    storage_mod.log_alert(alert)
    except Exception as e:
        print(f"[Callback] Classifier error: {e}")


app = FastAPI(title="IDS Backend API (for Streamlit UI)")
            
# allow CORS from Streamlit dev server 
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",
        "http://127.0.0.1:8501",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
) 

# Import existing modules safely 
try: 
    from . import capture as capture_mod 
except Exception: 
    capture_mod = None 
    
try: 
    from . import storage as storage_mod 
except Exception: 
    storage_mod = None 
    
try: 
    from . import classifiers as clf_mod 
except Exception: 
    clf_mod = None 
    
START_TIME = time.time() 

@app.get("/interfaces") 
def list_interfaces(): 
    """Return available network interfaces (uses psutil if capture module doesn't provide).""" 
    if capture_mod and hasattr(capture_mod, "list_interfaces"): 
        try: 
            return {"interfaces": capture_mod.list_interfaces()} 
        except Exception: 
            pass 
    # fallback: use psutil net_if_addrs 
    try: 
        if_addrs = psutil.net_if_addrs() 
        return {"interfaces": list(if_addrs.keys())} 
    except Exception as e: 
        raise HTTPException(status_code=500, detail=str(e)) 
    
@app.post("/capture/start")
async def start_capture(body: dict = Body(...)):
    global capture_thread
    try:
        iface = body.get("interface")
        if not iface:
            raise HTTPException(status_code=400, detail="No interface specified")

        # stop existing thread if already running
        if capture_thread:
            try:
                capture_thread.stop()
            except Exception:
                pass

        # create new capture thread
        capture_thread = CaptureThread(
            iface=iface,
            bpf_filter="",  # you can allow client to send a filter if needed
            callback=handle_features   # or hook into your logging/feature extraction
        )
        capture_thread.start()
        return {"status": "capture started", "interface": iface}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start capture: {e}")
    
@app.post("/capture/stop")
async def stop_capture():
    global capture_thread
    try:
        if capture_thread:
            capture_thread.stop()
            capture_thread = None
        return {"status": "capture stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop capture: {e}")
    

@app.post("/ignore/add")
def add_ignore_ip(body: dict = Body(...)):
    ip = body.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="No IP provided")
    IGNORE_IPS.add(ip)
    _save_ignore_file()
    return {"ignored": list(IGNORE_IPS)}

@app.post("/ignore/remove")
def remove_ignore_ip(body: dict = Body(...)):
    ip = body.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="No IP provided")
    IGNORE_IPS.discard(ip)
    _save_ignore_file()
    return {"ignored": list(IGNORE_IPS)}

@app.get("/ignore/list")
def list_ignore_ips():
    return {"ignored": list(IGNORE_IPS)}

    
@app.get("/logs/recent")
def logs_recent(limit: int = 200):
    """Return recent logs. Uses storage.read_latest_logs if available, else reads CSV fallback."""
    limit = max(1, min(limit, 5000))

    if storage_mod and hasattr(storage_mod, "read_latest_logs"):
        try:
            logs = storage_mod.read_latest_logs(limit=limit)
            return {"logs": logs}
        except Exception as e:
            print(f"[logs_recent] storage_mod error: {e}")

    csv_path = "data/logs.csv"
    if os.path.exists(csv_path) and os.path.getsize(csv_path) > 0:
        try:
            df = pd.read_csv(csv_path, on_bad_lines="skip")  # skip malformed lines
            if df.empty:
                return {"logs": []}
            records = df.tail(limit).to_dict(orient="records")[::-1]
            return {"logs": records}
        except Exception as e:
            print(f"[logs_recent] CSV read error: {e}")
            return {"logs": []}

    return {"logs": []}

@app.get("/alerts/recent") 
def alerts_recent(limit: int = 200): 
    limit = max(1, min(limit, 5000)) 
    if storage_mod and hasattr(storage_mod, "read_latest_alerts"): 
        try: 
            alerts = storage_mod.read_latest_alerts(limit=limit) 
            return {"alerts": alerts} 
        except Exception: 
            pass 
        
    csv_path = "data/alerts.csv" 
    if os.path.exists(csv_path): 
        try: 
            df = pd.read_csv(csv_path, on_bad_lines="skip") 
            records = df.tail(limit).to_dict(orient="records")[::-1] 
            return {"alerts": records} 
        except Exception as e: 
            raise HTTPException(status_code=500, detail=str(e)) 
    return {"alerts": []} 

@app.post("/logs/clear")
def clear_logs():
    """Clear logs and alerts CSV files."""
    for f in [SETTINGS.local_logs, SETTINGS.local_alerts]:
        if os.path.exists(f):
            with open(f, "w") as ff:
                ff.write("")
    return {"ok": True, "message": "Logs cleared"}
    
@app.get("/status")
def status():
    """Return basic health/status info: model loaded, capture running, n8n/mongo connectivity."""
    info = {"ok": True, "uptime": int(time.time() - START_TIME)}
    
    # model path & loaded?
    try:
        if clf_mod and hasattr(clf_mod, "CLASSIFIER"):
            info["model_loaded"] = True
            try:
                info["model_path"] = getattr(clf_mod, "MODEL_PATH", None) or getattr(clf_mod, "model_path", None)
            except Exception:
                info["model_path"] = None
        else:
            info["model_loaded"] = False
    except Exception:
        info["model_loaded"] = False

    # Check Mongo / n8n availability if settings has URIs
    try:
        from .settings import SETTINGS
        mongo_uri = getattr(SETTINGS, "mongo_uri", None)
        n8n_url = getattr(SETTINGS, "n8n_url", None)
        info["mongo_ok"] = False
        info["n8n_ok"] = False
        if mongo_uri:
            import pymongo
            try:
                client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
                client.server_info()
                info["mongo_ok"] = True
            except Exception:
                info["mongo_ok"] = False
        if n8n_url:
            try:
                r = requests.get(n8n_url, timeout=2)
                info["n8n_ok"] = r.status_code == 200
            except Exception:
                info["n8n_ok"] = False
    except Exception:
        info["mongo_ok"] = False
        info["n8n_ok"] = False

    # Add some stats if storage exposes them
    try:
        if storage_mod and hasattr(storage_mod, "stats"):
            info["stats"] = storage_mod.stats()
    except Exception:
        info["stats"] = {}

    # Capture thread status
    try:
        global capture_thread
        info["capture_running"] = bool(
            capture_thread and (
                getattr(capture_thread, "_thr", None) and capture_thread._thr.is_alive()
                or getattr(capture_thread, "_sniffer", None)
            )
        )
    except Exception:
        info["capture_running"] = False

    return info
