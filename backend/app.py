from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
import psutil
import pandas as pd
import requests
import time
import json
import os
import csv
import logging
from pathlib import Path
import numpy as np
from datetime import datetime

# Enhanced imports with proper error handling
try:
    from backend.merged_classifiers import get_classifier, predict_with_stages
    logger = logging.getLogger("ids.app")
    logger.info("Enhanced classifiers loaded successfully")
except ImportError:
    logger = logging.getLogger("ids.app")
    logger.warning("Enhanced classifiers not available, using fallback")
    get_classifier = None
    predict_with_stages = None

try:
    from backend.capture import CaptureThread
    logger.info("Capture module loaded")
except ImportError:
    logger.error("No capture module available")
    CaptureThread = None

try:
    from .settings import SETTINGS
    logger.info("Settings module loaded")
except ImportError:
    logger.warning("Settings module not available")
    # Create fallback settings
    class FallbackSettings:
        mongo_uri = None
        n8n_url = None
        local_logs = "./backend/data/logs.csv"
        local_alerts = "./backend/data/alerts.csv"
        mongo_db = "ids_db"
    SETTINGS = FallbackSettings()

# Global variables
capture_thread = None

# Logging configuration
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# File paths with proper directory structure
BASE_DIR = Path("./backend/data")
BASE_DIR.mkdir(parents=True, exist_ok=True)
IGNORE_FILE = BASE_DIR / "ignored_ips.json"
LOGS_FILE = BASE_DIR / "logs.csv"
ALERTS_FILE = BASE_DIR / "alerts.csv"

IGNORE_IPS = set()

def _load_ignore_file():
    """Load ignored IPs from JSON file"""
    global IGNORE_IPS
    if IGNORE_FILE.exists():
        try:
            with open(IGNORE_FILE, "r") as f:
                data = json.load(f)
                IGNORE_IPS = set(data.get("ignored", []))
                logger.info(f"Loaded {len(IGNORE_IPS)} ignored IPs")
        except Exception as e:
            logger.warning(f"Failed to load ignore file: {e}")
            IGNORE_IPS = set()

def _save_ignore_file():
    """Save ignored IPs to JSON file"""
    try:
        IGNORE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(IGNORE_FILE, "w") as f:
            json.dump({"ignored": list(IGNORE_IPS)}, f)
        logger.info(f"Saved {len(IGNORE_IPS)} ignored IPs")
    except Exception as e:
        logger.error(f"Failed to save ignore file: {e}")

# Load ignore list at up
_load_ignore_file()

# Import modules safely
try:
    from . import capture as capture_mod
except Exception:
    capture_mod = None

try:
    from . import storage as storage_mod
except Exception:
    storage_mod = None

try:
    from . import merged_classifiers as clf_mod
except Exception:
    clf_mod = None

def handle_features(feats: dict):
    """Enhanced callback for captured features with improved error handling"""
    if not feats:
        logger.debug("Empty features received")
        return

    try:
        # Get IPs for filtering
        src_ip = feats.get("SRC_IP", "")
        dst_ip = feats.get("DST_IP", "")

        # Skip ignored IPs
        if src_ip in IGNORE_IPS or dst_ip in IGNORE_IPS:
            logger.debug(f"Ignored flow {src_ip} -> {dst_ip}")
            return

        # Ensure timestamp is present
        if "TIMESTAMP" not in feats:
            feats["TIMESTAMP"] = time.time()

        # Determine direction
        local_ips = capture_thread.local_ips if capture_thread and hasattr(capture_thread, 'local_ips') else set()
        if src_ip in local_ips:
            feats["DIRECTION"] = "outgoing"
        elif dst_ip in local_ips:
            feats["DIRECTION"] = "incoming"
        else:
            feats["DIRECTION"] = "unknown"

        # Log flow to storage
        _log_flow_to_storage(feats)

        # Run classification
        malicious_prob = _classify_flow(feats)
        feats["MALICIOUS_PROB"] = malicious_prob

        # Handle alerts if threshold exceeded
        threshold = float(os.getenv("ALERT_THRESHOLD", "0.905"))
        if malicious_prob >= threshold:
            _handle_alert(feats, malicious_prob)

    except Exception as e:
        logger.error(f"Error in handle_features: {e}")

def clean_dataframe_for_json(df):
    """Clean DataFrame to remove NaN values and ensure JSON compatibility"""
    if df.empty:
        return df
    
    df = df.copy()
    
    # Handle different data types
    for column in df.columns:
        if df[column].dtype in ['float64', 'float32']:
            # Replace NaN in float columns with 0.0
            df[column] = df[column].fillna(0.0)
            # Replace infinity values with large numbers
            df[column] = df[column].replace([np.inf, -np.inf], [999999.0, -999999.0])
        elif df[column].dtype in ['int64', 'int32']:
            # Replace NaN in int columns with 0
            df[column] = df[column].fillna(0)
        else:
            # Replace NaN in string columns with empty string
            df[column] = df[column].fillna('')
    
    return df


def _log_flow_to_storage(feats: dict):
    """Log flow to CSV and MongoDB with proper error handling"""
    try:
        # Get timestamp and convert to readable format
        timestamp_unix = feats.get('TIMESTAMP', time.time())
        timestamp_readable = datetime.fromtimestamp(timestamp_unix).strftime('%d:%m:%y %H:%M:%S')
        # Prepare log entry with readable timestamp
        log_entry = {
            'timestamp': timestamp_readable,  # ← NOW READABLE: "27:09:25 09:35:23"
            'srcip': feats.get('SRC_IP', ''),
            'dstip': feats.get('DST_IP', ''),
            'srcport': feats.get('L4_SRC_PORT', 0),
            'dstport': feats.get('L4_DST_PORT', 0),
            'protocol': feats.get('PROTOCOL', ''),
            'l7proto': feats.get('L7_PROTO', 'UNKNOWN'),
            'inbytes': feats.get('IN_BYTES', 0),
            'outbytes': feats.get('OUT_BYTES', 0),
            'inpkts': feats.get('IN_PKTS', 0),
            'outpkts': feats.get('OUT_PKTS', 0),
            'tcpflags': feats.get('TCP_FLAGS', ''),
            'flowdurationms': feats.get('FLOW_DURATION_MILLISECONDS', 0),
            'direction': feats.get('DIRECTION', 'unknown'),
            'maliciousprob': feats.get('MALICIOUS_PROB', 0.0)
        }

        # Write to CSV
        _write_to_csv(LOGS_FILE, log_entry)
        logger.debug(f"Logged flow: {log_entry['srcip']}->{log_entry['dstip']} at {timestamp_readable}")

        # Try storage module if available
        if storage_mod and hasattr(storage_mod, "log_flow"):
            storage_mod.log_flow(feats)

        # Try MongoDB if available
        _write_to_mongo("logs", log_entry)

    except Exception as e:
        logger.error(f"Failed to log flow: {e}")

def _classify_flow(feats: dict) -> float:
    """Classify flow and return malicious probability"""
    try:
        # Try enhanced prediction first
        if predict_with_stages:
            result = predict_with_stages(feats)
            return result['probability']

        # Fallback to original classifier
        elif clf_mod and hasattr(clf_mod, "CLASSIFIER"):
            # Map enhanced features to original format
            original_feats = {
                'PROTOCOL': feats.get('PROTOCOL', ''),
                'L4_SRC_PORT': feats.get('L4_SRC_PORT', 0),
                'L4_DST_PORT': feats.get('L4_DST_PORT', 0),
                'IN_BYTES': feats.get('IN_BYTES', 0),
                'IN_PKTS': feats.get('IN_PKTS', 0),
                'OUT_BYTES': feats.get('OUT_BYTES', 0),
                'OUT_PKTS': feats.get('OUT_PKTS', 0),
                'FLOW_DURATION_MILLISECONDS': feats.get('FLOW_DURATION_MILLISECONDS', 0),
                'TCP_FLAGS': feats.get('TCP_FLAGS', '')
            }

            import pandas as pd
            X = pd.DataFrame([original_feats])
            probs = clf_mod.CLASSIFIER.predict_proba(X)[0]
            return float(probs[1]) if len(probs) > 1 else float(probs[0])

        else:
            logger.warning("No classifier available")
            return 0.0

    except Exception as e:
        logger.error(f"Classification error: {e}")
        return 0.0

def _handle_alert(feats: dict, malicious_prob: float):
    """Handle alert generation and storage"""
    try:
        if predict_with_stages:
            result = predict_with_stages(feats)
            attack_type = result.get('attack_type', 'unknown')
            detection_method = result.get('detection_method', 'ml_only')
        else:
            attack_type = 'unknown'
            detection_method = 'legacy'
        
        timestamp_unix = feats.get('TIMESTAMP', time.time())
        timestamp_readable = datetime.fromtimestamp(timestamp_unix).strftime('%d:%m:%y %H:%M:%S')
        alert = {
            'timestamp': timestamp_readable,  
            'srcip': feats.get('SRC_IP', ''),
            'dstip': feats.get('DST_IP', ''),
            'srcport': feats.get('L4_SRC_PORT', 0),
            'dstport': feats.get('L4_DST_PORT', 0),
            'protocol': feats.get('PROTOCOL', ''),
            'l7proto': feats.get('L7_PROTO', 'UNKNOWN'),
            'maliciousprob': malicious_prob,
            'confidence': abs(malicious_prob - 0.5) * 2,
            'severity': 'HIGH' if malicious_prob > 0.95 else 'MEDIUM',
            'attack_type': attack_type,
            'direction': feats.get('DIRECTION', 'unknown')
        }

        # Write to CSV
        _write_to_csv(ALERTS_FILE, alert)
        logger.info(f"[ALERT] Suspicious flow detected at {timestamp_readable}: prob={malicious_prob:.3f}")

        # Try storage module if available
        if storage_mod and hasattr(storage_mod, "log_alert"):
            storage_mod.log_alert(alert)

        # Try MongoDB if available
        _write_to_mongo("alerts", alert)

    except Exception as e:
        logger.error(f"Failed to handle alert: {e}")

def _write_to_csv(file_path: Path, data: dict):
    """Write data to CSV file with header management"""
    try:
        file_exists = file_path.exists() and file_path.stat().st_size > 0
        with open(file_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(data.keys()))
            if not file_exists:
                writer.writeheader()
            writer.writerow(data)
    except Exception as e:
        logger.error(f"Failed to write to CSV {file_path}: {e}")

def _write_to_mongo(collection: str, data: dict):
    """Write data to MongoDB if available"""
    try:
        if storage_mod and hasattr(storage_mod, "write_mongo"):
            storage_mod.write_mongo(SETTINGS.mongo_db, collection, data)
    except Exception as e:
        logger.debug(f"MongoDB write failed: {e}")

# FastAPI app initialization
app = FastAPI(title="IDS Backend API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",
        "http://127.0.0.1:8501",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

START_TIME = time.time()

# API Endpoints
@app.get("/interfaces")
def list_interfaces():
    """Return available network interfaces"""
    if capture_mod and hasattr(capture_mod, "list_interfaces"):
        try:
            return {"interfaces": capture_mod.list_interfaces()}
        except Exception:
            pass

    # Fallback: use psutil
    try:
        if_addrs = psutil.net_if_addrs()
        return {"interfaces": list(if_addrs.keys())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/capture/start")
async def start_capture(body: dict = Body(...)):
    """Start packet capture"""
    global capture_thread
    try:
        iface = body.get("interface")
        logger.info(f"DEBUG: Starting capture on interface: {iface}")
        logger.info(f"DEBUG: CaptureThread available: {CaptureThread is not None}")
        if not iface:
            raise HTTPException(status_code=400, detail="No interface specified")

        # Stop existing capture
        if capture_thread:
            try:
                if hasattr(capture_thread, 'stop_capture'):
                    capture_thread.stop_capture()
                else:
                    capture_thread.stop()
            except Exception as e:
                logger.warning(f"Error stopping previous capture: {e}")
            capture_thread = None

        # Create new capture thread
        if CaptureThread:
            logger.info("DEBUG: Creating CaptureThread...")
            capture_thread = CaptureThread(
                iface=iface,
                bpffilter="",
                callback=handle_features
            )
            logger.info("DEBUG: CaptureThread created, starting...")
            capture_thread.start()
            logger.info(f"Started packet capture on {iface}")
            return {"status": "capture started", "interface": iface}
        else:
            raise HTTPException(status_code=500, detail="Capture module not available")

    except Exception as e:
        logger.error(f"DEBUG: Capture start failed: {e}")
        logger.error(f"DEBUG: Error type: {type(e).__name__}")
        import traceback
        logger.error(f"DEBUG: Full traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Failed to start capture: {e}")

@app.post("/capture/stop")
async def stop_capture():
    """Stop packet capture"""
    global capture_thread
    try:
        if capture_thread:
            if hasattr(capture_thread, 'stop_capture'):
                capture_thread.stop_capture()
            else:
                capture_thread.stop()
            capture_thread = None
            logger.info("Stopped packet capture")
        return {"status": "capture stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop capture: {e}")

@app.get("/logs/recent")
def logs_recent(limit: int = 200):
    """Return recent logs with proper NaN handling"""
    limit = max(1, min(limit, 5000))

    if LOGS_FILE.exists() and LOGS_FILE.stat().st_size > 0:
        try:
            df = pd.read_csv(LOGS_FILE, on_bad_lines="skip")
            if df.empty:
                return {"logs": []}
            
            # Clean NaN values before JSON serialization
            df = clean_dataframe_for_json(df)
            
            records = df.tail(limit).to_dict(orient="records")
            records.reverse()
            return {"logs": records}
            
        except Exception as e:
            logger.error(f"Error reading logs CSV: {e}")
            return {"logs": []}

    return {"logs": []}

@app.get("/alerts/recent")  
def alerts_recent(limit: int = 200):
    """Return recent alerts with proper NaN handling"""
    limit = max(1, min(limit, 5000))

    if ALERTS_FILE.exists() and ALERTS_FILE.stat().st_size > 0:
        try:
            df = pd.read_csv(ALERTS_FILE, on_bad_lines="skip")
            if df.empty:
                return {"alerts": []}
            
            # Clean NaN values before JSON serialization
            df = clean_dataframe_for_json(df)
            
            records = df.tail(limit).to_dict(orient="records")
            records.reverse()
            return {"alerts": records}
            
        except Exception as e:
            logger.error(f"Error reading alerts CSV: {e}")
            return {"alerts": []}

    return {"alerts": []}

@app.post("/ignore/add")
def add_ignore_ip(body: dict = Body(...)):
    """Add IP to ignore list"""
    ip = body.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="No IP provided")

    IGNORE_IPS.add(ip)
    _save_ignore_file()
    return {"ignored": list(IGNORE_IPS)}

@app.post("/ignore/remove")
def remove_ignore_ip(body: dict = Body(...)):
    """Remove IP from ignore list"""
    ip = body.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="No IP provided")

    IGNORE_IPS.discard(ip)
    _save_ignore_file()
    return {"ignored": list(IGNORE_IPS)}

@app.get("/ignore/list")
def list_ignore_ips():
    """List ignored IPs"""
    return {"ignored": list(IGNORE_IPS)}

@app.post("/logs/clear")
def clear_logs():
    """Clear logs and alerts CSV files"""
    try:
        for file_path in [LOGS_FILE, ALERTS_FILE]:
            if file_path.exists():
                file_path.unlink()
        return {"ok": True, "message": "Logs cleared"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.get("/model/info")
def model_info():
    """Get enhanced model information"""
    try:
        if get_classifier:
            classifier = get_classifier()
            return {
                "model_type": "two_stage" if getattr(classifier, 'is_enhanced', False) else "single_stage",
                "features_count": len(getattr(classifier, 'feature_order', [])),
                "features": getattr(classifier, 'feature_order', []),
                "enhanced_capabilities": getattr(classifier, 'is_enhanced', False),
                "classifier_available": True
            }
        else:
            return {
                "model_type": "unavailable",
                "enhanced_capabilities": False,
                "classifier_available": False
            }
    except Exception as e:
        return {"error": str(e), "classifier_available": False}

@app.post("/predict/detailed")
async def detailed_prediction(features: dict = Body(...)):
    """Get detailed prediction with stage information"""
    try:
        if predict_with_stages:
            result = predict_with_stages(features)
            return result
        else:
            return {"error": "Enhanced prediction not available"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/status")
def status():
    """Return comprehensive system status"""
    info = {
        "ok": True,
        "uptime": int(time.time() - START_TIME),
        "timestamp": time.time()
    }

    # Model status
    try:
        if get_classifier:
            classifier = get_classifier()
            info["model_loaded"] = True
            info["model_enhanced"] = getattr(classifier, 'is_enhanced', False)
        else:
            info["model_loaded"] = False
            info["model_enhanced"] = False
    except Exception:
        info["model_loaded"] = False
        info["model_enhanced"] = False

    # Capture status
    try:
        capture_running = bool(
            capture_thread and (
                (hasattr(capture_thread, 'is_running') and capture_thread.is_running()) or
                (hasattr(capture_thread, 'thr') and capture_thread.thr and capture_thread.thr.is_alive()) or
                (hasattr(capture_thread, 'sniffer') and capture_thread.sniffer)
            )
        )
        info["capture_running"] = capture_running
    except Exception:
        info["capture_running"] = False

    # Database connectivity
    info["mongo_ok"] = False
    info["n8n_ok"] = False

    if hasattr(SETTINGS, 'mongo_uri') and SETTINGS.mongo_uri:
        try:
            import pymongo
            client = pymongo.MongoClient(SETTINGS.mongo_uri, serverSelectionTimeoutMS=2000)
            client.server_info()
            info["mongo_ok"] = True
        except Exception:
            info["mongo_ok"] = False

    if hasattr(SETTINGS, 'n8n_url') and SETTINGS.n8n_url:
        try:
            r = requests.get(SETTINGS.n8n_url, timeout=2)
            info["n8n_ok"] = r.status_code == 200
        except Exception:
            info["n8n_ok"] = False

    # File system stats
    info["logs_file_exists"] = LOGS_FILE.exists()
    info["alerts_file_exists"] = ALERTS_FILE.exists()
    info["ignore_ips_count"] = len(IGNORE_IPS)

    # Storage module stats
    try:
        if storage_mod and hasattr(storage_mod, "stats"):
            info["storage_stats"] = storage_mod.stats()
    except Exception:
        info["storage_stats"] = {}

    return info
