# backend/app.py (append or merge into your existing FastAPI app) 
from fastapi import FastAPI, HTTPException 
from fastapi.middleware.cors import CORSMiddleware 
import psutil 
import pandas as pd 
import requests 
import time 
import json 
import os 

app = FastAPI(title="IDS Backend API (for Streamlit UI)")

# allow CORS from Streamlit dev server 
app.add_middleware( CORSMiddleware, 
                   allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"], 
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
def capture_start(payload: dict): 
    iface = payload.get("interface") 
    if not iface: 
        raise HTTPException(status_code=400, detail="interface required") 
    if capture_mod and hasattr(capture_mod, "start_capture"): 
        try: 
            capture_mod.start_capture(iface) 
            return {"ok": True, "started": iface} 
        except Exception as e: 
            raise HTTPException(status_code=500, detail=str(e)) 
    else: 
        raise HTTPException(status_code=501, detail="capture module start_capture not implemented") 
    
@app.post("/capture/stop") 
def api_stop_capture(): 
    if capture_mod and hasattr(capture_mod, "stop_capture"): 
        try: 
            capture_mod.stop_capture() 
            return {"ok": True, "stopped": True} 
        except Exception as e: 
            raise HTTPException(status_code=500, detail=str(e)) 
    else: 
        raise HTTPException(status_code=501, detail="capture module stop_capture not implemented") 
    
@app.get("/logs/recent") 
def logs_recent(limit: int = 200): 
    """Return recent logs. Uses storage.read_latest_logs if available, else reads CSV fallback.""" 
    limit = max(1, min(limit, 5000)) 
    if storage_mod and hasattr(storage_mod, "read_latest_logs"): 
        try: 
            logs = storage_mod.read_latest_logs(limit=limit) 
            return {"logs": logs} 
        except Exception: 
            pass 
    
    # fallback: read backend/data/logs.csv if exists 
    csv_path = os.path.join("backend", "data", "logs.csv") 
    if os.path.exists(csv_path): 
        try: 
            df = pd.read_csv(csv_path) 
            records = df.tail(limit).to_dict(orient="records")[::-1] 
            return {"logs": records} 
        except Exception as e: 
            raise HTTPException(status_code=500, detail=str(e)) 
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
        
    csv_path = os.path.join("backend", "data", "alerts.csv") 
    if os.path.exists(csv_path): 
        try: 
            df = pd.read_csv(csv_path) 
            records = df.tail(limit).to_dict(orient="records")[::-1] 
            return {"alerts": records} 
        except Exception as e: 
            raise HTTPException(status_code=500, detail=str(e)) 
    return {"alerts": []} 
    
@app.get("/status") 
def status(): 
    """Return basic health/status info: model loaded, n8n/mongo connectivity (best-effort).""" 
    info = {"ok": True, "uptime": int(time.time() - START_TIME)} 
    # model path & loaded? 
    try: 
        if clf_mod and hasattr(clf_mod, "CLASSIFIER"): 
            info["model_loaded"] = True 
            # try to read model path from settings if available 
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
        return info 
    # If you already have other routes in file, merge accordingly; otherwise this app will run as-is.