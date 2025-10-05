# backend/settings.py
#from dotenv import load_dotenv
#load_dotenv()  # optional: allows .env file values to be read into env

try:
    # pydantic v2 has a separate package 'pydantic-settings'
    from pydantic_settings import BaseSettings
except Exception:
    # fallback: try importing BaseSettings from pydantic (older layouts)
    from pydantic import BaseSettings


class Settings(BaseSettings):
    model_path: str = "./model/enhanced_pipeline.joblib"
    schema_path: str = "./model/enhanced_schema.json"

    # local data directory and CSV paths
    data_dir: str = "./backend/data"
    local_alerts: str = "./backend/data/alerts.csv"
    local_logs: str = "./backend/data/logs.csv"

    # threshold: unified source of truth for alerts (0.0 - 1.0)
    alert_threshold: float = 0.85

    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db: str = "ids_db"
    n8n_url: str = "http://localhost:5678"

    model_config = {"protected_namespaces": ()}

SETTINGS = Settings()
