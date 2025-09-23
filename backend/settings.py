# backend/settings.py
try:
    # pydantic v2 has a separate package 'pydantic-settings'
    from pydantic_settings import BaseSettings
except Exception:
    # fallback: try importing BaseSettings from pydantic (older layouts)
    from pydantic import BaseSettings


class Settings(BaseSettings):
    model_path: str = "./model/pipeline.joblib"
    schema_path: str = "./model/feature_schema.json"
    data_dir: str = "data"
    local_alerts: str = "data/alerts.csv"
    local_logs: str = "data/logs.csv"

    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db: str = "ids_db"
    n8n_url: str = "http://localhost:5678"

    model_config = {"protected_namespaces": ()}

SETTINGS = Settings()
