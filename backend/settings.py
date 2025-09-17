# backend/settings.py
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    model_path: str = "model/pipeline.joblib"
    schema_path: str = "model/feature_schema.json"
    data_dir: str = "backend/data"
    alerts_file: str = "backend/data/alerts.csv"
    logs_file: str = "backend/data/logs.csv"

    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db: str = "ids_db"
    n8n_url: str = "http://localhost:5678"

    model_config = {"protected_namespaces": ()}

SETTINGS = Settings()
