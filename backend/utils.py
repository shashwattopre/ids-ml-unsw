import requests
from .settings import SETTINGS

session = requests.Session()

def post_n8n(url: str | None, payload: dict):
    if not url:
        return
    try:
        session.post(url, json=payload, timeout=3)
    except Exception:
        pass
