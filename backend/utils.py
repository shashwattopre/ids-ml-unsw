import requests
from .settings import SETTINGS
import os, csv

session = requests.Session()

def post_n8n(url: str | None, payload: dict):
    if not url:
        return
    try:
        session.post(url, json=payload, timeout=3)
    except Exception:
        pass

def write_csv_row(filepath, row_dict):
    file_exists = os.path.isfile(filepath)
    with open(filepath, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=row_dict.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(row_dict)