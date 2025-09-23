# IDS-ML-UNSW

An end-to-end Intrusion Detection System trained on NF-UNSW-NB15-v3 with real-time packet capture, ML classification, a React dashboard, and n8n automation to MongoDB + Telegram/Email.

## Setup
1. Python env & deps: `pip install -r requirements.txt`
2. Train model: `python train_model.py --data /path/to/NF-UNSW-NB15-v3.csv`
3. Backend: `python -m uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000`
4. Frontend: `npm install && npm run dev` in `frontend/`
5. n8n: Import workflow, set webhooks, Mongo, Telegram/SMTP

## Environment
Copy `.env.example` → `.env` and fill values.

## Run
- Start backend, then frontend, then hit **Start** on UI.
- Tune **Settings → Alert Threshold** to balance precision/recall.

## Export
- `GET /export/logs.csv` or `/export/alerts.csv`

## Notes
- Ensure capture permissions (run as admin or set capabilities on Linux: `sudo setcap cap_net_raw,cap_net_admin=eip $(which python)`)
- The live extractor uses a subset of features; keep training schema in sync.
