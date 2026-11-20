# SENTINEL-AI v0.1

Local-only cybersecurity telemetry MVP for Apple Silicon macOS. **This version does not detect malware or threats.** It collects CPU, RAM, process count, and aggregate network counters from your own machine, stores them in PostgreSQL, and shows recent readings in React.

## Prerequisites

- Python 3.12, Node.js 20+, npm, Docker Desktop (Apple Silicon), Git
- Docker Desktop must be running.

## 1. Configure

```bash
cp .env.example .env
python3.12 -c 'import secrets; print(secrets.token_urlsafe(32))'
python3.12 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Replace both placeholder values in `.env` with **different** generated secrets. Never commit `.env`.

## 2. Database and Python

```bash
docker compose up -d
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## 3. Start backend (Terminal 1)

```bash
source .venv/bin/activate
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Verify http://127.0.0.1:8000/health

## 4. Start agent (Terminal 2)

```bash
source .venv/bin/activate
python agent/main.py
```

## 5. Start dashboard (Terminal 3)

```bash
cd frontend
npm install
npm run dev
```

Open http://127.0.0.1:5173

## Safety and limitations

- Local development only. Both backend and dashboard bind to 127.0.0.1.
- The `/api/demo/telemetry/latest` route is intentionally unauthenticated for the local dashboard. Remove it before deployment and implement user authentication and authorization.
- A single shared agent token is used for the prototype. Production needs per-device identity, TLS, enrollment and revocation.
- Do not run on third-party or organizational machines without authorization.
- PostgreSQL data volume persists between container restarts. `docker compose down -v` deletes the database volume.
