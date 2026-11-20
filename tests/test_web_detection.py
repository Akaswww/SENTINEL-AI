
import os
import socket
from datetime import datetime, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

payload = {
    "hostname": socket.gethostname(),
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "method": "GET",
    "path": "/search?q=UNION%20SELECT%20name%20FROM%20items",
    "status_code": 400,
    "source": "local-test",
}

response = httpx.post(
    "http://127.0.0.1:8000/api/web/events",
    json=payload,
    headers={
        "X-Agent-Token": os.environ["SENTINEL_AGENT_TOKEN"]
    },
    timeout=15,
)

print("HTTP:", response.status_code)
print("Response:", response.text)
response.raise_for_status()
