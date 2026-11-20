
import os
import socket
from datetime import datetime, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

TOKEN = os.environ["SENTINEL_AGENT_TOKEN"]

payload = {
    "hostname": socket.gethostname(),
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "connections": [
        {
            "pid": 1234,
            "protocol": "TCP",
            "status": "LISTEN",
            "local_address": {
                "ip": "127.0.0.1",
                "port": 9999
            },
            "remote_address": None
        }
    ]
}

response = httpx.post(
    "http://127.0.0.1:8000/api/network",
    json=payload,
    headers={"X-Agent-Token": TOKEN},
    timeout=15
)

print("HTTP Status:", response.status_code)
print("Response:", response.text)

response.raise_for_status()
