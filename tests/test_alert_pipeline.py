
import os
import socket
from datetime import datetime, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

API_URL = "http://127.0.0.1:8000"
TOKEN = os.environ["SENTINEL_AGENT_TOKEN"]

test_event = {
    "hostname": socket.gethostname(),
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "processes": [
        {
            "pid": 999999,
            "name": "sentinel-test-process",
            "status": "running",
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "executable": "/private/tmp/sentinel-test-process",
        }
    ],
}

print("Sending simulated security event...")

response = httpx.post(
    f"{API_URL}/api/processes",
    json=test_event,
    headers={"X-Agent-Token": TOKEN},
    timeout=15.0,
)

print("HTTP status:", response.status_code)
print("Response:", response.text)
response.raise_for_status()
