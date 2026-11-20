

import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(
    Path(__file__).resolve().parents[1] / ".env"
)

question = (
    "Summarize my latest security alerts. "
    "Explain which events need investigation."
)

response = httpx.post(
    "http://127.0.0.1:8000/api/ai/chat",
    json={"question": question},
    headers={
        "X-Agent-Token": os.environ[
            "SENTINEL_AGENT_TOKEN"
        ]
    },
    timeout=120,
)

print("HTTP:", response.status_code)
print(response.text)
response.raise_for_status()
