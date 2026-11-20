
import re
from urllib.parse import unquote


SQL_PATTERNS = [
    re.compile(r"\bunion\s+select\b", re.I),
    re.compile(r"\bselect\b.{0,60}\bfrom\b", re.I),
    re.compile(r"\b(?:or|and)\s+\d+\s*=\s*\d+", re.I),
]

XSS_PATTERNS = [
    re.compile(r"<script\b", re.I),
    re.compile(r"\bonerror\s*=", re.I),
    re.compile(r"javascript\s*:", re.I),
]


def analyze_web_request(event: dict) -> list[dict]:
    path = str(event.get("path", ""))[:2048]
    method = str(event.get("method", "GET")).upper()

    # Decode once for basic normalized inspection.
    normalized = unquote(path)
    alerts = []

    for category, patterns in (
        ("sql_injection_indicator", SQL_PATTERNS),
        ("xss_indicator", XSS_PATTERNS),
    ):
        if any(pattern.search(normalized) for pattern in patterns):
            alerts.append({
                "category": category,
                "severity": "medium",
                "title": (
                    "Possible SQL injection indicator"
                    if category == "sql_injection_indicator"
                    else "Possible XSS indicator"
                ),
                "description": (
                    f"Suspicious pattern observed in "
                    f"{method} request path."
                ),
                "pid": None,
                "evidence": normalized[:1000],
            })

    return alerts

