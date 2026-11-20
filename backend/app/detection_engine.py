
from pathlib import PurePosixPath


def analyze_process(process: dict) -> list[dict]:
    """Identify process behaviors that deserve investigation."""
    alerts = []

    name = str(process.get("name") or "unknown")
    executable = str(process.get("executable") or "")
    pid = process.get("pid")

    # Heuristic: executable launched from a temporary directory.
    temporary_locations = (
        "/private/tmp/",
        "/tmp/",
        "/var/tmp/",
    )

    if executable.startswith(temporary_locations):
        alerts.append({
            "category": "suspicious_process_location",
            "severity": "medium",
            "title": "Process running from temporary directory",
            "description": (
                f"{name} (PID {pid}) is running from "
                f"{executable}. Verify whether this is expected."
            ),
            "pid": pid,
            "evidence": executable,
        })

    return alerts
