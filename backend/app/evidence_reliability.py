
from datetime import datetime, timezone


def assess_freshness(
    timestamp,
    max_age_seconds: int = 120,
) -> dict:
    if timestamp is None:
        return {
            "status": "unavailable",
            "age_seconds": None,
            "reliable_for_current_state": False,
        }

    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    age = (now - timestamp).total_seconds()

    if age < -30:
        status = "clock_mismatch"
    elif age <= max_age_seconds:
        status = "fresh"
    else:
        status = "stale"

    return {
        "status": status,
        "age_seconds": round(age, 1),
        "reliable_for_current_state": status == "fresh",
    }


def assess_context_reliability(context: dict) -> dict:
    telemetry = context.get("latest_system_telemetry") or {}
    network = context.get("network_summary") or {}
    services = context.get("service_intelligence") or {}

    return {
        "telemetry": assess_freshness(
            telemetry.get("timestamp"),
            max_age_seconds=30,
        ),
        "processes": assess_freshness(
            context.get("process_snapshot_timestamp"),
            max_age_seconds=90,
        ),
        "network": assess_freshness(
            network.get("timestamp"),
            max_age_seconds=120,
        ),
        "services": assess_freshness(
            services.get("network_snapshot_at"),
            max_age_seconds=120,
        ),
        "limitations": [
            "Freshness does not establish authenticity.",
            "Fresh data does not prove a device is secure.",
            "Snapshot timestamps depend on system clocks.",
        ],
    }
