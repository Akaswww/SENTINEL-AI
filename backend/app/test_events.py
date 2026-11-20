
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .models import SecurityAlert


ALLOWED_TEST_CATEGORIES = {
    "unexpected_listening_port",
    "suspicious_process_location",
    "sql_injection_indicator",
}


def create_simulated_alert(
    db: Session,
    hostname: str,
    category: str,
) -> SecurityAlert:
    if category not in ALLOWED_TEST_CATEGORIES:
        raise ValueError("Unsupported test category")

    alert = SecurityAlert(
        hostname=hostname,
        timestamp=datetime.now(timezone.utc),
        category=category,
        severity="low",
        title=f"Simulated {category.replace('_', ' ')}",
        description=(
            "Controlled development test event. "
            "Not evidence of an actual attack."
        ),
        pid=None,
        evidence="sentinel_simulation",
        status="open",
        source_type="simulated",
        source_name="sentinel_test_harness",
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert
