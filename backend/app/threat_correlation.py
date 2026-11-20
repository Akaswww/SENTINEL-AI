
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import SecurityAlert


SEVERITY_WEIGHTS = {
    "low": 10,
    "medium": 25,
    "high": 45,
    "critical": 65,
}


def correlate_threats(
    db: Session,
    hostname: str,
    hours: int = 24,
) -> dict:
    """
    Correlate recent alerts by host and PID.

    Read-only analysis. Does not execute
    defensive actions.
    """

    if not 1 <= hours <= 168:
        raise ValueError("hours must be between 1 and 168")

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours)

    alerts = db.scalars(
        select(SecurityAlert)
        .where(
            SecurityAlert.hostname == hostname,
            SecurityAlert.timestamp >= cutoff,
            SecurityAlert.status == "open",
        )
        .order_by(SecurityAlert.timestamp.desc())
        .limit(1000)
    ).all()

    groups = defaultdict(list)

    for alert in alerts:
        if alert.pid is None:
            # Don't merge unrelated events without a PID.
            key = ("alert", alert.id)
        else:
            key = ("pid", alert.pid)

        groups[key].append(alert)

    findings = []

    for key, group in groups.items():
        severities = [
            SEVERITY_WEIGHTS.get(
                str(alert.severity).lower(),
                10,
            )
            for alert in group
        ]

        categories = sorted({
            alert.category for alert in group
        })

        base_score = max(severities)

        # Multiple distinct categories increase priority.
        category_bonus = min(
            30,
            max(0, len(categories) - 1) * 15,
        )

        score = min(100, base_score + category_bonus)

        findings.append({
            "group_type": key[0],
            "group_id": key[1],
            "risk_score": score,
            "alert_count": len(group),
            "categories": categories,
            "alert_ids": [a.id for a in group],
            "first_seen": min(
                a.timestamp for a in group
            ).isoformat(),
            "last_seen": max(
                a.timestamp for a in group
            ).isoformat(),
            "assessment": (
                "Multiple detection categories share this PID."
                if len(categories) > 1
                else "Single detection category observed."
            ),
            "confidence": "unverified",
        })

    findings.sort(
        key=lambda item: item["risk_score"],
        reverse=True,
    )

    return {
        "hostname": hostname,
        "generated_at": now.isoformat(),
        "window_hours": hours,
        "total_alerts": len(alerts),
        "correlated_findings": findings,
        "execution_mode": "read_only",
        "limitations": [
            "PID reuse can create false correlations.",
            "Multiple alerts do not prove an attack.",
            "Scores are heuristic priorities, not probabilities.",
            "Simulated events may be present.",
            "No defensive actions were executed.",
        ],
    }
