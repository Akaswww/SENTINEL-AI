
from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import NetworkConnection


def learn_network_baseline(
    db: Session,
    hostname: str,
    snapshot_limit: int = 30,
) -> dict:
    """
    Learn frequently observed listening endpoints.

    Read-only. Does not change firewall rules,
    process state, or security alerts.
    """

    if not 2 <= snapshot_limit <= 100:
        raise ValueError("snapshot_limit must be 2-100")

    timestamps = db.scalars(
        select(NetworkConnection.timestamp)
        .where(NetworkConnection.hostname == hostname)
        .distinct()
        .order_by(NetworkConnection.timestamp.desc())
        .limit(snapshot_limit)
    ).all()

    total = len(timestamps)

    if total < 5:
        return {
            "status": "insufficient_data",
            "hostname": hostname,
            "snapshots_analyzed": total,
            "services": [],
        }

    records = db.scalars(
        select(NetworkConnection)
        .where(
            NetworkConnection.hostname == hostname,
            NetworkConnection.timestamp.in_(timestamps),
            NetworkConnection.status == "LISTEN",
        )
    ).all()

    observations = defaultdict(set)

    for record in records:
        identity = (
            record.protocol,
            record.local_ip,
            record.local_port,
        )

        observations[identity].add(record.timestamp)

    services = []

    for identity, seen_times in observations.items():
        protocol, ip, port = identity

        frequency = len(seen_times) / total

        if frequency >= 0.8:
            classification = "common"
        elif frequency >= 0.3:
            classification = "occasional"
        else:
            classification = "unusual"

        services.append({
            "protocol": protocol,
            "local_ip": ip,
            "local_port": port,
            "observed_snapshots": len(seen_times),
            "observation_frequency": round(
                frequency, 3
            ),
            "classification": classification,
        })

    services.sort(
        key=lambda item: (
            item["observation_frequency"],
            item["local_port"] or 0,
        ),
        reverse=True,
    )

    return {
        "status": "analyzed",
        "hostname": hostname,
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "snapshots_analyzed": total,
        "services": services,
        "execution_mode": "read_only",
        "limitations": [
            "Frequently observed does not mean safe.",
            "Unusual does not mean malicious.",
            "Missing network snapshots can bias frequencies.",
            "Historical test data may affect the baseline.",
            "No defensive actions were executed.",
        ],
    }
