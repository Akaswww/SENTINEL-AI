
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    SecurityAlert,
    ProcessSnapshot,
    NetworkConnection,
)


def investigate_alert(
    db: Session,
    alert_id: int,
) -> dict:
    alert = db.get(SecurityAlert, alert_id)

    if alert is None:
        raise ValueError("Alert not found")

    processes = []
    connections = []

    if alert.pid is not None:
        latest_process_time = db.scalar(
            select(ProcessSnapshot.timestamp)
            .where(
                ProcessSnapshot.hostname == alert.hostname
            )
            .order_by(ProcessSnapshot.id.desc())
            .limit(1)
        )

        if latest_process_time is not None:
            records = db.scalars(
                select(ProcessSnapshot)
                .where(
                    ProcessSnapshot.hostname == alert.hostname,
                    ProcessSnapshot.timestamp == latest_process_time,
                    ProcessSnapshot.pid == alert.pid,
                )
            ).all()

            processes = [
                {
                    "pid": p.pid,
                    "name": p.name,
                    "status": p.status,
                    "executable": p.executable,
                    "cpu_percent": p.cpu_percent,
                    "memory_percent": p.memory_percent,
                    "snapshot_time": p.timestamp.isoformat(),
                }
                for p in records
            ]

        latest_network_time = db.scalar(
            select(NetworkConnection.timestamp)
            .where(
                NetworkConnection.hostname == alert.hostname
            )
            .order_by(NetworkConnection.id.desc())
            .limit(1)
        )

        if latest_network_time is not None:
            records = db.scalars(
                select(NetworkConnection)
                .where(
                    NetworkConnection.hostname == alert.hostname,
                    NetworkConnection.timestamp == latest_network_time,
                    NetworkConnection.pid == alert.pid,
                )
            ).all()

            connections = [
                {
                    "protocol": c.protocol,
                    "local_ip": c.local_ip,
                    "local_port": c.local_port,
                    "remote_ip": c.remote_ip,
                    "remote_port": c.remote_port,
                    "status": c.status,
                    "snapshot_time": c.timestamp.isoformat(),
                }
                for c in records
            ]

    return {
        "alert_id": alert.id,
        "hostname": alert.hostname,
        "category": alert.category,
        "severity": alert.severity,
        "title": alert.title,
        "pid": alert.pid,
        "process_evidence": processes,
        "network_evidence": connections,
        "investigated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "execution_mode": "read_only",
        "limitations": [
            "Evidence comes from stored snapshots.",
            "A PID may have been reused.",
            "Missing records do not prove absence of activity.",
            "This investigation does not change the device.",
        ],
    }
