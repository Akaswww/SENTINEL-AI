
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import NetworkConnection, ProcessSnapshot


KNOWN_SERVICES = {
    22: "SSH remote access",
    53: "DNS",
    80: "HTTP web server",
    139: "NetBIOS session service",
    443: "HTTPS web server",
    445: "SMB file sharing",
    5432: "PostgreSQL",
    5900: "VNC screen sharing",
    8000: "Development web server",
    5173: "Vite development server",
}


def analyze_services(db: Session, hostname: str) -> dict:
    now = datetime.now(timezone.utc)

    latest_network_time = db.scalar(
        select(NetworkConnection.timestamp)
        .where(NetworkConnection.hostname == hostname)
        .order_by(NetworkConnection.id.desc())
        .limit(1)
    )

    if latest_network_time is None:
        return {
            "hostname": hostname,
            "analyzed_at": now.isoformat(),
            "services": [],
            "message": "No network snapshot available",
        }

    connections = db.scalars(
        select(NetworkConnection)
        .where(
            NetworkConnection.hostname == hostname,
            NetworkConnection.timestamp == latest_network_time,
            NetworkConnection.status == "LISTEN",
        )
    ).all()

    latest_process_time = db.scalar(
        select(ProcessSnapshot.timestamp)
        .where(ProcessSnapshot.hostname == hostname)
        .order_by(ProcessSnapshot.id.desc())
        .limit(1)
    )

    process_map = {}

    if latest_process_time is not None:
        processes = db.scalars(
            select(ProcessSnapshot)
            .where(
                ProcessSnapshot.hostname == hostname,
                ProcessSnapshot.timestamp == latest_process_time,
            )
        ).all()

        process_map = {
            p.pid: {
                "name": p.name,
                "executable": p.executable,
            }
            for p in processes
        }

    services = []
    seen = set()

    for connection in connections:
        identity = (
            connection.pid,
            connection.protocol,
            connection.local_ip,
            connection.local_port,
        )

        if identity in seen:
            continue

        seen.add(identity)

        process = process_map.get(connection.pid, {})

        services.append({
            "pid": connection.pid,
            "process_name": process.get("name", "Unknown"),
            "executable": process.get("executable"),
            "protocol": connection.protocol,
            "local_ip": connection.local_ip,
            "local_port": connection.local_port,
            "service_hint": KNOWN_SERVICES.get(
                connection.local_port,
                "Unidentified service",
            ),
            "authorization_status": "unverified",
        })

    return {
        "hostname": hostname,
        "analyzed_at": now.isoformat(),
        "network_snapshot_at": latest_network_time.isoformat(),
        "process_snapshot_at": (
            latest_process_time.isoformat()
            if latest_process_time else None
        ),
        "total_services": len(services),
        "services": services,
        "limitations": [
            "Service names are inferred from port numbers.",
            "Port numbers do not prove process identity.",
            "Process snapshots may be stale.",
            "Authorization has not been verified.",
            "No system changes were made.",
        ],
    }
