
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import ProcessSnapshot, NetworkConnection
from .behavior_baseline import learn_network_baseline

CPU_SPIKE_THRESHOLD = 80.0
MEMORY_SPIKE_THRESHOLD = 25.0


def analyze_behavior(
    db: Session,
    hostname: str,
) -> dict:
    """
    Compare the two most recent process snapshots.

    Read-only behavioral analysis.
    No defensive actions are executed.
    """

    timestamps = db.scalars(
        select(ProcessSnapshot.timestamp)
        .where(ProcessSnapshot.hostname == hostname)
        .distinct()
        .order_by(ProcessSnapshot.timestamp.desc())
        .limit(2)
    ).all()

    if len(timestamps) < 2:
        return {
            "hostname": hostname,
            "status": "insufficient_data",
            "findings": [],
        }

    current_time, previous_time = timestamps

    def load_snapshot(timestamp):
        processes = db.scalars(
            select(ProcessSnapshot)
            .where(
                ProcessSnapshot.hostname == hostname,
                ProcessSnapshot.timestamp == timestamp,
            )
        ).all()

        return {p.pid: p for p in processes}

    current = load_snapshot(current_time)
    previous = load_snapshot(previous_time)

    findings = []

    for pid, process in current.items():
        old = previous.get(pid)

        if old is None:
            findings.append({
                "category": "new_process",
                "severity": "info",
                "pid": pid,
                "process_name": process.name,
                "description": (
                    f"New process observed: {process.name}"
                ),
            })
            continue

        # PID reuse can occur, so check process identity.
        if (
            process.name != old.name
            or process.executable != old.executable
        ):
            findings.append({
                "category": "process_identity_changed",
                "severity": "low",
                "pid": pid,
                "process_name": process.name,
                "description": (
                    "The process associated with this PID "
                    "changed between snapshots."
                ),
            })
            continue

        if (
            process.cpu_percent >= CPU_SPIKE_THRESHOLD
            and old.cpu_percent < CPU_SPIKE_THRESHOLD
        ):
            findings.append({
                "category": "cpu_spike",
                "severity": "medium",
                "pid": pid,
                "process_name": process.name,
                "description": (
                    f"CPU usage increased from "
                    f"{old.cpu_percent:.1f}% to "
                    f"{process.cpu_percent:.1f}%."
                ),
            })

        if (
            process.memory_percent >= MEMORY_SPIKE_THRESHOLD
            and old.memory_percent < MEMORY_SPIKE_THRESHOLD
        ):
            findings.append({
                "category": "memory_spike",
                "severity": "medium",
                "pid": pid,
                "process_name": process.name,
                "description": (
                    f"Memory usage increased from "
                    f"{old.memory_percent:.1f}% to "
                    f"{process.memory_percent:.1f}%."
                ),
            })

    return {
        "hostname": hostname,
        "status": "analyzed",
        "analyzed_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "current_snapshot": current_time.isoformat(),
        "previous_snapshot": previous_time.isoformat(),
        "findings_count": len(findings),
        "findings": findings[:100],
        "execution_mode": "read_only",
        "limitations": [
            "High CPU or memory usage does not prove malware.",
            "New processes may be legitimate.",
            "PID reuse can affect comparisons.",
            "Snapshots may be stale.",
            "No defensive actions were executed.",
        ],
    }

def analyze_network_behavior(
    db: Session,
    hostname: str,
) -> dict:
    """
    Compare the two latest network snapshots.

    Detect newly observed listening endpoints.
    Read-only analysis.
    """

    timestamps = db.scalars(
        select(NetworkConnection.timestamp)
        .where(NetworkConnection.hostname == hostname)
        .distinct()
        .order_by(NetworkConnection.timestamp.desc())
        .limit(2)
    ).all()

    if len(timestamps) < 2:
        return {
            "hostname": hostname,
            "status": "insufficient_data",
            "findings": [],
        }

    current_time, previous_time = timestamps

    def load_listeners(timestamp):
        connections = db.scalars(
            select(NetworkConnection)
            .where(
                NetworkConnection.hostname == hostname,
                NetworkConnection.timestamp == timestamp,
                NetworkConnection.status == "LISTEN",
            )
        ).all()

        return {
            (
                c.protocol,
                c.local_ip,
                c.local_port,
                c.pid,
            )
            for c in connections
        }

    current = load_listeners(current_time)
    previous = load_listeners(previous_time)

    new_listeners = current - previous
    baseline = learn_network_baseline(
        db,
        hostname=hostname,
        snapshot_limit=30,
    )

    findings = []

    for protocol, ip, port, pid in sorted(
        new_listeners,
        key=lambda x: (
            str(x[0]),
            str(x[1]),
            x[2] or 0,
            x[3] or 0,
        ),
    ):
        findings.append({
            "category": "new_listening_port",
            "severity": "info",
            "pid": pid,
            "protocol": protocol,
            "local_ip": ip,
            "local_port": port,
            "description": (
                f"New listening endpoint observed: "
                f"{ip}:{port}"
            ),
        })

    return {
        "hostname": hostname,
        "status": "analyzed",
        "current_snapshot": current_time.isoformat(),
        "previous_snapshot": previous_time.isoformat(),
        "findings_count": len(findings),
        "findings": findings[:100],
        "execution_mode": "read_only",
        "limitations": [
            "A newly observed listener is not necessarily malicious.",
            "The previous snapshot may have missed short-lived services.",
            "PID reuse may affect process attribution.",
            "Snapshot freshness must be checked separately.",
            "No defensive actions were executed.",
        ],
    }
