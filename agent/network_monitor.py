
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import psutil


SNAPSHOT_PATH = Path(__file__).resolve().parent / "network_snapshot.json"


def address_to_dict(address):
    if not address:
        return None

    return {
        "ip": address.ip,
        "port": address.port,
    }


def get_network_connections():
    connections = []
    denied_processes = 0
    inspected_processes = 0

    for process in psutil.process_iter(["pid"]):
        try:
            process_connections = process.net_connections(
                kind="inet"
            )
            inspected_processes += 1

        except (psutil.AccessDenied, PermissionError):
            denied_processes += 1
            continue

        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue

        for connection in process_connections:
            protocol = (
                "TCP"
                if connection.type == socket.SOCK_STREAM
                else "UDP"
            )

            connections.append({
                "pid": process.pid,
                "protocol": protocol,
                "status": connection.status,
                "local_address": address_to_dict(
                    connection.laddr
                ),
                "remote_address": address_to_dict(
                    connection.raddr
                ),
            })

    return connections, inspected_processes, denied_processes


def collect_snapshot():
    connections, inspected, denied = get_network_connections()

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "connections": connections,
        "collection_metadata": {
            "inspected_processes": inspected,
            "denied_processes": denied,
            "complete": denied == 0,
        },
    }


if __name__ == "__main__":
    snapshot = collect_snapshot()

    SNAPSHOT_PATH.write_text(
        json.dumps(snapshot, indent=2),
        encoding="utf-8",
    )

    print(
        f"Collected {len(snapshot['connections'])} connections"
    )

    print(
        "Processes inspected:",
        snapshot["collection_metadata"]["inspected_processes"],
    )

    print(
        "Processes denied:",
        snapshot["collection_metadata"]["denied_processes"],
    )

    print("Snapshot saved:", SNAPSHOT_PATH)
