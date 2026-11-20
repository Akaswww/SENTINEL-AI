import json
from pathlib import Path
import os
import time
import socket
from datetime import datetime, timezone
from pathlib import Path

import httpx
import psutil
from dotenv import load_dotenv

from process_monitor import get_running_processes


# Load environment variables
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

API_URL = "http://127.0.0.1:8000"
TOKEN = os.environ["SENTINEL_AGENT_TOKEN"]

HEADERS = {
    "X-Agent-Token": TOKEN
}


def collect_telemetry():
    network = psutil.net_io_counters()

    return {
        "hostname": socket.gethostname(),
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "process_count": len(psutil.pids()),
        "bytes_sent": network.bytes_sent,
        "bytes_received": network.bytes_recv,
    }


def send_telemetry(client, telemetry):
    response = client.post(
        f"{API_URL}/api/telemetry",
        json=telemetry,
        headers=HEADERS,
    )

    response.raise_for_status()

    print(
        f"[TELEMETRY OK] {telemetry['hostname']} | "
        f"CPU: {telemetry['cpu_percent']}% | "
        f"RAM: {telemetry['memory_percent']}% | "
        f"Processes: {telemetry['process_count']}"
    )


def send_processes(client, telemetry):
    processes = get_running_processes()

    payload = {
        "hostname": telemetry["hostname"],
        "timestamp": telemetry["timestamp"],
        "processes": processes,
    }

    response = client.post(
        f"{API_URL}/api/processes",
        json=payload,
        headers=HEADERS,
    )

    if response.status_code == 422:
        print("[VALIDATION ERROR]")
        print(response.text[:4000])
    response.raise_for_status()

    print(
        f"[PROCESSES OK] Stored {len(processes)} processes"
    )



def send_network(client, telemetry):
    snapshot_file = (
        Path(__file__).resolve().parent
        / "network_snapshot.json"
    )

    if not snapshot_file.exists():
        return

    snapshot = json.loads(snapshot_file.read_text())

    payload = {
        "hostname": telemetry["hostname"],
        "timestamp": snapshot["timestamp"],
        "connections": snapshot["connections"],
    }

    response = client.post(
        f"{API_URL}/api/network",
        json=payload,
        headers=HEADERS,
    )

    response.raise_for_status()

    print(
        f"[NETWORK OK] Stored "
        f"{len(payload['connections'])} connections"
    )



def main():
    print("=" * 45)
    print("SENTINEL-AI Security Agent v0.5")
    print("macOS Endpoint & Network Monitoring")
    print("=" * 45)
    print("Press Ctrl+C to stop.\n")

    last_process_scan = 0.0
    last_network_timestamp = None

    snapshot_file = (
        Path(__file__).resolve().parent
        / "network_snapshot.json"
    )

    with httpx.Client(timeout=15.0) as client:
        try:
            while True:
                telemetry = collect_telemetry()

                # 1. Send system telemetry
                try:
                    send_telemetry(client, telemetry)

                except httpx.HTTPError as error:
                    print(f"[TELEMETRY ERROR] {error}")

                # 2. Collect processes every 30 seconds
                if time.monotonic() - last_process_scan >= 30:
                    try:
                        send_processes(client, telemetry)
                        last_process_scan = time.monotonic()

                    except httpx.HTTPError as error:
                        print(f"[PROCESS ERROR] {error}")

                # 3. Upload new network snapshots
                try:
                    if snapshot_file.exists():
                        snapshot = json.loads(
                            snapshot_file.read_text()
                        )

                        timestamp = snapshot["timestamp"]

                        if timestamp != last_network_timestamp:
                            send_network(client, telemetry)
                            last_network_timestamp = timestamp

                except (
                    httpx.HTTPError,
                    OSError,
                    ValueError,
                    KeyError,
                ) as error:
                    print(f"[NETWORK ERROR] {error}")

                time.sleep(4)

        except KeyboardInterrupt:
            print("\nSENTINEL-AI Agent stopped.")


if __name__ == "__main__":
    main()



if __name__ == "__main__":
    main()
