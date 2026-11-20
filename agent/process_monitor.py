
import json
from datetime import datetime, timezone

import psutil


def get_running_processes():
    processes = []

    for process in psutil.process_iter(
        [
            "pid",
            "name",
            "status",
            "cpu_percent",
            "memory_percent",
            "exe",
        ]
    ):
        try:
            info = process.info

            name = info.get("name")
            if not name:
                continue

            cpu = info.get("cpu_percent")
            memory = info.get("memory_percent")

            processes.append({
                "pid": int(info["pid"]),
                "name": str(name)[:255],
                "status": str(
                    info.get("status") or "unknown"
                )[:50],
                "cpu_percent": float(
                    cpu if cpu is not None else 0.0
                ),
                "memory_percent": float(
                    memory if memory is not None else 0.0
                ),
                "executable": (
                    str(info["exe"])[:2048]
                    if info.get("exe")
                    else None
                ),
            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
            TypeError,
            ValueError,
        ):
            continue

    return processes


if __name__ == "__main__":
    result = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "processes": get_running_processes(),
    }

    print(json.dumps(result, indent=2))
