
import ipaddress


def analyze_connection(
    connection: dict,
    allowed_listening_ports: set[int],
) -> list[dict]:
    alerts = []

    protocol = connection.get("protocol")
    status = connection.get("status")
    local_port = connection.get("local_port")
    local_ip = connection.get("local_ip")
    pid = connection.get("pid")

    # Detect listening TCP ports outside the approved baseline.
    if (
        protocol == "TCP"
        and status == "LISTEN"
        and isinstance(local_port, int)
        and local_port not in allowed_listening_ports
    ):
        alerts.append({
            "category": "unexpected_listening_port",
            "severity": "medium",
            "title": "Unexpected TCP listening port",
            "description": (
                f"PID {pid} is listening on "
                f"{local_ip}:{local_port}. "
                "Verify whether this service is authorized."
            ),
            "pid": pid,
            "evidence": f"{local_ip}:{local_port}",
        })

    return alerts
