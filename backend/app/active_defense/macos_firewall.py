
import ipaddress
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

HELPER = Path("/usr/local/libexec/sentinel-pf-helper")
STATE_DIR = Path.home() / ".sentinel-ai" / "firewall"


def validate_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Invalid IP address") from exc

    if not address.is_global:
        raise ValueError(
            "Only globally routable IP addresses are allowed"
        )

    return str(address)


def request_ip_block(
    target_ip: str,
    duration_minutes: int = 15,
) -> dict:
    """
    Prepare a blocking request.
    Does not execute until separately authorized.
    """

    target_ip = validate_ip(target_ip)

    if not 1 <= duration_minutes <= 60:
        raise ValueError(
            "Duration must be between 1 and 60 minutes"
        )

    now = datetime.now(timezone.utc)

    return {
        "action": "block_ip",
        "target_ip": target_ip,
        "duration_minutes": duration_minutes,
        "created_at": now.isoformat(),
        "expires_at": (
            now + timedelta(minutes=duration_minutes)
        ).isoformat(),
        "status": "pending_approval",
        "requires_approval": True,
        "executed": False,
    }


def firewall_helper_available() -> bool:
    return (
        HELPER.is_file()
        and os.access(HELPER, os.X_OK)
    )


def get_firewall_status() -> dict:
    """
    Read macOS Packet Filter status.
    Does not change firewall configuration.
    """

    try:
        result = subprocess.run(
            ["/sbin/pfctl", "-s", "info"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        output = result.stdout + result.stderr

        import re

        match = re.search(
            r"Status:\s*(Enabled|Disabled)",
            output,
            flags=re.IGNORECASE,
        )

        status = (
            match.group(1).lower()
            if match and result.returncode == 0
            else "unknown"
        )

        return {
            "pf_enabled": status == "enabled",
            "pf_disabled": status == "disabled",
            "pf_status": status,
            "helper_installed": firewall_helper_available(),
            "read_only": True,
            "error": (
                output.strip()
                if result.returncode != 0
                else None
            ),
        }

    except (
        subprocess.TimeoutExpired,
        OSError,
    ) as exc:
        return {
            "pf_enabled": False,
            "pf_disabled": False,
            "pf_status": "unknown",
            "helper_installed": firewall_helper_available(),
            "read_only": True,
            "error": str(exc),
        }


def prepare_firewall_report(
    target_ip: str,
    duration_minutes: int = 15,
) -> dict:
    request = request_ip_block(
        target_ip,
        duration_minutes,
    )

    request["firewall"] = get_firewall_status()

    request["execution_mode"] = "preview"
    request["status"] = "pending_approval"
    request["message"] = (
        "Firewall change prepared. "
        "A separately authorized privileged helper "
        "is required before execution."
    )

    return request
