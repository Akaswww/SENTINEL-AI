
import ipaddress
from datetime import datetime, timezone


MAX_BLOCK_MINUTES = 60


def prepare_firewall_block(
    target_ip: str,
    duration_minutes: int = 15,
) -> dict:
    """
    Prepare a temporary IP block request.

    Does not execute firewall commands.
    """

    try:
        address = ipaddress.ip_address(target_ip)
    except ValueError as exc:
        raise ValueError("Invalid IP address") from exc

    if not address.is_global:
        raise ValueError(
            "Only globally routable addresses are eligible."
        )

    if not 1 <= duration_minutes <= MAX_BLOCK_MINUTES:
        raise ValueError(
            "Block duration must be between 1 and 60 minutes."
        )

    return {
        "action": "block_ip",
        "target_ip": str(address),
        "duration_minutes": duration_minutes,
        "requires_approval": True,
        "execution_mode": "simulation",
        "status": "pending_approval",
        "executed": False,
        "prepared_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }
