
import ipaddress
from datetime import datetime, timezone


def prepare_ip_block(
    ip_address: str,
    reason: str,
) -> dict:
    """
    Validate an IP blocking request.

    This function prepares a defensive action.
    It does not modify firewall rules.
    """

    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        raise ValueError("Invalid IP address")

    if not address.is_global:
        raise ValueError(
            "Only globally routable IP addresses "
            "are eligible for this blocking workflow."
        )

    if not reason.strip():
        raise ValueError(
            "A reason is required for IP blocking."
        )

    return {
        "action": "block_ip",
        "target_ip": str(address),
        "reason": reason.strip(),
        "status": "pending_approval",
        "execution_mode": "simulation",
        "requires_approval": True,
        "prepared_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "executed": False,
    }
