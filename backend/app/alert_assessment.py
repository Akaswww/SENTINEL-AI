
from datetime import datetime, timezone

KNOWN_PORTS = {
    22: "SSH remote access",
    80: "HTTP web server",
    88: "Kerberos authentication",
    443: "HTTPS web server",
    445: "SMB file sharing",
    5900: "VNC screen sharing",
    5432: "PostgreSQL",
    8000: "Development web server",
    5173: "Vite development server",
}


def assess_alert(alert: dict) -> dict:
    """
    Read-only preliminary alert assessment.

    Does not confirm attacks or change system settings.
    """

    category = str(alert.get("category", "unknown"))
    evidence = str(alert.get("evidence", ""))
    severity = str(alert.get("severity", "unknown"))
    pid = alert.get("pid")

    # Provenance must be supplied by a trusted ingestion source.
    # Do not guess simulation status from process names.
    source_type = alert.get("source_type", "unknown")

    if source_type not in ("real", "simulated"):
        source_type = "unknown"

    result = {
        "alert_id": alert.get("id"),
        "category": category,
        "severity": severity,
        "pid": pid,
        "source_type": source_type,
        "assessment": "needs_review",
        "confidence": "unverified",
        "reason": "The alert requires additional evidence.",
        "analyzed_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "execution_mode": "read_only",
    }

    if source_type == "simulated":
        result.update({
            "assessment": "simulated",
            "reason": "This event was explicitly marked as a test.",
        })
        return result

    if category == "unexpected_listening_port":
        result["reason"] = (
            "A listening port was observed. "
            "Verify its owner and authorization."
        )

        for port, service in KNOWN_PORTS.items():
            if (
                f":{port}" in evidence
                and not any(
                    f":{port}{digit}" in evidence
                    for digit in "0123456789"
                )
            ):
                result["service_hint"] = service
                result["reason"] = (
                    f"Port {port} is commonly associated with "
                    f"{service}. Confirm the owning service "
                    "and whether it is authorized."
                )
                break

    elif category == "suspicious_process_location":
        result["reason"] = (
            "The executable location is unusual. "
            "Verify code signature, ownership, and origin."
        )

    elif category == "sql_injection_indicator":
        result["reason"] = (
            "A request matched a SQL injection detection rule. "
            "Inspect application logs to determine whether "
            "the request reached a vulnerable query."
        )

    return result
