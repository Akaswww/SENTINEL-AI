
from dataclasses import dataclass, asdict
from datetime import datetime, timezone


@dataclass
class DefenseRecommendation:
    alert_id: int
    category: str
    severity: str
    risk_score: int
    recommended_action: str
    reason: str
    requires_approval: bool = True
    execution_mode: str = "simulation"


RISK_SCORES = {
    "low": 20,
    "medium": 45,
    "high": 75,
    "critical": 95,
}


ACTION_POLICIES = {
    "suspicious_process_location": {
        "action": "investigate_process",
        "reason": (
            "Inspect executable path, code signature, "
            "process ownership, and recent activity."
        ),
    },
    "unexpected_listening_port": {
        "action": "review_listening_service",
        "reason": (
            "Identify the owning process and verify "
            "whether the listening service is authorized."
        ),
    },
    "sql_injection_indicator": {
        "action": "review_web_security_logs",
        "reason": (
            "Inspect application and WAF logs to determine "
            "whether suspicious requests were blocked."
        ),
    },
    "xss_indicator": {
        "action": "review_web_security_logs",
        "reason": (
            "Inspect request context and output encoding "
            "controls before classifying the event."
        ),
    },
}


def recommend_defense(alert) -> dict:
    severity = str(alert.severity).lower()

    policy = ACTION_POLICIES.get(
        alert.category,
        {
            "action": "manual_investigation",
            "reason": (
                "Insufficient evidence for an automated "
                "defensive response."
            ),
        },
    )

    recommendation = DefenseRecommendation(
        alert_id=alert.id,
        category=alert.category,
        severity=severity,
        risk_score=RISK_SCORES.get(severity, 30),
        recommended_action=policy["action"],
        reason=policy["reason"],
    )

    return asdict(recommendation)
