
import os
import secrets
import httpx
from .active_defense.macos_firewall import (
    prepare_firewall_report,
    get_firewall_status,
)
from ipaddress import ip_address
from fastapi import Request
from .test_events import create_simulated_alert
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .alert_assessment import assess_alert
from dotenv import load_dotenv
from .behavioral_detection import analyze_behavior
from .active_defense import models as active_defense_models  # register tables before create_all
from .active_defense.router import router as active_defense_router
from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Response,
)

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import Base, SessionLocal, engine

from .models import (
    Telemetry,
    ProcessSnapshot,
    NetworkConnection,
    SecurityAlert,
    DefenseDecision,
)

from .schemas import (
    TelemetryInput,
    ProcessBatch,
    NetworkBatch,
    WebEventInput,
)

from .detection_engine import analyze_process
from .network_detection import analyze_connection
from .network_policy import ALLOWED_LISTENING_PORTS
from .web_detection import analyze_web_request
from .defense_engine import recommend_defense
from .investigation_engine import investigate_alert

from .ai_assistant import (
    get_security_context,
    get_requested_investigation,
    get_provenance_answer,
    is_provenance_question,
    ask_sentinel,
)

from .service_intelligence import analyze_services
from .threat_correlation import correlate_threats

from .behavioral_detection import (
    analyze_behavior,
    analyze_network_behavior,
)


load_dotenv(Path(__file__).resolve().parents[2] / ".env")

AGENT_TOKEN = os.environ["SENTINEL_AGENT_TOKEN"]


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="SENTINEL-AI API",
    version="0.1.0",
    lifespan=lifespan,
)


def get_db():
    with SessionLocal() as db:
        yield db


def verify_token(
    x_agent_token: str = Header(default="")
):
    if not secrets.compare_digest(
        x_agent_token, AGENT_TOKEN
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid agent token",
        )


@app.get("/health")
def health():
    return {
        "status": "running",
        "service": "SENTINEL-AI",
    }


@app.post(
    "/api/telemetry",
    dependencies=[Depends(verify_token)],
)
def receive_telemetry(
    payload: TelemetryInput,
    db: Session = Depends(get_db),
):
    event = Telemetry(**payload.model_dump())
    db.add(event)
    db.commit()
    db.refresh(event)

    return {
        "status": "stored",
        "event_id": event.id,
    }


@app.get(
    "/api/telemetry/latest",
    dependencies=[Depends(verify_token)],
)
def latest_telemetry(
    db: Session = Depends(get_db),
):
    events = db.scalars(
        select(Telemetry)
        .order_by(Telemetry.id.desc())
        .limit(20)
    ).all()

    return [
        {
            "id": e.id,
            "hostname": e.hostname,
            "timestamp": e.timestamp,
            "cpu_percent": e.cpu_percent,
            "memory_percent": e.memory_percent,
            "process_count": e.process_count,
            "bytes_sent": e.bytes_sent,
            "bytes_received": e.bytes_received,
        }
        for e in events
    ]

@app.get("/api/demo/telemetry/latest")
def demo_latest_telemetry(
    db: Session = Depends(get_db),
):
    return latest_telemetry(db)




@app.post(
    "/api/processes",
    dependencies=[Depends(verify_token)],
)
def receive_processes(
    payload: ProcessBatch,
    db: Session = Depends(get_db),
):
    records = []
    alerts_created = 0

    for process in payload.processes:
        process_data = process.model_dump()

        records.append(
            ProcessSnapshot(
                hostname=payload.hostname,
                timestamp=payload.timestamp,
                **process_data,
            )
        )

        detections = analyze_process(process_data)

        for detection in detections:
            # Avoid duplicate open alerts for the same
            # host, category, PID, and evidence.
            existing = db.scalar(
                select(SecurityAlert.id).where(
                    SecurityAlert.hostname == payload.hostname,
                    SecurityAlert.category == detection["category"],
                    SecurityAlert.pid == detection["pid"],
                    SecurityAlert.evidence == detection["evidence"],
                    SecurityAlert.status == "open",
                ).limit(1)
            )

            if existing is not None:
                continue

            db.add(
                SecurityAlert(
                    hostname=payload.hostname,
                    timestamp=datetime.now(timezone.utc),
                    category=detection["category"],
                    severity=detection["severity"],
                    title=detection["title"],
                    description=detection["description"],
                    pid=detection["pid"],
                    evidence=detection["evidence"],
                    status="open",
                    source_type="unknown",
                    source_name="macos_process_agent",
                )
            )

            alerts_created += 1

    db.add_all(records)
    db.commit()

    return {
        "status": "stored",
        "processes": len(records),
        "alerts_created": alerts_created,
    }



@app.get(
    "/api/processes/latest",
    dependencies=[Depends(verify_token)],
)
def latest_processes(
    hostname: str,
    db: Session = Depends(get_db),
):
    latest_time = db.scalar(
        select(ProcessSnapshot.timestamp)
        .where(ProcessSnapshot.hostname == hostname)
        .order_by(ProcessSnapshot.timestamp.desc())
        .limit(1)
    )

    if latest_time is None:
        return []

    processes = db.scalars(
        select(ProcessSnapshot)
        .where(
            ProcessSnapshot.hostname == hostname,
            ProcessSnapshot.timestamp == latest_time,
        )
        .order_by(ProcessSnapshot.memory_percent.desc())
    ).all()

    return [
        {
            "pid": p.pid,
            "name": p.name,
            "status": p.status,
            "cpu_percent": p.cpu_percent,
            "memory_percent": p.memory_percent,
            "executable": p.executable,
        }
        for p in processes
    ]


@app.get("/api/demo/processes/latest")
def demo_latest_processes(
    db: Session = Depends(get_db),
):
    hostname = db.scalar(
        select(ProcessSnapshot.hostname)
        .order_by(ProcessSnapshot.id.desc())
        .limit(1)
    )

    if hostname is None:
        return []

    return latest_processes(
        hostname=hostname,
        db=db,
    )


@app.get(
    "/api/alerts",
    dependencies=[Depends(verify_token)],
)
def get_alerts(db: Session = Depends(get_db)):
    alerts = db.scalars(
        select(SecurityAlert)
        .order_by(SecurityAlert.timestamp.desc())
        .limit(100)
    ).all()

    return [
        {
            "id": a.id,
            "hostname": a.hostname,
            "timestamp": a.timestamp,
            "category": a.category,
            "severity": a.severity,
            "title": a.title,
            "description": a.description,
            "pid": a.pid,
            "evidence": a.evidence,
            "status": a.status,
        }
        for a in alerts
    ]

@app.get("/api/demo/alerts")
def demo_get_alerts(db: Session = Depends(get_db)):
    return get_alerts(db)




@app.post(
    "/api/network",
    dependencies=[Depends(verify_token)],
)
def receive_network(
    payload: NetworkBatch,
    db: Session = Depends(get_db),
):
    records = []
    alerts_created = 0
    seen_detections = set()

    for conn in payload.connections:
        local = conn.local_address
        remote = conn.remote_address

        record = NetworkConnection(
            hostname=payload.hostname,
            timestamp=payload.timestamp,
            pid=conn.pid,
            protocol=conn.protocol,
            status=conn.status,
            local_ip=local.ip if local else None,
            local_port=local.port if local else None,
            remote_ip=remote.ip if remote else None,
            remote_port=remote.port if remote else None,
        )

        records.append(record)

        connection_data = {
            "pid": record.pid,
            "protocol": record.protocol,
            "status": record.status,
            "local_ip": record.local_ip,
            "local_port": record.local_port,
        }

        detections = analyze_connection(
            connection_data,
            ALLOWED_LISTENING_PORTS,
        )

        for detection in detections:
            fingerprint = (
                payload.hostname,
                detection["category"],
                detection["evidence"],
            )

            # Avoid duplicate detections within this batch.
            if fingerprint in seen_detections:
                continue

            seen_detections.add(fingerprint)

            # Avoid creating another identical open alert.
            existing = db.scalar(
                select(SecurityAlert.id)
                .where(
                    SecurityAlert.hostname == payload.hostname,
                    SecurityAlert.category == detection["category"],
                    SecurityAlert.evidence == detection["evidence"],
                    SecurityAlert.status == "open",
                )
                .limit(1)
            )

            if existing is not None:
                continue

            db.add(
                SecurityAlert(
                    hostname=payload.hostname,
                    timestamp=datetime.now(timezone.utc),
                    category=detection["category"],
                    severity=detection["severity"],
                    title=detection["title"],
                    description=detection["description"],
                    pid=detection["pid"],
                    evidence=detection["evidence"],
                    status="open",
                    source_type="unknown",
                    source_name="macos_network_collector",
                )
            )

            alerts_created += 1

    db.add_all(records)
    db.commit()

    return {
        "status": "stored",
        "connections": len(records),
        "alerts_created": alerts_created,
    }



@app.get(
    "/api/network/latest",
    dependencies=[Depends(verify_token)],
)
def latest_network(db: Session = Depends(get_db)):
    latest = db.scalar(
        select(NetworkConnection.timestamp)
        .order_by(NetworkConnection.id.desc())
        .limit(1)
    )

    if latest is None:
        return []

    records = db.scalars(
        select(NetworkConnection)
        .where(NetworkConnection.timestamp == latest)
        .order_by(NetworkConnection.id.desc())
        .limit(1000)
    ).all()

    return [
        {
            "id": c.id,
            "hostname": c.hostname,
            "timestamp": c.timestamp,
            "pid": c.pid,
            "protocol": c.protocol,
            "status": c.status,
            "local_ip": c.local_ip,
            "local_port": c.local_port,
            "remote_ip": c.remote_ip,
            "remote_port": c.remote_port,
        }
        for c in records
    ]


@app.get("/api/demo/network/latest")
def demo_latest_network(db: Session = Depends(get_db)):
    return latest_network(db)


@app.post(
    "/api/web/events",
    dependencies=[Depends(verify_token)],
)
def receive_web_event(
    payload: WebEventInput,
    db: Session = Depends(get_db),
):
    detections = analyze_web_request(
        payload.model_dump()
    )

    created = 0

    for detection in detections:
        existing = db.scalar(
            select(SecurityAlert.id)
            .where(
                SecurityAlert.hostname == payload.hostname,
                SecurityAlert.category == detection["category"],
                SecurityAlert.evidence == detection["evidence"],
                SecurityAlert.status == "open",
            )
            .limit(1)
        )

        if existing is not None:
            continue

        db.add(
            SecurityAlert(
                hostname=payload.hostname,
                timestamp=payload.timestamp,
                category=detection["category"],
                severity=detection["severity"],
                title=detection["title"],
                description=detection["description"],
                pid=None,
                evidence=detection["evidence"],
                status="open",
                source_type="unknown",
                source_name="web_event_ingestion",
            )
        )
        created += 1

    db.commit()

    return {
        "status": "analyzed",
        "detections": len(detections),
        "alerts_created": created,
    }


class ChatRequest(BaseModel):
    question: str = Field(
        min_length=1,
        max_length=1000,
    )


@app.post(
    "/api/ai/chat",
    dependencies=[Depends(verify_token)],
)
async def chat_with_sentinel(
    payload: ChatRequest,
    db: Session = Depends(get_db),
):
    context = get_security_context(db)

    try:
        answer = await ask_sentinel(
            payload.question,
            context,
        )
    except httpx.HTTPError:
        raise HTTPException(
            status_code=503,
            detail="Local AI model is unavailable",
        )

    return {
        "assistant": "SENTINEL-AI",
        "answer": answer,
        "mode": "read-only",
    }


# ============================================
# SENTINEL-AI Dashboard Authentication
# Local development version
# ============================================

DASHBOARD_PASSWORD = os.environ["SENTINEL_DASHBOARD_PASSWORD"]

SESSION_TOKEN = secrets.token_urlsafe(32)
SESSION_EXPIRY = None


class DashboardLogin(BaseModel):
    password: str


def verify_dashboard_session(
    sentinel_session: str | None = Cookie(default=None),
):
    if (
        not sentinel_session
        or SESSION_EXPIRY is None
        or datetime.now(timezone.utc) >= SESSION_EXPIRY
        or not secrets.compare_digest(
            sentinel_session,
            SESSION_TOKEN,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Dashboard login required",
        )
from fastapi import Depends
app.include_router(
    active_defense_router,
    dependencies=[Depends(verify_dashboard_session)],
)

@app.post("/api/dashboard/login")
def dashboard_login(
    payload: DashboardLogin,
    response: Response,
):
    global SESSION_TOKEN, SESSION_EXPIRY

    if not secrets.compare_digest(
        payload.password,
        DASHBOARD_PASSWORD,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid dashboard password",
        )

    SESSION_TOKEN = secrets.token_urlsafe(32)

    SESSION_EXPIRY = (
        datetime.now(timezone.utc)
        + timedelta(hours=8)
    )

    response.set_cookie(
        key="sentinel_session",
        value=SESSION_TOKEN,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=28800,
        path="/",
    )

    return {"status": "authenticated"}


@app.get(
    "/api/dashboard/session",
    dependencies=[Depends(verify_dashboard_session)],
)
def dashboard_session():
    return {"authenticated": True}





@app.post(
    "/api/dashboard/chat",
    dependencies=[Depends(verify_dashboard_session)],
)
async def dashboard_chat(
    payload: ChatRequest,
    db: Session = Depends(get_db),
):
    # Handle provenance questions using verified database labels
    # instead of allowing Ollama to guess.
    if is_provenance_question(payload.question):
        return {
            "assistant": "SENTINEL-AI",
            "answer": get_provenance_answer(db),
            "mode": "read-only",
            "investigation_performed": False,
        }

    # Retrieve current security evidence
    context = get_security_context(db)

    # Check for a voice investigation command
    investigation = get_requested_investigation(
        db,
        payload.question,
    )

    if investigation is not None:
        context["requested_investigation"] = investigation

    try:
        answer = await ask_sentinel(
            payload.question,
            context,
        )

    except httpx.HTTPError:
        raise HTTPException(
            status_code=503,
            detail="Local Ollama AI is unavailable",
        )

    return {
        "assistant": "SENTINEL-AI",
        "answer": answer,
        "mode": "read-only",
        "investigation_performed": investigation is not None,
    }



@app.get(
    "/api/dashboard/defense/recommendations",
    dependencies=[Depends(verify_dashboard_session)],
)
def defense_recommendations(
    db: Session = Depends(get_db),
):
    alerts = db.scalars(
        select(SecurityAlert)
        .where(SecurityAlert.status == "open")
        .order_by(SecurityAlert.timestamp.desc())
        .limit(50)
    ).all()

    
    recommendations = []

    for alert in alerts:
        recommendation = recommend_defense(alert)

        recommendation["source_type"] = (
            alert.source_type or "unknown"
        )
        recommendation["source_name"] = alert.source_name

        recommendation["eligible_for_real_execution"] = False

        recommendations.append(recommendation)


    return {
        "mode": "simulation",
        "total": len(recommendations),
        "recommendations": recommendations,
    }


class DefenseDecisionInput(BaseModel):
    alert_id: int
    decision: str


@app.post(
    "/api/dashboard/defense/decision",
    dependencies=[Depends(verify_dashboard_session)],
)
def record_defense_decision(
    payload: DefenseDecisionInput,
    db: Session = Depends(get_db),
):
    if payload.decision not in ("approved", "rejected"):
        raise HTTPException(
            status_code=400,
            detail="Decision must be approved or rejected",
        )

    alert = db.get(SecurityAlert, payload.alert_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    recommendation = recommend_defense(alert)

    record = DefenseDecision(
        alert_id=alert.id,
        action=recommendation["recommended_action"],
        decision=payload.decision,
        execution_mode="simulation",
        timestamp=datetime.now(timezone.utc),
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "status": "recorded",
        "decision_id": record.id,
        "alert_id": alert.id,
        "decision": record.decision,
        "action": record.action,
        "execution_mode": "simulation",
        "executed": False,
    }


@app.get(
    "/api/dashboard/defense/history",
    dependencies=[Depends(verify_dashboard_session)],
)
def defense_history(
    db: Session = Depends(get_db),
):
    decisions = db.scalars(
        select(DefenseDecision)
        .order_by(DefenseDecision.id.desc())
        .limit(100)
    ).all()

    return [
        {
            "id": d.id,
            "alert_id": d.alert_id,
            "action": d.action,
            "decision": d.decision,
            "execution_mode": d.execution_mode,
            "timestamp": d.timestamp.isoformat(),
            "executed": False,
        }
        for d in decisions
    ]


@app.get(
    "/api/dashboard/investigate/{alert_id}",
    dependencies=[Depends(verify_dashboard_session)],
)
def investigate_security_alert(
    alert_id: int,
    db: Session = Depends(get_db),
):
    try:
        return investigate_alert(db, alert_id)
    except ValueError:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

@app.get(
    "/api/dashboard/services",
    dependencies=[Depends(verify_dashboard_session)],
)
def get_service_intelligence(
    db: Session = Depends(get_db),
):
    hostname = db.scalar(
        select(Telemetry.hostname)
        .order_by(Telemetry.id.desc())
        .limit(1)
    )

    if hostname is None:
        return {
            "status": "no_device",
            "services": [],
        }

    return analyze_services(db, hostname)


@app.get(
    "/api/dashboard/threats/correlated",
    dependencies=[Depends(verify_dashboard_session)],
)
def get_correlated_threats(
    hours: int = 24,
    db: Session = Depends(get_db),
):
    if not 1 <= hours <= 168:
        raise HTTPException(
            status_code=400,
            detail="hours must be between 1 and 168",
        )

    hostname = db.scalar(
        select(Telemetry.hostname)
        .order_by(Telemetry.id.desc())
        .limit(1)
    )

    if hostname is None:
        return {
            "status": "no_device",
            "correlated_findings": [],
        }

    return correlate_threats(
        db,
        hostname=hostname,
        hours=hours,
    )

@app.get(
    "/api/dashboard/alerts/{alert_id}/assessment",
    dependencies=[Depends(verify_dashboard_session)],
)
def get_alert_assessment(
    alert_id: int,
    db: Session = Depends(get_db),
):
    alert = db.get(SecurityAlert, alert_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    alert_data = {
        "id": alert.id,
        "category": alert.category,
        "severity": alert.severity,
        "pid": alert.pid,
        "evidence": alert.evidence,
        # Existing alerts have no verified provenance field.
        "source_type": "unknown",
    }

    return assess_alert(alert_data)

class SimulatedAlertInput(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    category: str


@app.post(
    "/api/dashboard/dev/simulate-alert",
    dependencies=[Depends(verify_dashboard_session)],
)
def simulate_alert(
    payload: SimulatedAlertInput,
    request: Request,
    db: Session = Depends(get_db),
):
    client_host = request.client.host if request.client else ""

    try:
        is_loopback = ip_address(client_host).is_loopback
    except ValueError:
        is_loopback = False

    if not is_loopback:
        raise HTTPException(
            status_code=403,
            detail="Simulation endpoint is localhost only",
        )

    if os.getenv("SENTINEL_DEV_MODE") != "true":
        raise HTTPException(
            status_code=403,
            detail="Development simulation is disabled",
        )

    try:
        alert = create_simulated_alert(
            db,
            hostname=payload.hostname,
            category=payload.category,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    return {
        "status": "simulated",
        "alert_id": alert.id,
        "source_type": alert.source_type,
    }

@app.get(
    "/api/dashboard/behavior",
    dependencies=[Depends(verify_dashboard_session)],
)
def get_behavioral_analysis(
    db: Session = Depends(get_db),
):
    hostname = db.scalar(
        select(Telemetry.hostname)
        .order_by(Telemetry.id.desc())
        .limit(1)
    )

    if hostname is None:
        return {
            "status": "no_device",
            "findings": [],
        }

    return analyze_behavior(db, hostname)

@app.get(
    "/api/dashboard/behavior/network",
    dependencies=[Depends(verify_dashboard_session)],
)
def get_network_behavior(
    db: Session = Depends(get_db),
):
    hostname = db.scalar(
        select(Telemetry.hostname)
        .order_by(Telemetry.id.desc())
        .limit(1)
    )

    if hostname is None:
        return {
            "status": "no_device",
            "findings": [],
        }

    return analyze_network_behavior(db, hostname)

class FirewallBlockRequest(BaseModel):
    target_ip: str
    duration_minutes: int = Field(
        default=15,
        ge=1,
        le=60,
    )


@app.get(
    "/api/dashboard/firewall/status",
    dependencies=[Depends(verify_dashboard_session)],
)
def firewall_status():
    return get_firewall_status()


@app.post(
    "/api/dashboard/firewall/prepare",
    dependencies=[Depends(verify_dashboard_session)],
)
def prepare_firewall_action(
    payload: FirewallBlockRequest,
):
    try:
        return prepare_firewall_report(
            target_ip=payload.target_ip,
            duration_minutes=payload.duration_minutes,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
