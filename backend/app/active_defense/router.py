import psutil
from datetime import datetime, timedelta, timezone
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..database import SessionLocal
from .models import DefenseAction, DefenseAudit
from .policy import PolicyError, validate
from .executor import execute

router = APIRouter(prefix='/api/dashboard/active-defense', tags=['Active Defense'])

def db_session():
    with SessionLocal() as db:
        yield db

class ActionRequest(BaseModel):
    action: Literal['block_ip', 'quarantine_file', 'terminate_process']
    target: str = Field(min_length=1, max_length=1024)
    reason: str = Field(min_length=10, max_length=500)
    alert_id: int | None = None

class DecisionRequest(BaseModel):
    confirmation: Literal['APPROVE', 'REJECT']

def log(db: Session, item: DefenseAction, event: str, detail: str):
    db.add(DefenseAudit(action_id=item.id, event=event, detail=detail))

@router.post('/requests')
def request_action(payload: ActionRequest, db: Session = Depends(db_session)):
    try:
        target, fingerprint = validate(payload.action, payload.target)
    except PolicyError as exc:
        raise HTTPException(400, str(exc)) from exc
    # No alert is required for an isolated lab demonstration.
    item = DefenseAction(action=payload.action, target=target, reason=payload.reason,
                         alert_id=payload.alert_id, target_fingerprint=fingerprint,
                         expires_at=datetime.now(timezone.utc) + timedelta(minutes=2))
    db.add(item)
    db.flush()
    log(db, item, 'requested', 'Awaiting explicit approval; no action executed')
    db.commit()
    db.refresh(item)
    return {'id': item.id, 'status': item.status, 'action': item.action,
            'target': item.target, 'expires_at': item.expires_at,
            'execution_mode': 'restricted_lab', 'executed': False}

@router.post('/requests/{action_id}/decision')
def decide(action_id: int, payload: DecisionRequest, db: Session = Depends(db_session)):
    item = db.get(DefenseAction, action_id)
    if not item:
        raise HTTPException(404, 'Action request not found')
    if item.status != 'pending':
        raise HTTPException(409, 'Action already decided')
    if datetime.now(timezone.utc) >= item.expires_at:
        item.status = 'expired'
        log(db, item, 'expired', 'Approval window elapsed')
        db.commit()
        raise HTTPException(409, 'Approval expired')
    if payload.confirmation == 'REJECT':
        item.status = 'rejected'
        log(db, item, 'rejected', 'User rejected action')
        db.commit()
        return {'status': item.status, 'executed': False}
    item.status = 'approved'
    log(db, item, 'approved', 'Explicit approval received')
    db.commit()
    try:
        detail, reversible = execute(item.id, item.action, item.target, item.target_fingerprint)
        item.status = 'not_executed' if detail.startswith('NOT_EXECUTED:') else ('completed' if 'exit not confirmed' not in detail else 'unverified')
        item.reversible = reversible
        item.outcome = detail
        log(db, item, item.status, detail)
    except (PolicyError, OSError, psutil.Error) as exc:
        item.status = 'failed'
        item.outcome = str(exc)
        log(db, item, 'failed', str(exc))
    item.completed_at = datetime.now(timezone.utc)
    db.commit()
    return {'status': item.status, 'executed': item.status == 'completed', 'outcome': item.outcome}

@router.get('/history')
def history(db: Session = Depends(db_session)):
    rows = db.scalars(select(DefenseAction).order_by(DefenseAction.id.desc()).limit(100)).all()
    return [{'id': x.id, 'action': x.action, 'target': x.target,
             'reason': x.reason, 'status': x.status, 'outcome': x.outcome,
             'requested_at': x.requested_at, 'completed_at': x.completed_at} for x in rows]
