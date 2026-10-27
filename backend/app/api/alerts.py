
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.permissions import (
    ANALYST,
    ORG_ADMIN,
    VIEWER,
    require_roles,
)
from app.core.tenant import get_db
from app.models.alert import Alert
from app.models.event import Event
from app.models.user import User
from app.schemas.alert import AlertIngest, AlertResponse


router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["Alerts"],
)


@router.post("/", response_model=AlertResponse)
def ingest_alert(
    payload: AlertIngest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(ORG_ADMIN, ANALYST)
    ),
):
    # If an event is attached, verify it belongs to this tenant.
    if payload.event_id is not None:
        event = db.query(Event).filter(
            Event.id == payload.event_id,
            Event.tenant_id == current_user.organization_id,
        ).first()

        if event is None:
            raise HTTPException(
                status_code=404,
                detail="Event not found",
            )

    # Basic duplicate check for alerts with a source ID.
    if payload.source_alert_id is not None:
        existing = db.query(Alert).filter(
            Alert.tenant_id == current_user.organization_id,
            Alert.source == payload.source,
            Alert.source_alert_id == payload.source_alert_id,
        ).first()

        if existing is not None:
            return existing

    alert = Alert(
        tenant_id=current_user.organization_id,
        event_id=payload.event_id,
        alert_type="SOURCE",
        source=payload.source,
        source_alert_id=payload.source_alert_id,
        rule_name=payload.rule_name,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        status="OPEN",
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert


@router.get("/", response_model=list[AlertResponse])
def list_alerts(
    status: str | None = Query(default=None, max_length=30),
    source: str | None = Query(default=None, max_length=50),
    alert_type: str | None = Query(default=None, max_length=30),
    severity: int | None = Query(default=None, ge=1, le=5),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(ORG_ADMIN, ANALYST, VIEWER)
    ),
):
    query = db.query(Alert).filter(
        Alert.tenant_id == current_user.organization_id
    )

    if status is not None:
        query = query.filter(Alert.status == status.upper())

    if source is not None:
        query = query.filter(Alert.source == source)

    if alert_type is not None:
        query = query.filter(Alert.alert_type == alert_type.upper())

    if severity is not None:
        query = query.filter(Alert.severity == severity)

    return (
        query.order_by(Alert.created_at.desc(), Alert.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )