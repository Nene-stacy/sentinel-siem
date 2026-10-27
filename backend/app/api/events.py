
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.tenant import get_db
from app.models.event import Event
from app.models.user import User
from app.schemas.event import EventResponse, SecurityEvent


router = APIRouter(
    prefix="/api/v1/events",
    tags=["Events"]
)


@router.post("/")
def ingest_event(
    event: SecurityEvent,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db_event = Event(
        tenant_id=current_user.organization_id,
        timestamp=event.timestamp,
        source=event.source,
        event_type=event.event_type,
        severity=event.severity,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        username=event.username,
        message=event.message
    )

    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    return {
        "status": "stored",
        "event_id": db_event.id
    }


@router.get("/", response_model=list[EventResponse])
def get_events(
    source: str | None = None,
    event_type: str | None = None,
    severity: int | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = (
        db.query(Event)
        .filter(
            Event.tenant_id == current_user.organization_id
        )
    )

    if source:
        query = query.filter(Event.source == source)

    if event_type:
        query = query.filter(Event.event_type == event_type)

    if severity is not None:
        query = query.filter(Event.severity == severity)

    return (
        query
        .order_by(Event.timestamp.desc())
        .all()
    )