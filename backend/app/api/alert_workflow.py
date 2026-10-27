
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.permissions import (
    ANALYST,
    ORG_ADMIN,
    VIEWER,
    require_roles,
)
from app.core.tenant import get_db
from app.models.investigation_note import InvestigationNote
from app.models.user import User
from app.schemas.alert import AlertResponse
from app.schemas.investigation import (
    AlertStatusUpdate,
    InvestigationNoteCreate,
    InvestigationNoteResponse,
)
from app.services.alert_workflow import (
    add_investigation_note,
    change_alert_status,
    get_organization_alert,
)


router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["Alert Workflow"],
)

WRITERS = (ORG_ADMIN, ANALYST)


@router.patch("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*WRITERS)),
):
    """Acknowledge an alert or resolve an acknowledged alert."""

    alert = get_organization_alert(
        db,
        alert_id,
        current_user.organization_id,
    )

    return change_alert_status(
        db,
        alert,
        payload.status,
        current_user,
    )


@router.post(
    "/{alert_id}/notes",
    response_model=InvestigationNoteResponse,
    status_code=201,
)
def create_investigation_note(
    alert_id: int,
    payload: InvestigationNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(*WRITERS)),
):
    """Record a finding without overwriting the alert description."""

    alert = get_organization_alert(
        db,
        alert_id,
        current_user.organization_id,
    )

    return add_investigation_note(
        db,
        alert,
        payload.note,
        current_user,
    )


@router.get(
    "/{alert_id}/notes",
    response_model=list[InvestigationNoteResponse],
)
def list_investigation_notes(
    alert_id: int,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(ORG_ADMIN, ANALYST, VIEWER)
    ),
):
    """Show notes only when the alert belongs to the current organization."""

    alert = get_organization_alert(
        db,
        alert_id,
        current_user.organization_id,
    )

    return (
        db.query(InvestigationNote)
        .filter(
            InvestigationNote.alert_id == alert.id,
            InvestigationNote.tenant_id == current_user.organization_id,
        )
        .order_by(
            InvestigationNote.created_at.desc(),
            InvestigationNote.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )
