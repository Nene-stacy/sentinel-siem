
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.investigation_note import InvestigationNote
from app.models.user import User
from app.services.audit import record_audit


ALLOWED_TRANSITIONS = {
    "OPEN": {"ACKNOWLEDGED"},
    "ACKNOWLEDGED": {"OPEN", "RESOLVED"},
    "RESOLVED": set(),
}


def get_organization_alert(
    db: Session,
    alert_id: int,
    organization_id: int,
) -> Alert:
    """Never return an alert belonging to another organization."""

    alert = (
        db.query(Alert)
        .filter(
            Alert.id == alert_id,
            Alert.tenant_id == organization_id,
        )
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    return alert


def change_alert_status(
    db: Session,
    alert: Alert,
    requested_status: str,
    current_user: User,
) -> Alert:
    """Validate the transition and audit it in the same transaction."""

    new_status = requested_status.strip().upper()
    old_status = alert.status.upper()

    if new_status not in ALLOWED_TRANSITIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Unsupported alert status",
        )

    if new_status == old_status:
        return alert

    if new_status not in ALLOWED_TRANSITIONS.get(old_status, set()):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot change an alert from {old_status} to {new_status}",
        )

    alert.status = new_status

    record_audit(
        db=db,
        tenant_id=current_user.organization_id,
        actor_user_id=current_user.id,
        action="alert.status_changed",
        target_type="alert",
        target_id=str(alert.id),
        details={
            "previous_status": old_status,
            "new_status": new_status,
        },
    )

    db.commit()
    db.refresh(alert)

    return alert


def add_investigation_note(
    db: Session,
    alert: Alert,
    note_text: str,
    current_user: User,
) -> InvestigationNote:
    """Save a finding and its audit record together."""

    clean_note = note_text.strip()

    if not clean_note:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Investigation note cannot be blank",
        )

    note = InvestigationNote(
        tenant_id=current_user.organization_id,
        alert_id=alert.id,
        author_user_id=current_user.id,
        note=clean_note,
    )

    db.add(note)
    db.flush()

    record_audit(
        db=db,
        tenant_id=current_user.organization_id,
        actor_user_id=current_user.id,
        action="alert.investigation_note_added",
        target_type="alert",
        target_id=str(alert.id),
        details={"note_id": note.id},
    )

    db.commit()
    db.refresh(note)

    return note
