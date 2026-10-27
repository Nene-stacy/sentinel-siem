# This helper adds an audit record to the current database transaction. 
# The endpoint will commit the business change and its audit record together, 
# so a failed transaction doesn't leave a misleading success audit

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def record_audit(
    db: Session,
    tenant_id: int,
    actor_user_id: int | None,
    action: str,
    target_type: str,
    target_id: str | None = None,
    details: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details or {},
        )
    )