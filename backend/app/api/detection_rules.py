
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.permissions import ORG_ADMIN, ANALYST, VIEWER, require_roles
from app.core.tenant import get_db
from app.models.detection_rule import DetectionRule
from app.models.user import User
from app.schemas.detection_rule import (
    DetectionRuleCreate,
    DetectionRuleResponse,
    DetectionRuleUpdate,
)
from app.services.audit import record_audit


router = APIRouter(
    prefix="/api/v1/detection-rules",
    tags=["Detection Rules"],
)


@router.post(
    "",
    response_model=DetectionRuleResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_detection_rule(
    rule_data: DetectionRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ORG_ADMIN)),
):
    rule = DetectionRule(
        organization_id=current_user.organization_id,
        **rule_data.model_dump(),
    )

    db.add(rule)

    try:
        db.flush()

        record_audit(
            db=db,
            tenant_id=current_user.organization_id,
            actor_user_id=current_user.id,
            action="detection_rule_created",
            target_type="detection_rule",
            target_id=rule.id,
            details={
                "name": rule.name,
                "rule_type": rule.rule_type,
            },
        )

        db.commit()
        db.refresh(rule)

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A detection rule with this name already exists.",
        )

    return rule


@router.get(
    "",
    response_model=list[DetectionRuleResponse],
)
def list_detection_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(ORG_ADMIN, ANALYST, VIEWER)
    ),
):
    return (
        db.query(DetectionRule)
        .filter(
            DetectionRule.organization_id
            == current_user.organization_id
        )
        .order_by(DetectionRule.id.asc())
        .all()
    )


@router.patch(
    "/{rule_id}",
    response_model=DetectionRuleResponse,
)
def update_detection_rule(
    rule_id: int,
    rule_data: DetectionRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ORG_ADMIN)),
):
    rule = (
        db.query(DetectionRule)
        .filter(
            DetectionRule.id == rule_id,
            DetectionRule.organization_id
            == current_user.organization_id,
        )
        .first()
    )

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection rule not found.",
        )

    changes = rule_data.model_dump(exclude_unset=True)

    if not changes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide at least one field to update.",
        )

    for field, value in changes.items():
        setattr(rule, field, value)

    try:
        record_audit(
            db=db,
            tenant_id=current_user.organization_id,
            actor_user_id=current_user.id,
            action="detection_rule_updated",
            target_type="detection_rule",
            target_id=rule.id,
            details={"changed_fields": list(changes.keys())},
        )

        db.commit()
        db.refresh(rule)

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A detection rule with this name already exists.",
        )

    return rule
