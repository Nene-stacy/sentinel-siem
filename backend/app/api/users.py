
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.permissions import require_roles, ORG_ADMIN
from app.core.security import hash_password
from app.core.tenant import get_db
from app.models.user import User
from app.schemas.users import UserCreate, UserSummary
from app.services.audit import record_audit


router = APIRouter(
    prefix="/api/v1/users",
    tags=["Organization Users"],
)


@router.get("/", response_model=list[UserSummary])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ORG_ADMIN)),
):
    return (
        db.query(User)
        .filter(
            User.organization_id == current_user.organization_id
        )
        .order_by(User.id)
        .all()
    )


@router.post(
    "/",
    response_model=UserSummary,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ORG_ADMIN)),
):
    email = payload.email.strip().lower()

    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A valid email address is required",
        )

    user = User(
        organization_id=current_user.organization_id,
        email=email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )

    db.add(user)

    try:
        db.flush()

        record_audit(
            db=db,
            tenant_id=current_user.organization_id,
            actor_user_id=current_user.id,
            action="USER_CREATED",
            target_type="user",
            target_id=str(user.id),
            details={"role": user.role},
        )

        db.commit()
        db.refresh(user)

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        )

    return user


@router.patch("/{user_id}/deactivate", response_model=UserSummary)
def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ORG_ADMIN)),
):
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account here",
        )

    target = (
        db.query(User)
        .filter(
            User.id == user_id,
            User.organization_id == current_user.organization_id,
        )
        .first()
    )

    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not target.is_active:
        return target

    if target.role == ORG_ADMIN:
        other_active_admins = (
            db.query(User)
            .filter(
                User.organization_id == current_user.organization_id,
                User.role == ORG_ADMIN,
                User.is_active.is_(True),
                User.id != target.id,
            )
            .count()
        )

        if other_active_admins == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cannot deactivate the organization's last active administrator",
            )

    target.is_active = False

    record_audit(
        db=db,
        tenant_id=current_user.organization_id,
        actor_user_id=current_user.id,
        action="USER_DEACTIVATED",
        target_type="user",
        target_id=str(target.id),
        details={"role": target.role},
    )

    db.commit()
    db.refresh(target)

    return target