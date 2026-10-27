
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.tenant import get_db
from app.core.auth import get_current_user
from app.core.permissions import require_roles
from app.models.user import User
# from app.models.alert import Alert
from app.services.detection import detect_failed_logins
from app.schemas.alert import AlertResponse
# from app.models.detection_rule import DetectionRule
from app.services.detection import detect_configured_rules


router = APIRouter(
    prefix="/api/v1/detection",
    tags=["Detection"],
)


@router.post(
    "/failed-logins",
    response_model=list[AlertResponse],
)
def run_failed_login_detection(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("ORG_ADMIN", "ANALYST")
    ),
):
    """
    Run enabled failed-login rules for the authenticated organization.
    """

    return detect_configured_rules(
        db=db,
        tenant_id=current_user.organization_id,
    )
