# this file determined users permission i.e who can access what
# role base 

from collections.abc import Callable

from fastapi import Depends, HTTPException, status

from app.core.auth import get_current_user
from app.models.user import User


ORG_ADMIN = "ORG_ADMIN"
ANALYST = "ANALYST"
VIEWER = "VIEWER"


def require_roles(*allowed_roles: str) -> Callable:
    """Allow access only to users with one of the specified roles."""

    def role_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )

        return current_user

    return role_checker