from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.organization import Organization


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def get_current_tenant(
    db: Session = Depends(get_db)
) -> Organization:

    tenant = (
        db.query(Organization)
        .filter(Organization.slug == "sentinel-test")
        .first()
    )

    if tenant is None:
        raise HTTPException(
            status_code=500,
            detail="Development tenant not found"
        )

    return tenant