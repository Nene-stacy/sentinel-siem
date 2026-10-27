from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models.organization import Organization
from app.models.user import User


db = SessionLocal()

try:
    organization = (
        db.query(Organization)
        .filter(
            Organization.slug == "sentinel-test"
        )
        .first()
    )

    if organization is None:
        raise RuntimeError(
            "sentinel-test organization does not exist"
        )

    existing_user = (
        db.query(User)
        .filter(
            User.email == "admin@sentinel.local"
        )
        .first()
    )

    if existing_user:
        print("Development admin already exists.")

    else:
        user = User(
            organization_id=organization.id,
            email="admin@sentinel.local",
            password_hash=hash_password(
                "SentinelDev123!"
            ),
            role="ORG_ADMIN",
            is_active=True
        )

        db.add(user)
        db.commit()

        print("Development admin created.")
        print("Email: admin@sentinel.local")
        print("Password: SentinelDev123!")

finally:
    db.close()
    