"""Create and verify API credentials for external integrations."""

import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.integration_credential import IntegrationCredential


def create_integration_credential(
    db: Session,
    organization_id: int,
    name: str,
    provider: str = "wazuh",
) -> tuple[IntegrationCredential, str]:
    """
    Create an integration key.

    The raw key is returned once to the caller.
    Only its SHA-256 hash is stored in the database.
    """

    # The unique prefix lets SEER find a credential without storing
    # the complete secret. Its length fits the model's String(12).
    key_prefix = "sk" + secrets.token_hex(5)

    secret = secrets.token_urlsafe(32)
    raw_key = f"{key_prefix}.{secret}"

    key_hash = hashlib.sha256(
        raw_key.encode("utf-8")
    ).hexdigest()

    credential = IntegrationCredential(
        organization_id=organization_id,
        name=name.strip(),
        provider=provider.strip().lower(),
        key_prefix=key_prefix,
        key_hash=key_hash,
        is_active=True,
    )

    try:
        db.add(credential)
        db.commit()
        db.refresh(credential)
    except Exception:
        db.rollback()
        raise

    return credential, raw_key


def verify_integration_credential(
    db: Session,
    raw_key: str,
    provider: str = "wazuh",
) -> IntegrationCredential | None:
    """Verify an active key for the requested integration provider."""

    if not raw_key or "." not in raw_key:
        return None

    key_prefix = raw_key.split(".", 1)[0]

    credential = (
        db.query(IntegrationCredential)
        .filter(
            IntegrationCredential.key_prefix == key_prefix,
            IntegrationCredential.provider == provider.strip().lower(),
            IntegrationCredential.is_active.is_(True),
        )
        .first()
    )

    if credential is None:
        return None

    supplied_hash = hashlib.sha256(
        raw_key.encode("utf-8")
    ).hexdigest()

    if not hmac.compare_digest(
        credential.key_hash,
        supplied_hash,
    ):
        return None

    credential.last_used_at = datetime.now(timezone.utc)

    try:
        db.commit()
        db.refresh(credential)
    except Exception:
        db.rollback()
        raise

    return credential