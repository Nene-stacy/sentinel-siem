"""API endpoints for managing external integration credentials."""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.permissions import ORG_ADMIN, require_roles
from app.core.tenant import get_db
from app.models.user import User
from app.schemas.integration_credential import (
    IntegrationCredentialCreate,
    IntegrationCredentialCreated,
)
from app.services.integration_credentials import (
    create_integration_credential,
)
import hashlib
from datetime import datetime, timezone

from fastapi import Header

from app.models.alert import Alert
from app.schemas.alert import AlertResponse
from app.schemas.wazuh import WazuhAlertPayload
from app.services.integration_credentials import (
    verify_integration_credential,
)


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/integrations",
    tags=["Integrations"],
)


@router.post(
    "/credentials",
    response_model=IntegrationCredentialCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_credential(
    payload: IntegrationCredentialCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ORG_ADMIN)),
):
    """
    Create an organization-scoped credential for an integration.

    The organization ID comes from the authenticated administrator.
    The raw API key is returned only when it is created.
    """

    try:
        credential, raw_key = create_integration_credential(
            db=db,
            organization_id=current_user.organization_id,
            name=payload.name,
            provider=payload.provider,
        )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "A credential with this name already exists "
                "for your organization, or a key-prefix collision occurred."
            ),
        ) from exc

    logger.info(
        "Integration credential created: credential_id=%s "
        "organization_id=%s provider=%s",
        credential.id,
        credential.organization_id,
        credential.provider,
    )

    return IntegrationCredentialCreated(
        id=credential.id,
        organization_id=credential.organization_id,
        name=credential.name,
        provider=credential.provider,
        key_prefix=credential.key_prefix,
        api_key=raw_key,
        is_active=credential.is_active,
        created_at=credential.created_at,
    )

def map_wazuh_severity(level: int) -> int:
    """Map Wazuh rule levels (0–16) to SEER severity (1–5)."""

    if level <= 3:
        return 1
    if level <= 6:
        return 2
    if level <= 9:
        return 3
    if level <= 12:
        return 4
    return 5


@router.post(
    "/wazuh/alerts",
    response_model=AlertResponse,
)
def ingest_wazuh_alert(
    payload: WazuhAlertPayload,
    x_seer_api_key: str | None = Header(
        default=None,
        alias="X-SEER-API-Key",
    ),
    db: Session = Depends(get_db),
):
    """
    Accept a Wazuh alert using an organization-scoped API key.

    The organization is derived from the verified credential, never
    from the submitted Wazuh payload.
    """

    if not x_seer_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing integration API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    credential = verify_integration_credential(
        db=db,
        raw_key=x_seer_api_key,
        provider="wazuh",
    )

    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive integration API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Hash the external alert ID to build a compact, stable
    # deduplication key scoped to this integration credential.
    external_id_hash = hashlib.sha256(
        payload.id.encode("utf-8")
    ).hexdigest()

    deduplication_key = (
        f"wazuh:credential-{credential.id}:{external_id_hash}"
    )

    existing = (
        db.query(Alert)
        .filter(
            Alert.tenant_id == credential.organization_id,
            Alert.deduplication_key == deduplication_key,
        )
        .first()
    )

    # Wazuh may retry delivery. Return the existing alert instead
    # of creating a duplicate.
    if existing is not None:
        return existing

    detected_at = payload.timestamp or datetime.now(timezone.utc)

    if detected_at.tzinfo is None:
        detected_at = detected_at.replace(tzinfo=timezone.utc)

    description_parts = [
        (
            f"Wazuh rule {payload.rule.id}, "
            f"level {payload.rule.level}: "
            f"{payload.rule.description}"
        )
    ]

    if payload.agent is not None:
        agent_details = []

        if payload.agent.name:
            agent_details.append(f"name={payload.agent.name}")
        if payload.agent.id:
            agent_details.append(f"id={payload.agent.id}")
        if payload.agent.ip:
            agent_details.append(f"ip={payload.agent.ip}")

        if agent_details:
            description_parts.append(
                "Agent: " + ", ".join(agent_details)
            )

    if payload.location:
        description_parts.append(
            f"Wazuh location: {payload.location}"
        )

    if payload.full_log:
        description_parts.append(
            "Full log: " + payload.full_log[:4000]
        )

    alert = Alert(
        tenant_id=credential.organization_id,
        event_id=None,
        alert_type="SOURCE",
        source="wazuh",
        source_alert_id=payload.id,
        deduplication_key=deduplication_key,
        rule_name=f"wazuh:{payload.rule.id}",
        title=payload.rule.description[:255],
        description="\n".join(description_parts),
        severity=map_wazuh_severity(payload.rule.level),
        status="OPEN",
        detected_at=detected_at,
    )

    try:
        db.add(alert)
        db.commit()
        db.refresh(alert)

    except IntegrityError:
        # Another request might have inserted the same alert
        # between our duplicate check and database commit.
        db.rollback()

        existing = (
            db.query(Alert)
            .filter(
                Alert.tenant_id == credential.organization_id,
                Alert.deduplication_key == deduplication_key,
            )
            .first()
        )

        if existing is not None:
            return existing

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Could not store the Wazuh alert due to a database constraint",
        )

    logger.info(
        "Wazuh alert ingested: alert_id=%s organization_id=%s",
        alert.id,
        credential.organization_id,
    )

    return alert