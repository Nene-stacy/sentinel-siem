
"""Tests for SEER's organization-scoped integration credentials."""

import hashlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.auth import get_current_user
from app.core.database import Base
from app.core.tenant import get_db
from app.main import app
from app.models.integration_credential import IntegrationCredential
from app.models.organization import Organization
from app.models.user import User
from app.services.integration_credentials import (
    verify_integration_credential,
)
from app.models.alert import Alert


@pytest.fixture
def db_session():
    """Give each test a fresh temporary database."""

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    TestSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    session = TestSession()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture
def test_environment(db_session):
    """Create an organization and its administrator."""

    organization = Organization(
        name="Integration Test Organization",
        slug="integration-test-org",
    )
    db_session.add(organization)
    db_session.flush()

    admin = User(
        organization_id=organization.id,
        email="integration-admin@example.test",
        password_hash="test-only-not-a-real-password-hash",
        role="ORG_ADMIN",
        is_active=True,
    )

    db_session.add(admin)
    db_session.commit()

    return {
        "organization": organization,
        "admin": admin,
    }


@pytest.fixture
def client(db_session, test_environment):
    """Override authentication and the database for API tests."""

    acting_user = {"user": test_environment["admin"]}

    def override_database():
        yield db_session

    def override_current_user():
        return acting_user["user"]

    app.dependency_overrides[get_db] = override_database
    app.dependency_overrides[get_current_user] = override_current_user

    try:
        with TestClient(app) as test_client:
            test_client.acting_user = acting_user
            yield test_client
    finally:
        app.dependency_overrides.clear()


def test_admin_can_create_wazuh_credential_securely(
    client,
    db_session,
    test_environment,
):
    """The key is returned once and only its hash is stored."""

    response = client.post(
        "/api/v1/integrations/credentials",
        json={
            "name": "Test Wazuh Manager",
            "provider": "wazuh",
        },
    )

    assert response.status_code == 201

    body = response.json()
    organization = test_environment["organization"]

    assert body["organization_id"] == organization.id
    assert body["name"] == "Test Wazuh Manager"
    assert body["provider"] == "wazuh"
    assert body["is_active"] is True

    raw_key = body["api_key"]
    assert raw_key.startswith(body["key_prefix"] + ".")

    # Verify that the database contains a hash, not the raw key.
    stored = (
        db_session.query(IntegrationCredential)
        .filter(IntegrationCredential.id == body["id"])
        .one()
    )

    expected_hash = hashlib.sha256(
        raw_key.encode("utf-8")
    ).hexdigest()

    assert stored.key_hash == expected_hash
    assert stored.key_hash != raw_key

    # Verify the key is accepted and linked to the right organization.
    verified = verify_integration_credential(
        db_session,
        raw_key,
        provider="wazuh",
    )

    assert verified is not None
    assert verified.organization_id == organization.id
    assert verified.is_active is True
    assert verified.last_used_at is not None

def test_wazuh_ingestion_rejects_invalid_api_key(client):
    """Wazuh alerts must not be accepted without a valid integration key."""

    response = client.post(
        "/api/v1/integrations/wazuh/alerts",
        headers={
            "X-SEER-API-Key": "invalid-test-key",
        },
        json={
            "id": "wazuh-test-alert-001",
            "timestamp": "2026-10-27T12:00:00Z",
            "rule": {
                "id": "5710",
                "level": 5,
                "description": "Multiple authentication failures",
            },
            "agent": {
                "id": "001",
                "name": "test-agent",
                "ip": "192.0.2.10",
            },
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid or inactive integration API key"
    )


def test_valid_wazuh_key_ingests_alert_and_deduplicates(
    client,
    db_session,
    test_environment,
):
    """A valid key ingests an alert once, even if Wazuh retries."""

    # Create a Wazuh credential through the administrator API.
    credential_response = client.post(
        "/api/v1/integrations/credentials",
        json={
            "name": "Wazuh ingestion test",
            "provider": "wazuh",
        },
    )

    assert credential_response.status_code == 201
    api_key = credential_response.json()["api_key"]

    payload = {
        "id": "wazuh-alert-test-20261027-001",
        "timestamp": "2026-10-27T12:00:00Z",
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "Multiple authentication failures",
        },
        "agent": {
            "id": "001",
            "name": "test-agent",
            "ip": "192.0.2.10",
        },
        "full_log": "Synthetic Wazuh alert for integration testing",
    }

    headers = {"X-SEER-API-Key": api_key}
    organization = test_environment["organization"]

    # First delivery should create the alert.
    first_response = client.post(
        "/api/v1/integrations/wazuh/alerts",
        headers=headers,
        json=payload,
    )

    assert first_response.status_code == 200

    first_alert = first_response.json()

    assert first_alert["tenant_id"] == organization.id
    assert first_alert["source"] == "wazuh"
    assert first_alert["source_alert_id"] == payload["id"]
    assert first_alert["severity"] == 2
    assert first_alert["status"] == "OPEN"
    assert first_alert["detected_at"] is not None

    # Simulate Wazuh retrying the same alert.
    second_response = client.post(
        "/api/v1/integrations/wazuh/alerts",
        headers=headers,
        json=payload,
    )

    assert second_response.status_code == 200
    assert second_response.json()["id"] == first_alert["id"]

    # Only one database alert should exist for this external alert ID.
    stored_alerts = (
        db_session.query(Alert)
        .filter(
            Alert.tenant_id == organization.id,
            Alert.source_alert_id == payload["id"],
        )
        .all()
    )

    assert len(stored_alerts) == 1

def test_wazuh_key_cannot_choose_another_organization(
    client,
    db_session,
    test_environment,
):
    """The integration credential determines the alert's organization."""

    # Create a Wazuh credential for Organization A.
    credential_response = client.post(
        "/api/v1/integrations/credentials",
        json={
            "name": "Organization A Wazuh",
            "provider": "wazuh",
        },
    )

    assert credential_response.status_code == 201
    api_key = credential_response.json()["api_key"]

    organization_a = test_environment["organization"]

    # Create a second organization.
    organization_b = Organization(
        name="Other Integration Organization",
        slug="other-integration-org",
    )
    db_session.add(organization_b)
    db_session.commit()
    db_session.refresh(organization_b)

    # Even if the incoming payload claims it belongs to Organization B,
    # the verified credential must determine where SEER stores it.
    payload = {
        "id": "wazuh-tenant-isolation-test-001",
        "timestamp": "2026-10-27T12:00:00Z",
        "organization_id": organization_b.id,
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "Synthetic tenant-isolation test alert",
        },
        "agent": {
            "id": "001",
            "name": "test-agent",
        },
    }

    response = client.post(
        "/api/v1/integrations/wazuh/alerts",
        headers={"X-SEER-API-Key": api_key},
        json=payload,
    )

    assert response.status_code == 200
    assert response.json()["tenant_id"] == organization_a.id
    assert response.json()["tenant_id"] != organization_b.id

    stored_alert = (
        db_session.query(Alert)
        .filter(
            Alert.source_alert_id == payload["id"],
        )
        .one()
    )

    assert stored_alert.tenant_id == organization_a.id
