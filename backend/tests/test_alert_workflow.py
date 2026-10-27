
"""Automated tests for SEER's alert investigation workflow."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.auth import get_current_user
from app.core.tenant import get_db
from app.main import app

# Import the models so SQLAlchemy knows which tables to create.
from app.models.organization import Organization
from app.models.user import User
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.investigation_note import InvestigationNote


@pytest.fixture
def db_session():
    """Give every test its own temporary database."""
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
    """Create two organizations and a test user for each one."""
    organization_a = Organization(
        name="Organization A",
        slug="organization-a",
    )
    organization_b = Organization(
        name="Organization B",
        slug="organization-b",
    )

    db_session.add_all([organization_a, organization_b])
    db_session.flush()

    analyst = User(
        organization_id=organization_a.id,
        email="analyst-a@example.test",
        password_hash="not-a-real-password-hash",
        role="ANALYST",
        is_active=True,
    )

    viewer = User(
        organization_id=organization_a.id,
        email="viewer-a@example.test",
        password_hash="not-a-real-password-hash",
        role="VIEWER",
        is_active=True,
    )

    other_analyst = User(
        organization_id=organization_b.id,
        email="analyst-b@example.test",
        password_hash="not-a-real-password-hash",
        role="ANALYST",
        is_active=True,
    )

    db_session.add_all([analyst, viewer, other_analyst])
    db_session.flush()

    alert_a = Alert(
        tenant_id=organization_a.id,
        alert_type="failed_login",
        source="SENTINEL",
        rule_name="Repeated failed logins",
        title="Multiple failed login attempts",
        description="Several failed logins from one IP address.",
        severity=4,
        status="OPEN",
    )

    alert_b = Alert(
        tenant_id=organization_b.id,
        alert_type="failed_login",
        source="SENTINEL",
        rule_name="Repeated failed logins",
        title="Organization B alert",
        description="This alert belongs to Organization B.",
        severity=4,
        status="OPEN",
    )

    db_session.add_all([alert_a, alert_b])
    db_session.commit()

    return {
        "organization_a": organization_a,
        "organization_b": organization_b,
        "analyst": analyst,
        "viewer": viewer,
        "other_analyst": other_analyst,
        "alert_a": alert_a,
        "alert_b": alert_b,
    }


@pytest.fixture
def client(db_session, test_environment):
    """Use the test database and a selectable test user for API requests."""
    acting_user = {"user": test_environment["analyst"]}

    def override_database():
        yield db_session

    def override_current_user():
        return acting_user["user"]

    app.dependency_overrides[get_db] = override_database
    app.dependency_overrides[get_current_user] = override_current_user

    with TestClient(app) as test_client:
        # Tests can switch between analyst, viewer, and other-tenant users.
        test_client.acting_user = acting_user
        yield test_client

    app.dependency_overrides.clear()


def test_analyst_can_acknowledge_and_resolve_alert(client, test_environment):
    """An alert must be acknowledged before it can be resolved."""
    alert_id = test_environment["alert_a"].id

    response = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "ACKNOWLEDGED"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ACKNOWLEDGED"

    response = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "RESOLVED"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "RESOLVED"


def test_open_alert_cannot_be_resolved_directly(client, test_environment):
    """The workflow must reject a skipped status."""
    alert_id = test_environment["alert_a"].id

    response = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "RESOLVED"},
    )

    assert response.status_code == 409


def test_analyst_can_add_and_read_investigation_note(client, test_environment):
    """A note should be saved and returned by the notes endpoint."""
    alert_id = test_environment["alert_a"].id

    response = client.post(
        f"/api/v1/alerts/{alert_id}/notes",
        json={"note": "  Checked the source IP address.  "},
    )

    assert response.status_code == 201
    assert response.json()["note"] == "Checked the source IP address."

    response = client.get(f"/api/v1/alerts/{alert_id}/notes")

    assert response.status_code == 200
    notes = response.json()
    assert len(notes) == 1
    assert notes[0]["note"] == "Checked the source IP address."
    assert notes[0]["author_user_id"] == test_environment["analyst"].id


def test_viewer_can_read_but_cannot_modify_alert(client, test_environment):
    """Viewers can investigate existing records but cannot change them."""
    client.acting_user["user"] = test_environment["viewer"]
    alert_id = test_environment["alert_a"].id

    read_response = client.get(f"/api/v1/alerts/{alert_id}/notes")
    assert read_response.status_code == 200

    status_response = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "ACKNOWLEDGED"},
    )
    assert status_response.status_code == 403

    note_response = client.post(
        f"/api/v1/alerts/{alert_id}/notes",
        json={"note": "Viewer attempting to add a note."},
    )
    assert note_response.status_code == 403


def test_organization_cannot_access_another_organizations_alert(
    client, test_environment
):
    """An alert ID must not allow access across organization boundaries."""
    client.acting_user["user"] = test_environment["analyst"]
    foreign_alert_id = test_environment["alert_b"].id

    notes_response = client.get(
        f"/api/v1/alerts/{foreign_alert_id}/notes"
    )
    assert notes_response.status_code == 404

    status_response = client.patch(
        f"/api/v1/alerts/{foreign_alert_id}/status",
        json={"status": "ACKNOWLEDGED"},
    )
    assert status_response.status_code == 404


def test_status_change_creates_audit_record(
    client, db_session, test_environment
):
    """A successful status change should leave an audit trail."""
    alert_id = test_environment["alert_a"].id

    response = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "ACKNOWLEDGED"},
    )
    assert response.status_code == 200

    audit_entry = (
        db_session.query(AuditLog)
        .filter(
            AuditLog.tenant_id == test_environment["organization_a"].id,
            AuditLog.action == "alert.status_changed",
            AuditLog.target_id == str(alert_id),
        )
        .first()
    )

    assert audit_entry is not None
    assert audit_entry.details["previous_status"] == "OPEN"
    assert audit_entry.details["new_status"] == "ACKNOWLEDGED"
