
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.exc import IntegrityError

from app.core.database import Base
from app.models.alert import Alert
from app.models.event import Event
from app.models.organization import Organization
from app.services.detection import detect_failed_logins
from app.models.detection_rule import DetectionRule
from app.services.detection import detect_configured_rules


@pytest.fixture
def db_session():
    """Give each test a fresh, temporary database."""

    # Keep the in-memory database available throughout this test session.
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


def create_organization(db_session, name, slug):
    """Create an organization that can own test events."""

    organization = Organization(name=name, slug=slug)
    db_session.add(organization)
    db_session.commit()
    db_session.refresh(organization)

    return organization


def record_failed_login(
    db_session,
    tenant_id,
    timestamp,
    source_ip="192.168.1.50",
    username="testuser",
):
    """Record one failed login using the same model as production."""

    event = Event(
        tenant_id=tenant_id,
        timestamp=timestamp,
        source="wazuh",
        event_type="authentication_failure",
        severity=5,
        source_ip=source_ip,
        username=username,
        message="Failed login attempt",
    )

    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    return event


def create_detection_rule(
    db_session,
    organization_id,
    name="Custom failed-login rule",
    threshold=3,
    window_minutes=5,
    severity=2,
    is_enabled=True,
):
    """Create a saved rule belonging to one organization."""

    rule = DetectionRule(
        organization_id=organization_id,
        name=name,
        rule_type="repeated_failed_logins",
        threshold=threshold,
        window_minutes=window_minutes,
        severity=severity,
        is_enabled=is_enabled,
    )

    db_session.add(rule)
    db_session.commit()
    db_session.refresh(rule)

    return rule



def test_four_failed_logins_do_not_create_an_alert(db_session):
    """Four failures are below the configured threshold of five."""

    organization = create_organization(
        db_session, "Test Organization", "test-org"
    )
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)

    for attempt in range(4):
        record_failed_login(
            db_session,
            organization.id,
            now - timedelta(seconds=attempt * 30),
        )

    alerts = detect_failed_logins(
        db_session,
        tenant_id=organization.id,
        threshold=5,
        window_minutes=5,
        now=now,
    )

    assert alerts == []
    assert db_session.query(Alert).count() == 0


def test_five_failed_logins_create_a_sentinel_alert(db_session):
    """Five recent failures from one IP should trigger our rule."""

    organization = create_organization(
        db_session, "Test Organization", "test-org"
    )
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)

    for attempt in range(5):
        record_failed_login(
            db_session,
            organization.id,
            now - timedelta(seconds=attempt * 30),
        )

    alerts = detect_failed_logins(
        db_session,
        tenant_id=organization.id,
        threshold=5,
        window_minutes=5,
        now=now,
    )

    assert len(alerts) == 1
    assert alerts[0].alert_type == "SENTINEL"
    assert alerts[0].rule_name == "repeated_failed_logins"
    assert alerts[0].tenant_id == organization.id
    assert alerts[0].severity == 4


def test_old_failures_do_not_trigger_an_alert(db_session):
    """Failures outside the five-minute window must not count."""

    organization = create_organization(
        db_session, "Test Organization", "test-org"
    )
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)

    for attempt in range(5):
        record_failed_login(
            db_session,
            organization.id,
            now - timedelta(minutes=6, seconds=attempt * 10),
        )

    alerts = detect_failed_logins(
        db_session,
        tenant_id=organization.id,
        threshold=5,
        window_minutes=5,
        now=now,
    )

    assert alerts == []


def test_another_organizations_events_do_not_count(db_session):
    """One organization's activity must not affect another's detection."""

    organization_a = create_organization(
        db_session, "Organization A", "org-a"
    )
    organization_b = create_organization(
        db_session, "Organization B", "org-b"
    )
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)

    # Organization A has four failures from this IP.
    for attempt in range(4):
        record_failed_login(
            db_session,
            organization_a.id,
            now - timedelta(seconds=attempt * 30),
        )

    # Organization B has one failure from the same IP.
    record_failed_login(
        db_session,
        organization_b.id,
        now,
    )

    alerts = detect_failed_logins(
        db_session,
        tenant_id=organization_a.id,
        threshold=5,
        window_minutes=5,
        now=now,
    )

    assert alerts == []
    assert (
        db_session.query(Alert)
        .filter(Alert.tenant_id == organization_a.id)
        .count()
        == 0
    )


def test_running_detection_twice_does_not_duplicate_open_alert(
    db_session,
):
    """Repeated checks should reuse an existing open alert."""

    organization = create_organization(
        db_session, "Test Organization", "test-org"
    )
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)

    for attempt in range(5):
        record_failed_login(
            db_session,
            organization.id,
            now - timedelta(seconds=attempt * 30),
        )

    first_run = detect_failed_logins(
        db_session, organization.id, now=now
    )
    second_run = detect_failed_logins(
        db_session, organization.id, now=now
    )

    assert len(first_run) == 1
    assert second_run == []
    assert db_session.query(Alert).count() == 1
    
    
def test_duplicate_deduplication_key_is_rejected_for_same_organization(
    db_session,
):
    """The database must reject duplicate keys within one organization."""

    organization_a = create_organization(
        db_session, "Organization A", "org-a"
    )
    organization_b = create_organization(
        db_session, "Organization B", "org-b"
    )

    shared_key = "failed-login:v1:192.168.1.50:100"

    first_alert = Alert(
        tenant_id=organization_a.id,
        alert_type="SENTINEL",
        source="sentinel",
        rule_name="repeated_failed_logins",
        title="Repeated failed logins from 192.168.1.50",
        description="Test alert for deduplication.",
        severity=4,
        status="OPEN",
        deduplication_key=shared_key,
    )

    db_session.add(first_alert)
    db_session.commit()

    # The same key is allowed for a different organization.
    other_organization_alert = Alert(
        tenant_id=organization_b.id,
        alert_type="SENTINEL",
        source="sentinel",
        rule_name="repeated_failed_logins",
        title="Repeated failed logins from 192.168.1.50",
        description="Separate organization's test alert.",
        severity=4,
        status="OPEN",
        deduplication_key=shared_key,
    )

    db_session.add(other_organization_alert)
    db_session.commit()

    # But reusing that key within Organization A must fail.
    duplicate_alert = Alert(
        tenant_id=organization_a.id,
        alert_type="SENTINEL",
        source="sentinel",
        rule_name="repeated_failed_logins",
        title="Duplicate test alert",
        description="This duplicate should be rejected.",
        severity=4,
        status="OPEN",
        deduplication_key=shared_key,
    )

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(duplicate_alert)
            db_session.flush()

    # The failed insert must not affect the two valid alerts.
    assert db_session.query(Alert).count() == 2


def test_saved_rule_controls_threshold_and_severity(db_session):
    """The saved threshold and severity must be used."""

    organization = create_organization(
        db_session, "Organization A", "org-a"
    )
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)

    create_detection_rule(
        db_session,
        organization.id,
        name="Three login failures",
        threshold=3,
        severity=2,
    )

    for attempt in range(3):
        record_failed_login(
            db_session,
            organization.id,
            now - timedelta(seconds=attempt * 30),
        )

    alerts = detect_configured_rules(
        db_session, organization.id, now=now
    )

    assert len(alerts) == 1
    assert alerts[0].rule_name == "Three login failures"
    assert alerts[0].severity == 2
    assert "3 authentication failures" in alerts[0].description


def test_disabled_rule_does_not_generate_alert(db_session):
    """A saved but disabled rule must not run."""

    organization = create_organization(
        db_session, "Organization A", "org-a"
    )
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)

    create_detection_rule(
        db_session,
        organization.id,
        threshold=3,
        is_enabled=False,
    )

    for attempt in range(5):
        record_failed_login(
            db_session,
            organization.id,
            now - timedelta(seconds=attempt * 30),
        )

    alerts = detect_configured_rules(
        db_session, organization.id, now=now
    )

    assert alerts == []
    assert db_session.query(Alert).count() == 0


def test_saved_rule_respects_its_time_window(db_session):
    """Failures outside a rule's window must not count."""

    organization = create_organization(
        db_session, "Organization A", "org-a"
    )
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)

    create_detection_rule(
        db_session,
        organization.id,
        threshold=3,
        window_minutes=2,
    )

    for attempt in range(3):
        record_failed_login(
            db_session,
            organization.id,
            now - timedelta(minutes=4, seconds=attempt * 10),
        )

    alerts = detect_configured_rules(
        db_session, organization.id, now=now
    )

    assert alerts == []


def test_saved_rules_are_isolated_between_organizations(db_session):
    """One organization's saved rule must not affect another."""

    organization_a = create_organization(
        db_session, "Organization A", "org-a"
    )
    organization_b = create_organization(
        db_session, "Organization B", "org-b"
    )
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)

    create_detection_rule(
        db_session,
        organization_a.id,
        threshold=3,
    )

    for attempt in range(3):
        timestamp = now - timedelta(seconds=attempt * 30)

        record_failed_login(
            db_session, organization_a.id, timestamp
        )
        record_failed_login(
            db_session, organization_b.id, timestamp
        )

    alerts_a = detect_configured_rules(
        db_session, organization_a.id, now=now
    )
    alerts_b = detect_configured_rules(
        db_session, organization_b.id, now=now
    )

    assert len(alerts_a) == 1
    assert alerts_b == []

    assert (
        db_session.query(Alert)
        .filter(Alert.tenant_id == organization_a.id)
        .count()
        == 1
    )
    assert (
        db_session.query(Alert)
        .filter(Alert.tenant_id == organization_b.id)
        .count()
        == 0
    )


def test_two_saved_rules_can_create_separate_alerts(db_session):
    """Two matching rules can generate distinct alerts."""

    organization = create_organization(
        db_session, "Organization A", "org-a"
    )
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)

    create_detection_rule(
        db_session,
        organization.id,
        name="Three failures",
        threshold=3,
        severity=2,
    )
    create_detection_rule(
        db_session,
        organization.id,
        name="Five failures",
        threshold=5,
        severity=5,
    )

    for attempt in range(5):
        record_failed_login(
            db_session,
            organization.id,
            now - timedelta(seconds=attempt * 30),
        )

    alerts = detect_configured_rules(
        db_session, organization.id, now=now
    )

    assert len(alerts) == 2

    alerts_by_name = {
        alert.rule_name: alert for alert in alerts
    }

    assert alerts_by_name["Three failures"].severity == 2
    assert alerts_by_name["Five failures"].severity == 5

    assert (
        alerts_by_name["Three failures"].deduplication_key
        != alerts_by_name["Five failures"].deduplication_key
    )


def test_new_incident_after_cooldown_links_to_previous_alert(
    db_session,
):
    """A new incident creates an alert linked to the previous alert."""

    organization = create_organization(
        db_session, "Organization A", "org-a"
    )
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)

    # Create the first group of five failed logins.
    for attempt in range(5):
        record_failed_login(
            db_session,
            organization.id,
            now - timedelta(seconds=attempt * 30),
        )

    first_run = detect_failed_logins(
        db_session, organization.id, now=now
    )

    assert len(first_run) == 1
    first_alert = first_run[0]

    # An analyst has resolved the first alert.
    first_alert.status = "RESOLVED"
    db_session.commit()

    # Simulate five new failures 12 minutes later.
    later = now + timedelta(minutes=12)

    for attempt in range(5):
        record_failed_login(
            db_session,
            organization.id,
            later - timedelta(seconds=attempt * 30),
        )

    second_run = detect_failed_logins(
        db_session, organization.id, now=later
    )

    # The new incident should create a separate, linked alert.
    assert len(second_run) == 1

    second_alert = second_run[0]

    assert second_alert.id != first_alert.id
    assert second_alert.previous_alert_id == first_alert.id
    assert second_alert.status == "OPEN"

    # Running detection again should not duplicate that incident.
    assert detect_failed_logins(
        db_session, organization.id, now=later
    ) == []
    
def test_new_activity_during_cooldown_is_suppressed(db_session):
    """A new burst during cooldown must not create another alert."""

    organization = create_organization(
        db_session, "Organization A", "org-a"
    )
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)

    # First burst: create the original alert.
    for attempt in range(5):
        record_failed_login(
            db_session,
            organization.id,
            now - timedelta(seconds=attempt * 30),
        )

    first_run = detect_failed_logins(
        db_session, organization.id, now=now
    )
    assert len(first_run) == 1

    first_alert = first_run[0]
    first_alert.status = "RESOLVED"
    db_session.commit()

    # A second burst occurs only five minutes later.
    during_cooldown = now + timedelta(minutes=5)

    for attempt in range(5):
        record_failed_login(
            db_session,
            organization.id,
            during_cooldown - timedelta(seconds=attempt * 30),
        )

    result = detect_failed_logins(
        db_session,
        organization.id,
        now=during_cooldown,
    )

    assert result == []

    # The original alert remains resolved; no duplicate is created.
    db_session.refresh(first_alert)
    assert first_alert.status == "RESOLVED"
    assert (
        db_session.query(Alert)
        .filter(Alert.tenant_id == organization.id)
        .count()
        == 1
    )