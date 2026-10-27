from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.detection_rule import DetectionRule
from app.models.event import Event


DEFAULT_RULE_NAME = "repeated_failed_logins"
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 5
DEFAULT_SEVERITY = 4
DEFAULT_ALERT_COOLDOWN_MINUTES = 10


def _as_utc(value: datetime) -> datetime:
    """Normalize a timestamp to UTC, including naive database values."""

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _event_is_newer(
    candidate: Event,
    previous: Event | None,
) -> bool:
    """Check whether the candidate is newer than the event already tracked."""

    if previous is None:
        return True

    candidate_time = _as_utc(candidate.timestamp)
    previous_time = _as_utc(previous.timestamp)

    if candidate_time != previous_time:
        return candidate_time > previous_time

    # If timestamps match, use the database IDs for consistent ordering.
    return candidate.id > previous.id


def detect_failed_logins(
    db: Session,
    tenant_id: int,
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    now: datetime | None = None,
    rule_name: str = DEFAULT_RULE_NAME,
    severity: int = DEFAULT_SEVERITY,
    rule_id: int | None = None,
    cooldown_minutes: int = DEFAULT_ALERT_COOLDOWN_MINUTES,
) -> list[Alert]:
    """
    Detect repeated authentication failures from the same source IP.

    Existing open or acknowledged alerts are retained. A resolved alert
    can have a new linked alert created only when newer qualifying
    activity occurs after the cooldown.

    tenant_id must come from the authenticated user's organization.
    """

    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    if not 1 <= severity <= 5:
        raise ValueError("severity must be between 1 and 5")

    if cooldown_minutes < 1:
        raise ValueError("cooldown_minutes must be at least 1")

    current_time = _as_utc(now or datetime.now(timezone.utc))
    cutoff_time = current_time - timedelta(minutes=window_minutes)

    # Always restrict event searches to the authenticated organization.
    recent_events = (
        db.query(Event)
        .filter(
            Event.tenant_id == tenant_id,
            Event.event_type == "authentication_failure",
            Event.timestamp >= cutoff_time,
            Event.timestamp <= current_time,
            Event.source_ip.isnot(None),
        )
        .order_by(Event.timestamp.desc(), Event.id.desc())
        .all()
    )

    events_by_ip: dict[str, list[Event]] = defaultdict(list)

    for event in recent_events:
        events_by_ip[event.source_ip].append(event)

    generated_alerts: list[Alert] = []
    database_changed = False

    for source_ip, events in events_by_ip.items():
        if len(events) < threshold:
            continue

        # This stable key identifies a rule/IP combination, not a single
        # occurrence. It is used to find that combination's alert history.
        if rule_id is None:
            correlation_key = (
                f"{DEFAULT_RULE_NAME}:{source_ip}"
            )
        else:
            correlation_key = (
                f"{DEFAULT_RULE_NAME}:rule-{rule_id}:{source_ip}"
            )

        # Retain compatibility with older alerts that used the stable key
        # directly, and find newer alerts with incident-specific keys.
        existing_alert = (
            db.query(Alert)
            .filter(
                Alert.tenant_id == tenant_id,
                or_(
                    Alert.deduplication_key == correlation_key,
                    Alert.deduplication_key.like(
                        f"{correlation_key}:incident-%"
                    ),
                ),
            )
            .order_by(
                Alert.detected_at.desc(),
                Alert.id.desc(),
            )
            .first()
        )

        latest_event = events[0]

        if existing_alert is not None:
            previous_event = (
                db.get(Event, existing_alert.event_id)
                if existing_alert.event_id is not None
                else None
            )

            # The same previously considered activity must never create
            # a new incident simply because detection ran again.
            if not _event_is_newer(latest_event, previous_event):
                continue

            previous_status = existing_alert.status.upper()

            if previous_status != "RESOLVED":
                # Track the newest event considered while this alert is
                # active. This prevents that same activity being treated
                # as a new incident after the alert is later resolved.
                existing_alert.event_id = latest_event.id
                database_changed = True
                continue

            cooldown_ends_at = (
                _as_utc(existing_alert.detected_at)
                + timedelta(minutes=cooldown_minutes)
            )

            # Activity during the cooldown is recorded as considered,
            # but it does not generate another alert.
            if _as_utc(latest_event.timestamp) < cooldown_ends_at:
                existing_alert.event_id = latest_event.id
                database_changed = True
                continue

        usernames = sorted({
            event.username
            for event in events
            if event.username
        })

        username_summary = (
            ", ".join(usernames) if usernames else "unknown"
        )

        # Every distinct incident gets its own key. The database's
        # tenant/key uniqueness constraint protects concurrent runs.
        deduplication_key = (
            f"{correlation_key}:incident-{latest_event.id}"
        )

        new_alert = Alert(
            tenant_id=tenant_id,
            event_id=latest_event.id,
            previous_alert_id=(
                existing_alert.id
                if existing_alert is not None
                else None
            ),
            alert_type="SENTINEL",
            source="sentinel",
            source_alert_id=None,
            deduplication_key=deduplication_key,
            rule_name=rule_name,
            title=f"Repeated failed logins from {source_ip}",
            description=(
                f"Detected {len(events)} authentication failures "
                f"from source IP {source_ip} within "
                f"{window_minutes} minutes. "
                f"Associated usernames: {username_summary}."
            ),
            severity=severity,
            status="OPEN",
            detected_at=current_time,
        )

        try:
            with db.begin_nested():
                db.add(new_alert)
                db.flush()

            generated_alerts.append(new_alert)
            database_changed = True

        except IntegrityError:
            # Another detection run may have inserted this incident first.
            continue

    if database_changed:
        db.commit()

        for alert in generated_alerts:
            db.refresh(alert)

    return generated_alerts


def detect_configured_rules(
    db: Session,
    tenant_id: int,
    now: datetime | None = None,
) -> list[Alert]:
    """
    Run this organization's enabled saved failed-login rules.

    Organizations without saved rules keep the legacy default behavior.
    """

    rules = (
        db.query(DetectionRule)
        .filter(
            DetectionRule.organization_id == tenant_id,
            DetectionRule.rule_type == DEFAULT_RULE_NAME,
        )
        .order_by(DetectionRule.id.asc())
        .all()
    )

    if not rules:
        return detect_failed_logins(
            db=db,
            tenant_id=tenant_id,
            threshold=DEFAULT_THRESHOLD,
            window_minutes=DEFAULT_WINDOW_MINUTES,
            now=now,
        )

    generated_alerts: list[Alert] = []

    for rule in rules:
        if not rule.is_enabled:
            continue

        generated_alerts.extend(
            detect_failed_logins(
                db=db,
                tenant_id=tenant_id,
                threshold=rule.threshold,
                window_minutes=rule.window_minutes,
                now=now,
                rule_name=rule.name,
                severity=rule.severity,
                rule_id=rule.id,
            )
        )

    return generated_alerts