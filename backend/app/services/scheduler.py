"""Scheduled background jobs for SEER."""

import logging
from datetime import datetime, timezone

from app.core.database import SessionLocal
from app.models.detection_rule import DetectionRule
from app.services.detection import (
    DEFAULT_RULE_NAME,
    detect_configured_rules,
)

logger = logging.getLogger(__name__)


def run_scheduled_detection() -> None:
    """
    Run enabled, supported detection rules for each organization.

    Each organization gets its own database session so an error
    processing one organization does not stop the others.
    """
    logger.info("SEER scheduled detection job started")
    lookup_db = SessionLocal()

    try:
        # Only schedule organizations with enabled failed-login rules.
        # This avoids silently running the default rule for organizations
        # that have not enabled a detection rule.
        organization_rows = (
            lookup_db.query(DetectionRule.organization_id)
            .filter(
                DetectionRule.rule_type == DEFAULT_RULE_NAME,
                DetectionRule.is_enabled.is_(True),
            )
            .distinct()
            .all()
        )

        organization_ids = [
            row[0] for row in organization_rows
        ]

    except Exception:
        lookup_db.rollback()
        logger.exception(
            "Could not find organizations with enabled detection rules"
        )
        return

    finally:
        lookup_db.close()

    for organization_id in organization_ids:
        db = SessionLocal()

        try:
            alerts = detect_configured_rules(
                db=db,
                tenant_id=organization_id,
                now=datetime.now(timezone.utc),
            )

            if alerts:
                logger.info(
                    "Scheduled detection generated %d alert(s) "
                    "for organization %s",
                    len(alerts),
                    organization_id,
                )

        except Exception:
            db.rollback()
            logger.exception(
                "Scheduled detection failed for organization %s",
                organization_id,
            )

        finally:
            db.close()