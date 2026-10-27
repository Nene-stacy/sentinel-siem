
from contextlib import asynccontextmanager
from datetime import timezone
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI

from app.api.auth import router as auth_router
from app.api.events import router as events_router
from app.api.users import router as users_router
from app.api.alerts import router as alerts_router
from app.api.detection import router as detection_router
from app.api.alert_workflow import router as alert_workflow_router
from app.api.detection_rules import router as detection_rules_router
from app.services.scheduler import run_scheduled_detection
from app.api.integration_credentials import (
router as integration_credentials_router,
)


logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start scheduled detection with SEER and stop it on shutdown."""

    scheduler = BackgroundScheduler(timezone=timezone.utc)

    scheduler.add_job(
        run_scheduled_detection,
        trigger="interval",
        minutes=1,
        id="seer_scheduled_detection",
        name="SEER scheduled detection",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=30,
    )

    scheduler.start()
    app.state.scheduler = scheduler

    logger.info("SEER scheduled detection started")

    try:
        yield
    finally:
        scheduler.shutdown(wait=True)
        logger.info("SEER scheduled detection stopped")


app = FastAPI(
    title="SEER",
    description=(
        "Your virtual SOC. SIEM and SOAR platform "
        "for security monitoring"
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(auth_router)
app.include_router(events_router)
app.include_router(users_router)
app.include_router(alerts_router)
app.include_router(detection_router)
app.include_router(alert_workflow_router)
app.include_router(detection_rules_router)
app.include_router(integration_credentials_router)


@app.get("/")
def root():
    return {
        "name": "SEER",
        "status": "online",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }
