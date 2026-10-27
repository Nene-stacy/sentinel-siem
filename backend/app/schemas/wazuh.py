
"""Validation schemas for incoming Wazuh alerts."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class WazuhRule(BaseModel):
    """The detection rule that generated the Wazuh alert."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(min_length=1, max_length=100)
    level: int = Field(ge=0, le=16)
    description: str = Field(min_length=1, max_length=2000)


class WazuhAgent(BaseModel):
    """Optional details about the monitored agent."""

    model_config = ConfigDict(extra="allow")

    id: str | None = None
    name: str | None = None
    ip: str | None = None


class WazuhAlertPayload(BaseModel):
    """Relevant fields from a Wazuh JSON alert."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(min_length=1, max_length=255)
    timestamp: datetime | None = None
    rule: WazuhRule
    agent: WazuhAgent | None = None
    manager: dict[str, Any] | None = None
    decoder: dict[str, Any] | None = None
    data: dict[str, Any] | None = None
    full_log: str | None = None
    location: str | None = None
