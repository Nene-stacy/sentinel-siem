

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AlertIngest(BaseModel):
    event_id: int | None = None
    source: str = Field(min_length=1, max_length=50)
    source_alert_id: str | None = Field(default=None, max_length=255)
    rule_name: str = Field(min_length=1, max_length=150)
    title: str = Field(min_length=1, max_length=255)
    description: str
    severity: int = Field(ge=1, le=5)


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    event_id: int | None
    alert_type: str
    source: str
    source_alert_id: str | None
    rule_name: str
    title: str
    description: str
    severity: int
    status: str
    previous_alert_id: int | None
    detected_at: datetime
    created_at: datetime