
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class DetectionRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    rule_type: str = Field(
        default="repeated_failed_logins",
        pattern=r"^repeated_failed_logins$",
    )
    threshold: int = Field(default=5, ge=1, le=1000)
    window_minutes: int = Field(default=5, ge=1, le=1440)
    severity: int = Field(default=4, ge=1, le=5)
    is_enabled: bool = True


class DetectionRuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=150)
    threshold: int | None = Field(default=None, ge=1, le=1000)
    window_minutes: int | None = Field(default=None, ge=1, le=1440)
    severity: int | None = Field(default=None, ge=1, le=5)
    is_enabled: bool | None = None


class DetectionRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    name: str
    rule_type: str
    threshold: int
    window_minutes: int
    severity: int
    is_enabled: bool
    created_at: datetime
    updated_at: datetime
