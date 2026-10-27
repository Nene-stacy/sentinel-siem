
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AlertStatusUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=30)


class InvestigationNoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=5000)


class InvestigationNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: int
    author_user_id: int
    note: str
    created_at: datetime
