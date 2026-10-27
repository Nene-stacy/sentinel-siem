from datetime import datetime

from pydantic import BaseModel


class SecurityEvent(BaseModel):
    timestamp: datetime
    source: str
    event_type: str
    severity: int
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    message: str | None = None


class EventResponse(BaseModel):
    id: int
    timestamp: datetime
    source: str
    event_type: str
    severity: int
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    message: str | None = None

    class Config:
        from_attributes = True