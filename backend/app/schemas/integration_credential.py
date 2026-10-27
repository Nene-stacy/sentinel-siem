"""Request and response schemas for integration credentials."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IntegrationCredentialCreate(BaseModel):
    """Fields an administrator supplies when creating a credential."""

    name: str = Field(min_length=1, max_length=100)
    provider: Literal["wazuh"] = "wazuh"

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        """Reject names that contain only whitespace."""

        cleaned_value = value.strip()

        if not cleaned_value:
            raise ValueError("Credential name cannot be blank")

        return cleaned_value


class IntegrationCredentialCreated(BaseModel):
    """Returned once when a new credential is created."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    organization_id: int
    name: str
    provider: str
    key_prefix: str
    api_key: str
    is_active: bool
    created_at: datetime