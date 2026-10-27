
from pydantic import BaseModel, Field, field_validator


class UserCreate(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=12, max_length=128)
    role: str

    @field_validator("role", mode="before")
    @classmethod
    def normalize_role(cls, value):
        if not isinstance(value, str):
            return value

        return value.strip().upper()

    @field_validator("role")
    @classmethod
    def validate_role(cls, value):
        allowed_roles = {"ANALYST", "VIEWER"}

        if value not in allowed_roles:
            raise ValueError(
                "Role must be ANALYST or VIEWER"
            )

        return value


class UserSummary(BaseModel):
    id: int
    email: str
    organization_id: int
    role: str
    is_active: bool

    class Config:
        from_attributes = True