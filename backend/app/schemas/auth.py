from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class UserResponse(BaseModel):
    id: int
    email: str
    organization_id: int
    role: str
    is_active: bool

    class Config:
        from_attributes = True