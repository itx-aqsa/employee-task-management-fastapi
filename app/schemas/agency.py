from typing import Annotated
from uuid import UUID
from pydantic import BaseModel, EmailStr, StringConstraints


AgencyName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class AgencyCreate(BaseModel):
    name: AgencyName
    description: str | None = None
    isDefault: bool = False
    isActive: bool = True


class AgencyUpdate(BaseModel):
    name: AgencyName | None = None
    description: str | None = None
    isDefault: bool | None = None
    isActive: bool | None = None


class AgencyAssignAdmin(BaseModel):
    """Legacy schema kept for backward compatibility — accepts an existing user by ID."""
    userId: UUID


class AgencyAdminCreate(BaseModel):
    """Create a new ADMIN user and assign them to an agency in one step."""
    name: str
    email: EmailStr
    password: str
