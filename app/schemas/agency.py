from typing import Annotated
from uuid import UUID
from pydantic import BaseModel, StringConstraints


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
    userId: UUID
