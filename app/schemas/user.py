from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserUpdate(BaseModel):
    name: str | None = None
    email: EmailStr | None = None  # EmailStr so invalid formats are rejected on update too
    password: str | None = None
