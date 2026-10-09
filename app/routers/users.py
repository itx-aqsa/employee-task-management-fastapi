from fastapi import APIRouter, Depends, HTTPException, Response
from app.database import db
from app.schemas.user import UserCreate, UserLogin
from app.core.security import (
    hash_password, verify_password, create_access_token
)
from app.middleware.auth import get_current_user

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)

@router.post("/")
async def create_user(user: UserCreate):
    existing_user = await db.user.find_unique(
        where={
            "email": user.email
        }
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    new_user = await db.user.create(
        data={
            "name": user.name,
            "email": user.email,
            "password": hash_password(user.password),
        }
    )

    return {
        "status": "True",
        "message": "User created successfully",
        "data": {
            "id": new_user.id,
            "name": new_user.name,
            "email": new_user.email,
            "role": new_user.role.value
        }
    }

@router.post("/login")
async def login_user(
    user: UserLogin,
    response: Response
):
    existing_user = await db.user.find_unique(
        where={
            "email": user.email
        }
    )

    if not existing_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if not verify_password(
        user.password,
        existing_user.password
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    token = create_access_token(
        str(existing_user.id),
        existing_user.role.value
    )

    response.set_cookie(
        key="token",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60      
    )

    return {
        "status": True,
        "message": "Login successful",
        "data": {
            "id": existing_user.id,
            "name": existing_user.name,
            "email": existing_user.email,
            "role": existing_user.role.value
        }
    }

@router.post("/logout")
async def logout_user(response: Response):

    response.delete_cookie(
        key="token"
    )

    return {
        "status": True,
        "message": "Logout successful"
    }

@router.get("/profile")
async def get_profile(
    current_user = Depends(get_current_user)
):
    user = await db.user.find_unique(
        where={
            "id": current_user["id"]
        }
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return {
        "status": True,
        "data": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role.value
        }
    }