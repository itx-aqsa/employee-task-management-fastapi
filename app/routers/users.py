from fastapi import APIRouter, Depends, HTTPException, Response
from app.database import db
from app.schemas.user import UserCreate, UserLogin, UserUpdate
from app.core.security import (
    hash_password, verify_password, create_access_token
)
from app.middleware.auth import get_current_user
from app.middleware.role import require_role

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
            "role": new_user.role
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
        existing_user.role
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
            "role": existing_user.role
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
    current_user=Depends(get_current_user)
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
            "role": user.role
        }
    }

@router.get("/employees")
async def get_employees(
    current_user=Depends(require_role("ADMIN"))
):
    employees = await db.user.find_many(
        where={
            "role": "EMPLOYEE"
        },
        order=[
            {
                "createdAt": "desc"
            }
        ],
        include={
            "tasks": True
        }
    )

    return {
        "status": True,
        "data": [
            {
                "id": emp.id,
                "name": emp.name,
                "email": emp.email,
                "role": emp.role,
                "createdAt": emp.createdAt,
                "updatedAt": emp.updatedAt,
                "_count": {
                    "tasks": len(emp.tasks) if emp.tasks else 0
                }
            }
            for emp in employees
        ]
    }

@router.get("/dashboard-stats")
async def dashboard_stats(
    current_user=Depends(require_role("ADMIN"))
):
    total_employees = await db.user.count(
        where={
            "role": "EMPLOYEE"
        }
    )
    total_tasks = await db.task.count()

    pending_tasks = await db.task.count(
        where={
            "status": "PENDING"
        }
    )

    return {
        "status": True,
        "data": {
            "totalEmployees": total_employees,
            "totalTasks": total_tasks,
            "pendingTasks": pending_tasks
        }
    }

@router.get("/{user_id}")
async def get_employee(
    user_id: str,
    current_user=Depends(require_role("ADMIN"))
):
    user = await db.user.find_unique(
        where={
            "id": user_id
        }
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if user.role != "EMPLOYEE":
        raise HTTPException(
            status_code=404,
            detail="Employee not found"
        )

    return {
        "status": True,
        "data": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role
        }
    }

@router.put("/{user_id}")
async def update_employee(
    user_id: str,
    user_data: UserUpdate,
    current_user=Depends(require_role("ADMIN"))
):
    existing_user = await db.user.find_unique(
        where={
            "id": user_id
        }
    )

    if not existing_user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if existing_user.role != "EMPLOYEE":
        raise HTTPException(
            status_code=403,
            detail="Admin user cannot be edited here"
        )

    update_data = {}

    if user_data.name is not None:
        update_data["name"] = user_data.name

    if user_data.email is not None:
        if user_data.email != existing_user.email:
            email_exists = await db.user.find_unique(
                where={
                    "email": user_data.email
                }
            )

            if email_exists:
                raise HTTPException(
                    status_code=409,
                    detail="Email already exists"
                )

        update_data["email"] = user_data.email

    if user_data.password:
        update_data["password"] = hash_password(
            user_data.password
        )

    updated_user = await db.user.update(
        where={
            "id": user_id
        },
        data=update_data
    )

    return {
        "status": True,
        "message": "User updated successfully",
        "data": {
            "id": updated_user.id,
            "name": updated_user.name,
            "email": updated_user.email,
            "role": updated_user.role
        }
    }

@router.delete("/{user_id}")
async def delete_employee(
    user_id: str,
    current_user=Depends(require_role("ADMIN"))
):
    existing_user = await db.user.find_unique(
        where={
            "id": user_id
        }
    )

    if not existing_user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if existing_user.role != "EMPLOYEE":
        raise HTTPException(
            status_code=403,
            detail="Admin user cannot be deleted here"
        )

    await db.user.delete(
        where={
            "id": user_id
        }
    )

    return {
        "status": True,
        "message": "User deleted successfully"
    }
