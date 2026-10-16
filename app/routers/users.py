from fastapi import APIRouter, Depends, HTTPException, Response
from app.database import db
from app.schemas.user import UserCreate, UserLogin, UserUpdate
from app.core.security import (
    hash_password, verify_password, create_access_token
)
from app.middleware.auth import get_current_user
from app.middleware.role import require_agency_role, require_role
from app.schemas.auth import AgencyContext

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)


# ---------------------------------------------------------------------------
# Public endpoints — no agency context required
# ---------------------------------------------------------------------------

@router.post("/")
async def create_user(user: UserCreate):
    """
    Platform-level user registration. Creates the User record only.
    Agency membership is established separately via the agency-management
    endpoints (POST /agencies/{agency_id}/members).
    """
    existing_user = await db.user.find_unique(
        where={"email": user.email}
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
        "status": True,
        "message": "User created successfully",
        "data": {
            "id": new_user.id,
            "name": new_user.name,
            "email": new_user.email,
            "role": new_user.role,
        },
    }


@router.post("/login")
async def login_user(user: UserLogin, response: Response):
    existing_user = await db.user.find_unique(
        where={"email": user.email}
    )

    if not existing_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if not verify_password(user.password, existing_user.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    token = create_access_token(str(existing_user.id))

    response.set_cookie(
        key="token",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60,
    )

    return {
        "status": True,
        "message": "Login successful",
        "data": {
            "id": existing_user.id,
            "name": existing_user.name,
            "email": existing_user.email,
            "role": existing_user.role,
        },
    }


@router.post("/logout")
async def logout_user(response: Response):
    response.delete_cookie(key="token")
    return {"status": True, "message": "Logout successful"}


@router.get("/profile")
async def get_profile(current_user=Depends(get_current_user)):
    """Returns the authenticated user's own profile. No agency scope needed."""
    user = await db.user.find_unique(where={"id": current_user.id})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "status": True,
        "data": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
        },
    }


# ---------------------------------------------------------------------------
# Agency-scoped endpoints — require X-Agency-ID header + ADMIN membership
# ---------------------------------------------------------------------------

@router.get("/employees")
async def get_employees(
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """
    Returns only the employees who are members of the requesting agency.
    Prevents cross-agency employee enumeration.
    """
    memberships = await db.agencymembership.find_many(
        where={
            "agencyId": agency_ctx.agency_id,
            "role": "EMPLOYEE",
        },
        include={"user": True},
        order=[{"createdAt": "desc"}],
    )

    data = []
    for m in memberships:
        u = m.user
        # Count only tasks belonging to this agency
        task_count = await db.task.count(
            where={"userId": u.id, "agencyId": agency_ctx.agency_id}
        )
        data.append({
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "role": u.role,
            "createdAt": u.createdAt,
            "updatedAt": u.updatedAt,
            "_count": {"tasks": task_count},
        })

    return {"status": True, "data": data}


@router.get("/dashboard-stats")
async def dashboard_stats(
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """
    Returns employee and task counts scoped strictly to the requesting agency.
    Prevents global stat leakage across agencies.
    """
    total_employees = await db.agencymembership.count(
        where={
            "agencyId": agency_ctx.agency_id,
            "role": "EMPLOYEE",
        }
    )

    total_tasks = await db.task.count(
        where={"agencyId": agency_ctx.agency_id}
    )

    pending_tasks = await db.task.count(
        where={
            "agencyId": agency_ctx.agency_id,
            "status": "PENDING",
        }
    )

    return {
        "status": True,
        "data": {
            "totalEmployees": total_employees,
            "totalTasks": total_tasks,
            "pendingTasks": pending_tasks,
        },
    }


@router.get("/{user_id}")
async def get_employee(
    user_id: str,
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """
    Fetches a single employee only if they are a member of the requesting agency.
    Prevents cross-agency profile disclosure (IDOR).
    """
    # Verify this user is actually a member of the caller's agency
    membership = await db.agencymembership.find_unique(
        where={
            "userId_agencyId": {
                "userId": user_id,
                "agencyId": agency_ctx.agency_id,
            }
        },
        include={"user": True},
    )

    if not membership:
        raise HTTPException(status_code=404, detail="Employee not found")

    user = membership.user
    if user.role not in ("EMPLOYEE",):
        raise HTTPException(status_code=404, detail="Employee not found")

    return {
        "status": True,
        "data": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
        },
    }


@router.put("/{user_id}")
async def update_employee(
    user_id: str,
    user_data: UserUpdate,
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """
    Updates an employee only if they belong to the requesting agency.
    Prevents cross-agency mutation (IDOR).
    """
    # Confirm agency membership before loading the record
    membership = await db.agencymembership.find_unique(
        where={
            "userId_agencyId": {
                "userId": user_id,
                "agencyId": agency_ctx.agency_id,
            }
        }
    )

    if not membership:
        raise HTTPException(status_code=404, detail="Employee not found")

    existing_user = await db.user.find_unique(where={"id": user_id})

    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    if existing_user.role not in ("EMPLOYEE",):
        raise HTTPException(
            status_code=403,
            detail="Admin user cannot be edited here"
        )

    update_data: dict = {}

    if user_data.name is not None:
        update_data["name"] = user_data.name

    if user_data.email is not None:
        if user_data.email != existing_user.email:
            email_exists = await db.user.find_unique(
                where={"email": user_data.email}
            )
            if email_exists:
                raise HTTPException(
                    status_code=409,
                    detail="Email already exists"
                )
        update_data["email"] = user_data.email

    if user_data.password:
        update_data["password"] = hash_password(user_data.password)

    updated_user = await db.user.update(
        where={"id": user_id},
        data=update_data,
    )

    return {
        "status": True,
        "message": "User updated successfully",
        "data": {
            "id": updated_user.id,
            "name": updated_user.name,
            "email": updated_user.email,
            "role": updated_user.role,
        },
    }


@router.delete("/{user_id}")
async def delete_employee(
    user_id: str,
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """
    Removes the employee from the agency (deletes AgencyMembership).
    Does NOT delete the User account itself — they may belong to other agencies.
    Prevents cross-agency deletion (IDOR).
    """
    membership = await db.agencymembership.find_unique(
        where={
            "userId_agencyId": {
                "userId": user_id,
                "agencyId": agency_ctx.agency_id,
            }
        },
        include={"user": True},
    )

    if not membership:
        raise HTTPException(status_code=404, detail="Employee not found")

    if membership.user.role not in ("EMPLOYEE",):
        raise HTTPException(
            status_code=403,
            detail="Admin user cannot be removed here"
        )

    await db.agencymembership.delete(
        where={
            "userId_agencyId": {
                "userId": user_id,
                "agencyId": agency_ctx.agency_id,
            }
        }
    )

    return {"status": True, "message": "Employee removed from agency successfully"}
