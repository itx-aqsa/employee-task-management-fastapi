from fastapi import APIRouter, Depends, HTTPException, Response
from prisma.enums import Role, Status
from app.database import db
from app.schemas.user import UserCreate, UserLogin, UserUpdate, EmployeeCreate
from app.core.security import hash_password, verify_password, create_access_token
from app.middleware.auth import get_current_user
from app.middleware.role import require_agency_role, require_role, require_platform_role
from app.schemas.auth import AgencyContext

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------

@router.post("", include_in_schema=False)
@router.post("/")
async def create_user(user: UserCreate):
    """Register a new user. Agency membership is assigned separately."""
    existing_user = await db.user.find_unique(where={"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already exists")

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
    existing_user = await db.user.find_unique(where={"email": user.email})
    if not existing_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not verify_password(user.password, existing_user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(str(existing_user.id))
    response.set_cookie(
        key="token",
        value=token,
        httponly=True,
        secure=False,  # set True in production
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
    """Return the authenticated user's own profile, including agencyId if they have a membership."""
    user = await db.user.find_unique(where={"id": current_user.id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Filter by role so a stale membership in another agency is never returned.
    # SUPER_ADMIN has no membership row; skip the lookup entirely for them.
    membership = None
    if current_user.platform_role in ("ADMIN", "EMPLOYEE"):
        lookup_role = Role.ADMIN if current_user.platform_role == "ADMIN" else Role.EMPLOYEE
        membership = await db.agencymembership.find_first(
            where={"userId": current_user.id, "role": lookup_role},
            order={"createdAt": "desc"},
        )

    return {
        "status": True,
        "data": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "agencyId": str(membership.agencyId) if membership else None,
        },
    }


# ---------------------------------------------------------------------------
# Platform-level endpoints (SUPER_ADMIN only, no agency scope)
# ---------------------------------------------------------------------------

@router.get("/all", dependencies=[Depends(require_platform_role("SUPER_ADMIN"))])
async def get_all_users(current_user=Depends(require_platform_role("SUPER_ADMIN"))):
    """List all registered users. SUPER_ADMIN only."""
    users = await db.user.find_many(order=[{"createdAt": "desc"}])
    return {"status": True, "data": users}


@router.get("/platform-stats")
async def platform_stats(
    current_user=Depends(require_platform_role("SUPER_ADMIN"))
):
    """Platform-wide aggregate stats across all agencies. SUPER_ADMIN only, no agency scope."""
    total_users = await db.user.count()
    total_agencies = await db.agency.count()
    total_admins = await db.user.count(where={"role": Role.ADMIN})
    total_employees = await db.user.count(where={"role": Role.EMPLOYEE})
    total_tasks = await db.task.count()
    pending_tasks = await db.task.count(where={"status": Status.PENDING})
    in_progress_tasks = await db.task.count(where={"status": Status.IN_PROGRESS})
    completed_tasks = await db.task.count(where={"status": Status.COMPLETED})
    return {
        "status": True,
        "data": {
            "totalUsers": total_users,
            "totalAgencies": total_agencies,
            "totalAdmins": total_admins,
            "totalEmployees": total_employees,
            "totalTasks": total_tasks,
            "pendingTasks": pending_tasks,
            "inProgressTasks": in_progress_tasks,
            "completedTasks": completed_tasks,
        },
    }


# ---------------------------------------------------------------------------
# Agency-scoped endpoints — require X-Agency-ID header
# ---------------------------------------------------------------------------

@router.post("/employees")
async def create_employee(
    payload: EmployeeCreate,
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """Create a new EMPLOYEE user and enroll them in the agency."""
    existing = await db.user.find_unique(where={"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="A user with this email already exists")

    new_user = await db.user.create(
        data={
            "name": payload.name,
            "email": payload.email,
            "password": hash_password(payload.password),
            "role": Role.EMPLOYEE,
        }
    )

    membership = await db.agencymembership.create(
        data={
            "userId": new_user.id,
            "agencyId": agency_ctx.agency_id,
            "role": Role.EMPLOYEE,
        }
    )

    return {
        "status": True,
        "message": "Employee created and enrolled in agency successfully",
        "data": {
            "user": {
                "id": new_user.id,
                "name": new_user.name,
                "email": new_user.email,
                "role": str(new_user.role),
            },
            "membership": {
                "id": membership.id,
                "userId": membership.userId,
                "agencyId": membership.agencyId,
                "role": str(membership.role),
            },
        },
    }


@router.get("/employees")
async def get_employees(
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """List EMPLOYEE-role members of the agency with their scoped task counts."""
    memberships = await db.agencymembership.find_many(
        where={"agencyId": agency_ctx.agency_id, "role": Role.EMPLOYEE},
        include={"user": True},
        order=[{"createdAt": "desc"}],
    )

    data = []
    for m in memberships:
        u = m.user
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


@router.get("/admins")
async def get_admins(
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """List ADMIN-role members of the agency."""
    memberships = await db.agencymembership.find_many(
        where={"agencyId": agency_ctx.agency_id, "role": Role.ADMIN},
        include={"user": True},
        order=[{"createdAt": "desc"}],
    )

    data = [
        {
            "id": m.user.id,
            "name": m.user.name,
            "email": m.user.email,
            "role": m.user.role,
            "createdAt": m.user.createdAt,
            "updatedAt": m.user.updatedAt,
        }
        for m in memberships
    ]

    return {"status": True, "data": data}


@router.get("/dashboard-stats")
async def dashboard_stats(
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """Agency-scoped employee, admin, and task counts."""
    total_admins = await db.agencymembership.count(
        where={"agencyId": agency_ctx.agency_id, "role": Role.ADMIN}
    )
    total_employees = await db.agencymembership.count(
        where={"agencyId": agency_ctx.agency_id, "role": Role.EMPLOYEE}
    )
    total_tasks = await db.task.count(where={"agencyId": agency_ctx.agency_id})
    pending_tasks = await db.task.count(
        where={"agencyId": agency_ctx.agency_id, "status": Status.PENDING}
    )
    in_progress_tasks = await db.task.count(
        where={"agencyId": agency_ctx.agency_id, "status": Status.IN_PROGRESS}
    )
    completed_tasks = await db.task.count(
        where={"agencyId": agency_ctx.agency_id, "status": Status.COMPLETED}
    )
    return {
        "status": True,
        "data": {
            "totalAdmins": total_admins,
            "totalEmployees": total_employees,
            "totalTasks": total_tasks,
            "pendingTasks": pending_tasks,
            "inProgressTasks": in_progress_tasks,
            "completedTasks": completed_tasks,
        },
    }


@router.get("/{user_id}")
async def get_employee(
    user_id: str,
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """Fetch a single employee if they are an EMPLOYEE member of the agency."""
    membership = await db.agencymembership.find_unique(
        where={"userId_agencyId": {"userId": user_id, "agencyId": agency_ctx.agency_id}},
        include={"user": True},
    )
    if not membership:
        raise HTTPException(status_code=404, detail="Employee not found")

    user = membership.user
    if user.role not in (Role.EMPLOYEE,):
        raise HTTPException(status_code=404, detail="Employee not found")

    return {
        "status": True,
        "data": {"id": user.id, "name": user.name, "email": user.email, "role": user.role},
    }


@router.put("/{user_id}")
async def update_employee(
    user_id: str,
    user_data: UserUpdate,
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """Update an employee within the agency. Rejects changes to ADMIN accounts."""
    membership = await db.agencymembership.find_unique(
        where={"userId_agencyId": {"userId": user_id, "agencyId": agency_ctx.agency_id}}
    )
    if not membership:
        raise HTTPException(status_code=404, detail="Employee not found")

    existing_user = await db.user.find_unique(where={"id": user_id})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    if existing_user.role not in (Role.EMPLOYEE,):
        raise HTTPException(status_code=403, detail="Admin user cannot be edited here")

    update_data: dict = {}

    if user_data.name is not None:
        update_data["name"] = user_data.name

    if user_data.email is not None:
        if user_data.email != existing_user.email:
            email_exists = await db.user.find_unique(where={"email": user_data.email})
            if email_exists:
                raise HTTPException(status_code=409, detail="Email already exists")
        update_data["email"] = user_data.email

    if user_data.password:
        update_data["password"] = hash_password(user_data.password)

    updated_user = await db.user.update(where={"id": user_id}, data=update_data)
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
    """Remove the employee from the agency (membership only, not the user account)."""
    membership = await db.agencymembership.find_unique(
        where={"userId_agencyId": {"userId": user_id, "agencyId": agency_ctx.agency_id}},
        include={"user": True},
    )
    if not membership:
        raise HTTPException(status_code=404, detail="Employee not found")

    if membership.user.role not in (Role.EMPLOYEE,):
        raise HTTPException(status_code=403, detail="Admin user cannot be removed here")

    await db.agencymembership.delete(
        where={"userId_agencyId": {"userId": user_id, "agencyId": agency_ctx.agency_id}}
    )
    return {"status": True, "message": "Employee removed from agency successfully"}
