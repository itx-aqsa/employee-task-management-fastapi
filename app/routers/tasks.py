from fastapi import APIRouter, Depends, HTTPException
from app.database import db
from app.schemas.task import TaskCreate, TaskUpdate, TaskStatus, TaskStatusUpdate
from app.middleware.auth import get_current_user
from app.middleware.role import require_agency_role
from app.schemas.auth import AgencyContext, UserContext

router = APIRouter(
    prefix="/tasks",
    tags=["Tasks"]
)


def _is_valid_status(value: str) -> bool:
    return value in {s.value for s in TaskStatus}


# ---------------------------------------------------------------------------
# Agency-scoped task endpoints
# All endpoints require X-Agency-ID header. Every DB query is filtered by
# agency_ctx.agency_id to enforce strict multi-agency data isolation and
# prevent cross-agency IDOR vulnerabilities.
# ---------------------------------------------------------------------------

@router.post("/")
async def create_task(
    task: TaskCreate,
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """
    Creates a task and pins it to the requesting agency.
    The assignee must be an EMPLOYEE member of the same agency — prevents
    cross-agency task assignment.
    """
    # Verify the target user exists AND is a member of this agency
    membership = await db.agencymembership.find_unique(
        where={
            "userId_agencyId": {
                "userId": task.userId,
                "agencyId": agency_ctx.agency_id,
            }
        },
        include={"user": True},
    )

    if not membership:
        raise HTTPException(
            status_code=404,
            detail="Employee not found in this agency"
        )

    if str(membership.user.role) != "EMPLOYEE":
        raise HTTPException(
            status_code=400,
            detail="Task can only be assigned to an employee"
        )

    if task.priority not in ("LOW", "MEDIUM", "HIGH"):
        raise HTTPException(status_code=400, detail="Invalid task priority")

    if not _is_valid_status(task.status):
        raise HTTPException(status_code=400, detail="Invalid task status")

    new_task = await db.task.create(
        data={
            "title": task.title,
            "description": task.description,
            "priority": task.priority,
            "status": task.status,
            "userId": task.userId,
            "agencyId": agency_ctx.agency_id,  # always stamp the agency
        }
    )

    return {
        "status": True,
        "message": "Task created successfully",
        "data": new_task,
    }


@router.get("/")
async def get_tasks(
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """
    Returns all tasks belonging to the requesting agency only.
    Prevents cross-agency task enumeration.
    """
    tasks = await db.task.find_many(
        where={"agencyId": agency_ctx.agency_id},
        order=[{"createdAt": "desc"}],
        include={"user": True},
    )

    return {"status": True, "data": tasks}


@router.get("/my-tasks")
async def get_my_tasks(
    agency_ctx: AgencyContext = Depends(require_agency_role("EMPLOYEE", "ADMIN", "SUPER_ADMIN"))
):
    """
    Returns the caller's own tasks scoped to the requesting agency.
    Employees see only their own tasks; the agency boundary is also enforced
    so tasks from another agency are never exposed.
    """
    tasks = await db.task.find_many(
        where={
            "userId": agency_ctx.user.id,
            "agencyId": agency_ctx.agency_id,
        },
        order=[{"createdAt": "desc"}],
    )

    return {"status": True, "data": tasks}


@router.get("/board")
async def get_task_board(
    agency_ctx: AgencyContext = Depends(require_agency_role("EMPLOYEE", "ADMIN", "SUPER_ADMIN"))
):
    """
    Returns the Kanban board for the requesting agency.
    ADMINs/SUPER_ADMINs see all agency tasks; EMPLOYEEs see only their own.
    Both paths filter by agencyId to prevent cross-agency leakage.
    """
    role = agency_ctx.agency_role

    if role in ("ADMIN", "SUPER_ADMIN"):
        tasks = await db.task.find_many(
            where={"agencyId": agency_ctx.agency_id},
            order=[{"createdAt": "desc"}],
            include={"user": True},
        )
    else:
        # EMPLOYEE: own tasks within the agency
        tasks = await db.task.find_many(
            where={
                "userId": agency_ctx.user.id,
                "agencyId": agency_ctx.agency_id,
            },
            order=[{"createdAt": "desc"}],
            include={"user": True},
        )

    board = {s.value: [] for s in TaskStatus}
    for task in tasks:
        board[task.status].append(task)

    return {"status": True, "data": board}


@router.get("/{task_id}")
async def get_task(
    task_id: str,
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """
    Fetches a single task only if it belongs to the requesting agency.
    Prevents cross-agency task disclosure (IDOR).
    """
    task = await db.task.find_first(
        where={
            "id": task_id,
            "agencyId": agency_ctx.agency_id,
        },
        include={"user": True},
    )

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return {"status": True, "data": task}


@router.put("/{task_id}")
async def update_task(
    task_id: str,
    task_data: TaskUpdate,
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """
    Updates a task only if it belongs to the requesting agency.
    If re-assigning, the new assignee must also be an EMPLOYEE in this agency.
    Prevents cross-agency task mutation (IDOR).
    """
    existing_task = await db.task.find_first(
        where={
            "id": task_id,
            "agencyId": agency_ctx.agency_id,
        }
    )

    if not existing_task:
        raise HTTPException(status_code=404, detail="Task not found")

    update_data: dict = {}

    if task_data.title is not None:
        update_data["title"] = task_data.title

    if task_data.description is not None:
        update_data["description"] = task_data.description

    if task_data.priority is not None:
        if task_data.priority not in ("LOW", "MEDIUM", "HIGH"):
            raise HTTPException(status_code=400, detail="Invalid task priority")
        update_data["priority"] = task_data.priority

    if task_data.status is not None:
        if not _is_valid_status(task_data.status):
            raise HTTPException(status_code=400, detail="Invalid task status")
        update_data["status"] = task_data.status

    if task_data.userId is not None:
        # New assignee must be an EMPLOYEE in this agency
        membership = await db.agencymembership.find_unique(
            where={
                "userId_agencyId": {
                    "userId": task_data.userId,
                    "agencyId": agency_ctx.agency_id,
                }
            },
            include={"user": True},
        )

        if not membership:
            raise HTTPException(
                status_code=404,
                detail="Employee not found in this agency"
            )

        if str(membership.user.role) != "EMPLOYEE":
            raise HTTPException(
                status_code=400,
                detail="Task can only be assigned to an employee"
            )

        update_data["userId"] = task_data.userId

    updated_task = await db.task.update(
        where={"id": task_id},
        data=update_data,
    )

    return {
        "status": True,
        "message": "Task updated successfully",
        "data": updated_task,
    }


@router.delete("/{task_id}")
async def delete_task(
    task_id: str,
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """
    Deletes a task only if it belongs to the requesting agency.
    Prevents cross-agency task deletion (IDOR).
    """
    existing_task = await db.task.find_first(
        where={
            "id": task_id,
            "agencyId": agency_ctx.agency_id,
        }
    )

    if not existing_task:
        raise HTTPException(status_code=404, detail="Task not found")

    await db.task.delete(where={"id": task_id})

    return {"status": True, "message": "Task deleted successfully"}


@router.put("/{task_id}/status")
async def update_task_status(
    task_id: str,
    status_data: TaskStatusUpdate,
    agency_ctx: AgencyContext = Depends(require_agency_role("EMPLOYEE", "ADMIN", "SUPER_ADMIN"))
):
    """
    Updates a task's status. The task must belong to the requesting agency.
    EMPLOYEEs may only update their own tasks. ADMINs may update any task
    within the agency. Prevents cross-agency status mutation.
    """
    task = await db.task.find_first(
        where={
            "id": task_id,
            "agencyId": agency_ctx.agency_id,
        },
        include={"user": True},
    )

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # EMPLOYEE ownership check: can only update their own task
    if (
        agency_ctx.agency_role == "EMPLOYEE"
        and str(task.userId) != str(agency_ctx.user.id)
    ):
        raise HTTPException(
            status_code=403,
            detail="You are not allowed to update this task"
        )

    updated_task = await db.task.update(
        where={"id": task_id},
        data={"status": status_data.status.value},
    )

    return {
        "status": True,
        "message": "Task status updated successfully",
        "data": updated_task,
    }
