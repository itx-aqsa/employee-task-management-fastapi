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


@router.post("/")
async def create_task(
    task: TaskCreate,
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """Create a task pinned to the requesting agency. Assignee must be an EMPLOYEE in this agency."""
    user_id = str(task.userId)

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
        raise HTTPException(status_code=404, detail="Employee not found in this agency")

    if str(membership.user.role) != "EMPLOYEE":
        raise HTTPException(status_code=400, detail="Task can only be assigned to an employee")

    new_task = await db.task.create(
        data={
            "title": task.title,
            "description": task.description,
            "priority": task.priority.value,
            "status": task.status.value,
            "userId": user_id,
            "agencyId": agency_ctx.agency_id,
        }
    )

    return {"status": True, "message": "Task created successfully", "data": new_task}


@router.get("/")
async def get_tasks(
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """Return all tasks belonging to the requesting agency."""
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
    """Return the caller's own tasks scoped to the requesting agency."""
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
    """Kanban board: ADMINs see all agency tasks, EMPLOYEEs see their own."""
    role = agency_ctx.agency_role

    if role in ("ADMIN", "SUPER_ADMIN"):
        tasks = await db.task.find_many(
            where={"agencyId": agency_ctx.agency_id},
            order=[{"createdAt": "desc"}],
            include={"user": True},
        )
    else:
        tasks = await db.task.find_many(
            where={"userId": agency_ctx.user.id, "agencyId": agency_ctx.agency_id},
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
    """Fetch a single task only if it belongs to the requesting agency."""
    task = await db.task.find_first(
        where={"id": task_id, "agencyId": agency_ctx.agency_id},
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
    """Update a task within the agency. Re-assignment validates EMPLOYEE membership."""
    existing_task = await db.task.find_first(
        where={"id": task_id, "agencyId": agency_ctx.agency_id}
    )
    if not existing_task:
        raise HTTPException(status_code=404, detail="Task not found")

    update_data: dict = {}

    if task_data.title is not None:
        update_data["title"] = task_data.title
    if task_data.description is not None:
        update_data["description"] = task_data.description
    if task_data.priority is not None:
        update_data["priority"] = task_data.priority.value
    if task_data.status is not None:
        update_data["status"] = task_data.status.value
    if task_data.userId is not None:
        user_id = str(task_data.userId)
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
            raise HTTPException(status_code=404, detail="Employee not found in this agency")
        if str(membership.user.role) != "EMPLOYEE":
            raise HTTPException(status_code=400, detail="Task can only be assigned to an employee")
        update_data["userId"] = user_id

    updated_task = await db.task.update(where={"id": task_id}, data=update_data)
    return {"status": True, "message": "Task updated successfully", "data": updated_task}


@router.delete("/{task_id}")
async def delete_task(
    task_id: str,
    agency_ctx: AgencyContext = Depends(require_agency_role("ADMIN", "SUPER_ADMIN"))
):
    """Delete a task only if it belongs to the requesting agency."""
    existing_task = await db.task.find_first(
        where={"id": task_id, "agencyId": agency_ctx.agency_id}
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
    """Update task status. EMPLOYEEs may only update their own tasks."""
    task = await db.task.find_first(
        where={"id": task_id, "agencyId": agency_ctx.agency_id},
        include={"user": True},
    )
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if agency_ctx.agency_role == "EMPLOYEE" and str(task.userId) != str(agency_ctx.user.id):
        raise HTTPException(status_code=403, detail="You are not allowed to update this task")

    updated_task = await db.task.update(
        where={"id": task_id},
        data={"status": status_data.status.value},
    )
    return {"status": True, "message": "Task status updated successfully", "data": updated_task}
