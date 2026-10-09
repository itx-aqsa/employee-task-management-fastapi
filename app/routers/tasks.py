from fastapi import APIRouter, Depends, HTTPException
from app.database import db
from app.schemas.task import TaskCreate, TaskUpdate
from app.middleware.auth import get_current_user
from app.middleware.role import require_role

router = APIRouter(
    prefix="/tasks",
    tags=["Tasks"]
)

@router.post("/")
async def create_task(
    task: TaskCreate,
    current_user=Depends(require_role("ADMIN"))
):
    user = await db.user.find_unique(
        where={
            "id": task.userId
        }
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Employee not found"
        )

    if user.role != "EMPLOYEE":
        raise HTTPException(
            status_code=400,
            detail="Task can only be assigned to an employee"
        )

    if task.priority not in ["LOW", "MEDIUM", "HIGH"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid task priority"
        )

    if task.status not in ["PENDING", "IN_PROGRESS", "COMPLETED"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid task status"
        )

    new_task = await db.task.create(
        data={
            "title": task.title,
            "description": task.description,
            "priority": task.priority,
            "status": task.status,
            "userId": task.userId
        }
    )

    return {
        "status": True,
        "message": "Task created successfully",
        "data": new_task
    }

@router.get("/")
async def get_tasks(
    current_user=Depends(require_role("ADMIN"))
):
    tasks = await db.task.find_many(
        order=[
            {
                "createdAt": "desc"
            }
        ],
        include={
            "user": True
        }
    )

    return {
        "status": True,
        "data": tasks
    }

@router.get("/my-tasks")
async def get_my_tasks(
    current_user=Depends(require_role("EMPLOYEE"))
):
    tasks = await db.task.find_many(
        where={
            "userId": current_user["id"]
        },
        order=[
            {
                "createdAt": "desc"
            }
        ]
    )

    return {
        "status": True,
        "data": tasks
    }

@router.get("/{task_id}")
async def get_task(
    task_id: str,
    current_user=Depends(require_role("ADMIN"))
):
    task = await db.task.find_unique(
        where={
            "id": task_id
        },
        include={
            "user": True
        }
    )

    if not task:
        raise HTTPException(
            status_code=404,
            detail="Task not found"
        )

    return {
        "status": True,
        "data": task
    }

@router.put("/{task_id}")
async def update_task(
    task_id: str,
    task_data: TaskUpdate,
    current_user=Depends(require_role("ADMIN"))
):
    existing_task = await db.task.find_unique(
        where={
            "id": task_id
        }
    )

    if not existing_task:
        raise HTTPException(
            status_code=404,
            detail="Task not found"
        )

    update_data = {}

    if task_data.title is not None:
        update_data["title"] = task_data.title

    if task_data.description is not None:
        update_data["description"] = task_data.description

    if task_data.priority is not None:
        if task_data.priority not in [
            "LOW",
            "MEDIUM",
            "HIGH"
        ]:
            raise HTTPException(
                status_code=400,
                detail="Invalid task priority"
            )

        update_data["priority"] = task_data.priority

    if task_data.status is not None:
        if task_data.status not in [
            "PENDING",
            "IN_PROGRESS",
            "COMPLETED"
        ]:
            raise HTTPException(
                status_code=400,
                detail="Invalid task status"
            )

        update_data["status"] = task_data.status

    if task_data.userId is not None:
        user = await db.user.find_unique(
            where={
                "id": task_data.userId
            }
        )

        if not user:
            raise HTTPException(
                status_code=404,
                detail="Employee not found"
            )

        if user.role != "EMPLOYEE":
            raise HTTPException(
                status_code=400,
                detail="Task can only be assigned to an employee"
            )

        update_data["userId"] = task_data.userId

    updated_task = await db.task.update(
        where={
            "id": task_id
        },
        data=update_data
    )

    return {
        "status": True,
        "message": "Task updated successfully",
        "data": updated_task
    }

@router.delete("/{task_id}")
async def delete_task(
    task_id: str,
    current_user=Depends(require_role("ADMIN"))
):
    existing_task = await db.task.find_unique(
        where={
            "id": task_id
        }
    )

    if not existing_task:
        raise HTTPException(
            status_code=404,
            detail="Task not found"
        )

    await db.task.delete(
        where={
            "id": task_id
        }
    )

    return {
        "status": True,
        "message": "Task deleted successfully"
    }