from pydantic import BaseModel
from enum import Enum

class TaskCreate(BaseModel):
    title: str
    description: str | None = None
    priority: str = "MEDIUM"
    status: str = "PENDING"
    userId: str

class TaskUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    priority: str | None = None
    status: str | None = None
    userId: str | None = None

class TaskStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"

class TaskStatusUpdate(BaseModel):
    status: TaskStatus