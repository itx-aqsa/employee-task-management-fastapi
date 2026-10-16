"""
Agency-scoped task endpoint tests.

All DB and middleware calls are mocked — no live server or database required.
Covers the cross-agency IDOR protection added in feature/user-task-scoping.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import HTTPException

from app.schemas.auth import UserContext, AgencyContext
from app.routers.tasks import (
    create_task,
    get_tasks,
    get_my_tasks,
    get_task_board,
    get_task,
    update_task,
    delete_task,
    update_task_status,
)
from app.schemas.task import TaskCreate, TaskUpdate, TaskStatus, TaskStatusUpdate

from tests.conftest import (
    ADMIN_ID,
    EMPLOYEE_ID,
    AGENCY_ID,
    OTHER_AGENCY,
    SUPER_ADMIN_ID,
    fake_user,
    fake_membership,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _admin_ctx(agency_id: str = AGENCY_ID) -> AgencyContext:
    return AgencyContext(
        user=UserContext(id=ADMIN_ID, platform_role="ADMIN"),
        agency_id=agency_id,
        agency_role="ADMIN",
    )


def _employee_ctx(agency_id: str = AGENCY_ID) -> AgencyContext:
    return AgencyContext(
        user=UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE"),
        agency_id=agency_id,
        agency_role="EMPLOYEE",
    )


def _super_admin_ctx(agency_id: str = AGENCY_ID) -> AgencyContext:
    return AgencyContext(
        user=UserContext(id=SUPER_ADMIN_ID, platform_role="SUPER_ADMIN"),
        agency_id=agency_id,
        agency_role="SUPER_ADMIN",
    )


def _fake_task(
    task_id: str,
    agency_id: str = AGENCY_ID,
    user_id: str = EMPLOYEE_ID,
    status: str = "PENDING",
) -> MagicMock:
    t = MagicMock()
    t.id = task_id
    t.agencyId = agency_id
    t.userId = user_id
    t.status = status
    t.title = "Test Task"
    t.description = None
    t.priority = "MEDIUM"
    return t


def _make_membership(user_id: str, agency_id: str, role: str) -> MagicMock:
    m = fake_membership(user_id, agency_id, role)
    m.user = fake_user(user_id, role)
    return m


TASK_ID = "eeeeeeee-0000-0000-0000-000000000005"


# ===========================================================================
# POST /tasks/
# ===========================================================================

class TestCreateTask:
    async def test_creates_task_in_agency(self):
        ctx = _admin_ctx()
        membership = _make_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")
        membership.user.role = "EMPLOYEE"
        created_task = _fake_task(TASK_ID)

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            mock_db.task.create = AsyncMock(return_value=created_task)

            result = await create_task(
                task=TaskCreate(title="Fix bug", userId=EMPLOYEE_ID),
                agency_ctx=ctx,
            )

        assert result["status"] is True
        create_call = mock_db.task.create.call_args.kwargs
        assert create_call["data"]["agencyId"] == AGENCY_ID

    async def test_cross_agency_assignee_raises_404(self):
        """Assigning to a user not in the agency must fail."""
        ctx = _admin_ctx(agency_id=AGENCY_ID)

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await create_task(
                    task=TaskCreate(title="Cross-agency task", userId=EMPLOYEE_ID),
                    agency_ctx=ctx,
                )

        assert exc_info.value.status_code == 404

    async def test_assigning_to_admin_raises_400(self):
        ctx = _admin_ctx()
        membership = _make_membership(ADMIN_ID, AGENCY_ID, "ADMIN")
        membership.user.role = "ADMIN"

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            with pytest.raises(HTTPException) as exc_info:
                await create_task(
                    task=TaskCreate(title="Task", userId=ADMIN_ID),
                    agency_ctx=ctx,
                )

        assert exc_info.value.status_code == 400

    async def test_invalid_priority_raises_400(self):
        ctx = _admin_ctx()
        membership = _make_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")
        membership.user.role = "EMPLOYEE"

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            with pytest.raises(HTTPException) as exc_info:
                await create_task(
                    task=TaskCreate(title="T", userId=EMPLOYEE_ID, priority="CRITICAL"),
                    agency_ctx=ctx,
                )

        assert exc_info.value.status_code == 400

    async def test_invalid_status_raises_400(self):
        ctx = _admin_ctx()
        membership = _make_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")
        membership.user.role = "EMPLOYEE"

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            with pytest.raises(HTTPException) as exc_info:
                await create_task(
                    task=TaskCreate(title="T", userId=EMPLOYEE_ID, status="DONE"),
                    agency_ctx=ctx,
                )

        assert exc_info.value.status_code == 400


# ===========================================================================
# GET /tasks/
# ===========================================================================

class TestGetTasks:
    async def test_returns_only_agency_tasks(self):
        ctx = _admin_ctx()
        task = _fake_task(TASK_ID)

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_many = AsyncMock(return_value=[task])
            result = await get_tasks(agency_ctx=ctx)

        assert result["status"] is True
        call_kwargs = mock_db.task.find_many.call_args.kwargs
        assert call_kwargs["where"]["agencyId"] == AGENCY_ID

    async def test_does_not_return_tasks_from_other_agency(self):
        """The query filter is the protection — a different agency_id must query differently."""
        ctx_a = _admin_ctx(agency_id=AGENCY_ID)
        ctx_b = _admin_ctx(agency_id=OTHER_AGENCY)

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_many = AsyncMock(return_value=[])
            await get_tasks(agency_ctx=ctx_a)
            call_a = mock_db.task.find_many.call_args_list[0].kwargs["where"]["agencyId"]

            await get_tasks(agency_ctx=ctx_b)
            call_b = mock_db.task.find_many.call_args_list[1].kwargs["where"]["agencyId"]

        assert call_a == AGENCY_ID
        assert call_b == OTHER_AGENCY
        assert call_a != call_b


# ===========================================================================
# GET /tasks/my-tasks
# ===========================================================================

class TestGetMyTasks:
    async def test_employee_sees_own_tasks_in_agency(self):
        ctx = _employee_ctx()
        task = _fake_task(TASK_ID, user_id=EMPLOYEE_ID)

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_many = AsyncMock(return_value=[task])
            result = await get_my_tasks(agency_ctx=ctx)

        assert result["status"] is True
        call_kwargs = mock_db.task.find_many.call_args.kwargs
        assert call_kwargs["where"]["userId"] == EMPLOYEE_ID
        assert call_kwargs["where"]["agencyId"] == AGENCY_ID

    async def test_tasks_from_other_agency_excluded(self):
        """The agency filter ensures tasks from another agency are not returned."""
        ctx = _employee_ctx(agency_id=AGENCY_ID)

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_many = AsyncMock(return_value=[])
            await get_my_tasks(agency_ctx=ctx)

        call_kwargs = mock_db.task.find_many.call_args.kwargs
        assert call_kwargs["where"]["agencyId"] == AGENCY_ID
        # A task with agencyId=OTHER_AGENCY would not match this filter


# ===========================================================================
# GET /tasks/board
# ===========================================================================

class TestGetTaskBoard:
    async def test_admin_board_scoped_to_agency(self):
        ctx = _admin_ctx()
        task = _fake_task(TASK_ID, status="PENDING")

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_many = AsyncMock(return_value=[task])
            result = await get_task_board(agency_ctx=ctx)

        assert "PENDING" in result["data"]
        call_kwargs = mock_db.task.find_many.call_args.kwargs
        assert call_kwargs["where"]["agencyId"] == AGENCY_ID
        # Admin branch must NOT filter by userId
        assert "userId" not in call_kwargs["where"]

    async def test_employee_board_scoped_to_own_tasks_in_agency(self):
        ctx = _employee_ctx()
        task = _fake_task(TASK_ID, user_id=EMPLOYEE_ID, status="IN_PROGRESS")

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_many = AsyncMock(return_value=[task])
            result = await get_task_board(agency_ctx=ctx)

        assert "IN_PROGRESS" in result["data"]
        call_kwargs = mock_db.task.find_many.call_args.kwargs
        assert call_kwargs["where"]["agencyId"] == AGENCY_ID
        assert call_kwargs["where"]["userId"] == EMPLOYEE_ID

    async def test_board_groups_tasks_by_status(self):
        ctx = _admin_ctx()
        tasks = [
            _fake_task("t1", status="PENDING"),
            _fake_task("t2", status="PENDING"),
            _fake_task("t3", status="COMPLETED"),
        ]

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_many = AsyncMock(return_value=tasks)
            result = await get_task_board(agency_ctx=ctx)

        board = result["data"]
        assert len(board["PENDING"]) == 2
        assert len(board["COMPLETED"]) == 1
        assert len(board["IN_PROGRESS"]) == 0


# ===========================================================================
# GET /tasks/{task_id}
# ===========================================================================

class TestGetTask:
    async def test_returns_task_in_agency(self):
        ctx = _admin_ctx()
        task = _fake_task(TASK_ID)

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_first = AsyncMock(return_value=task)
            result = await get_task(task_id=TASK_ID, agency_ctx=ctx)

        assert result["data"].id == TASK_ID
        call_kwargs = mock_db.task.find_first.call_args.kwargs
        assert call_kwargs["where"]["id"] == TASK_ID
        assert call_kwargs["where"]["agencyId"] == AGENCY_ID

    async def test_cross_agency_task_returns_404(self):
        """A task belonging to a different agency must appear as not found."""
        ctx = _admin_ctx(agency_id=AGENCY_ID)

        with patch("app.routers.tasks.db") as mock_db:
            # find_first returns None because agencyId doesn't match
            mock_db.task.find_first = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await get_task(task_id=TASK_ID, agency_ctx=ctx)

        assert exc_info.value.status_code == 404


# ===========================================================================
# PUT /tasks/{task_id}
# ===========================================================================

class TestUpdateTask:
    async def test_updates_task_within_agency(self):
        ctx = _admin_ctx()
        existing = _fake_task(TASK_ID)
        updated = _fake_task(TASK_ID)
        updated.title = "Updated Title"

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_first = AsyncMock(return_value=existing)
            mock_db.task.update = AsyncMock(return_value=updated)
            result = await update_task(
                task_id=TASK_ID,
                task_data=TaskUpdate(title="Updated Title"),
                agency_ctx=ctx,
            )

        assert result["status"] is True
        find_call = mock_db.task.find_first.call_args.kwargs
        assert find_call["where"]["agencyId"] == AGENCY_ID

    async def test_cross_agency_update_raises_404(self):
        ctx = _admin_ctx(agency_id=AGENCY_ID)

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_first = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await update_task(
                    task_id=TASK_ID,
                    task_data=TaskUpdate(title="Hacked"),
                    agency_ctx=ctx,
                )

        assert exc_info.value.status_code == 404

    async def test_reassign_to_cross_agency_employee_raises_404(self):
        """Re-assigning to a user not in this agency must fail."""
        ctx = _admin_ctx()
        existing = _fake_task(TASK_ID)
        OTHER_USER = "ffffffff-0000-0000-0000-000000000009"

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_first = AsyncMock(return_value=existing)
            mock_db.agencymembership.find_unique = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await update_task(
                    task_id=TASK_ID,
                    task_data=TaskUpdate(userId=OTHER_USER),
                    agency_ctx=ctx,
                )

        assert exc_info.value.status_code == 404


# ===========================================================================
# DELETE /tasks/{task_id}
# ===========================================================================

class TestDeleteTask:
    async def test_deletes_task_in_agency(self):
        ctx = _admin_ctx()
        existing = _fake_task(TASK_ID)

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_first = AsyncMock(return_value=existing)
            mock_db.task.delete = AsyncMock()
            result = await delete_task(task_id=TASK_ID, agency_ctx=ctx)

        assert result["status"] is True
        mock_db.task.delete.assert_awaited_once_with(where={"id": TASK_ID})

    async def test_cross_agency_delete_raises_404(self):
        ctx = _admin_ctx(agency_id=AGENCY_ID)

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_first = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await delete_task(task_id=TASK_ID, agency_ctx=ctx)

        assert exc_info.value.status_code == 404

    async def test_find_first_uses_agency_filter(self):
        ctx = _admin_ctx(agency_id=AGENCY_ID)

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_first = AsyncMock(return_value=None)
            with pytest.raises(HTTPException):
                await delete_task(task_id=TASK_ID, agency_ctx=ctx)

        call_kwargs = mock_db.task.find_first.call_args.kwargs
        assert call_kwargs["where"]["id"] == TASK_ID
        assert call_kwargs["where"]["agencyId"] == AGENCY_ID


# ===========================================================================
# PUT /tasks/{task_id}/status
# ===========================================================================

class TestUpdateTaskStatus:
    async def test_employee_can_update_own_task_status(self):
        ctx = _employee_ctx()
        task = _fake_task(TASK_ID, user_id=EMPLOYEE_ID, status="PENDING")
        updated = _fake_task(TASK_ID, user_id=EMPLOYEE_ID, status="IN_PROGRESS")

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_first = AsyncMock(return_value=task)
            mock_db.task.update = AsyncMock(return_value=updated)
            result = await update_task_status(
                task_id=TASK_ID,
                status_data=TaskStatusUpdate(status=TaskStatus.IN_PROGRESS),
                agency_ctx=ctx,
            )

        assert result["status"] is True

    async def test_employee_cannot_update_another_employees_task(self):
        OTHER_EMPLOYEE = "cccccccc-1111-1111-1111-000000000001"
        ctx = _employee_ctx()
        task = _fake_task(TASK_ID, user_id=OTHER_EMPLOYEE, status="PENDING")

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_first = AsyncMock(return_value=task)
            with pytest.raises(HTTPException) as exc_info:
                await update_task_status(
                    task_id=TASK_ID,
                    status_data=TaskStatusUpdate(status=TaskStatus.COMPLETED),
                    agency_ctx=ctx,
                )

        assert exc_info.value.status_code == 403

    async def test_admin_can_update_any_task_in_agency(self):
        ctx = _admin_ctx()
        task = _fake_task(TASK_ID, user_id=EMPLOYEE_ID, status="PENDING")
        updated = _fake_task(TASK_ID, user_id=EMPLOYEE_ID, status="COMPLETED")

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_first = AsyncMock(return_value=task)
            mock_db.task.update = AsyncMock(return_value=updated)
            result = await update_task_status(
                task_id=TASK_ID,
                status_data=TaskStatusUpdate(status=TaskStatus.COMPLETED),
                agency_ctx=ctx,
            )

        assert result["status"] is True

    async def test_cross_agency_task_status_update_raises_404(self):
        """Task from a different agency must appear as not found."""
        ctx = _employee_ctx(agency_id=AGENCY_ID)

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_first = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await update_task_status(
                    task_id=TASK_ID,
                    status_data=TaskStatusUpdate(status=TaskStatus.COMPLETED),
                    agency_ctx=ctx,
                )

        assert exc_info.value.status_code == 404

    async def test_status_update_query_includes_agency_filter(self):
        ctx = _employee_ctx()
        task = _fake_task(TASK_ID, user_id=EMPLOYEE_ID)

        with patch("app.routers.tasks.db") as mock_db:
            mock_db.task.find_first = AsyncMock(return_value=task)
            mock_db.task.update = AsyncMock(return_value=task)
            await update_task_status(
                task_id=TASK_ID,
                status_data=TaskStatusUpdate(status=TaskStatus.PENDING),
                agency_ctx=ctx,
            )

        call_kwargs = mock_db.task.find_first.call_args.kwargs
        assert call_kwargs["where"]["agencyId"] == AGENCY_ID
