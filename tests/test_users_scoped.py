"""
Agency-scoped user endpoint tests.

All DB and middleware calls are mocked — no live server or database required.
Covers the cross-agency IDOR protection added in feature/user-task-scoping.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import HTTPException

from app.schemas.auth import UserContext, AgencyContext
from app.routers.users import (
    get_employees,
    dashboard_stats,
    get_employee,
    update_employee,
    delete_employee,
)
from app.schemas.user import UserUpdate

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


def _make_membership(user_id: str, agency_id: str, role: str) -> MagicMock:
    """Creates a fake AgencyMembership with an embedded .user attribute."""
    m = fake_membership(user_id, agency_id, role)
    m.user = fake_user(user_id, role)
    m.createdAt = "2024-01-01T00:00:00Z"
    return m


# ===========================================================================
# GET /users/employees
# ===========================================================================

class TestGetEmployees:
    async def test_returns_only_agency_employees(self):
        """Employees from another agency must not appear in the response."""
        ctx = _admin_ctx()
        emp_membership = _make_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.find_many = AsyncMock(
                return_value=[emp_membership]
            )
            mock_db.task.count = AsyncMock(return_value=3)

            result = await get_employees(agency_ctx=ctx)

        assert result["status"] is True
        assert len(result["data"]) == 1
        assert result["data"][0]["id"] == EMPLOYEE_ID
        # Verify the DB was called with the agency filter
        mock_db.agencymembership.find_many.assert_awaited_once()
        call_kwargs = mock_db.agencymembership.find_many.call_args.kwargs
        assert call_kwargs["where"]["agencyId"] == AGENCY_ID

    async def test_task_count_scoped_to_agency(self):
        """Task count per employee must be filtered by agencyId."""
        ctx = _admin_ctx()
        emp_membership = _make_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.find_many = AsyncMock(
                return_value=[emp_membership]
            )
            mock_db.task.count = AsyncMock(return_value=5)

            result = await get_employees(agency_ctx=ctx)

        count_call = mock_db.task.count.call_args.kwargs
        assert count_call["where"]["agencyId"] == AGENCY_ID
        assert count_call["where"]["userId"] == EMPLOYEE_ID
        assert result["data"][0]["_count"]["tasks"] == 5

    async def test_super_admin_context_also_filtered(self):
        """SUPER_ADMIN using a different agency_id must see that agency's data."""
        ctx = _super_admin_ctx(agency_id=OTHER_AGENCY)
        emp_membership = _make_membership(EMPLOYEE_ID, OTHER_AGENCY, "EMPLOYEE")

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.find_many = AsyncMock(
                return_value=[emp_membership]
            )
            mock_db.task.count = AsyncMock(return_value=0)
            await get_employees(agency_ctx=ctx)

        call_kwargs = mock_db.agencymembership.find_many.call_args.kwargs
        assert call_kwargs["where"]["agencyId"] == OTHER_AGENCY


# ===========================================================================
# GET /users/dashboard-stats
# ===========================================================================

class TestDashboardStats:
    async def test_counts_scoped_to_agency(self):
        ctx = _admin_ctx()

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.count = AsyncMock(return_value=4)
            mock_db.task.count = AsyncMock(side_effect=[10, 3])

            result = await dashboard_stats(agency_ctx=ctx)

        assert result["data"]["totalEmployees"] == 4
        assert result["data"]["totalTasks"] == 10
        assert result["data"]["pendingTasks"] == 3

        # Both task.count calls must include the agency filter
        calls = mock_db.task.count.call_args_list
        for c in calls:
            assert c.kwargs["where"]["agencyId"] == AGENCY_ID

    async def test_membership_count_filters_by_employee_role(self):
        ctx = _admin_ctx()

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.count = AsyncMock(return_value=2)
            mock_db.task.count = AsyncMock(return_value=0)
            await dashboard_stats(agency_ctx=ctx)

        membership_call = mock_db.agencymembership.count.call_args.kwargs
        assert membership_call["where"]["agencyId"] == AGENCY_ID
        assert membership_call["where"]["role"] == "EMPLOYEE"


# ===========================================================================
# GET /users/{user_id}
# ===========================================================================

class TestGetEmployee:
    async def test_returns_employee_in_agency(self):
        ctx = _admin_ctx()
        membership = _make_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")
        membership.user.role = "EMPLOYEE"

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            result = await get_employee(user_id=EMPLOYEE_ID, agency_ctx=ctx)

        assert result["data"]["id"] == EMPLOYEE_ID

    async def test_cross_agency_returns_404(self):
        """A user_id from another agency must yield 404, not leak data."""
        ctx = _admin_ctx(agency_id=AGENCY_ID)

        with patch("app.routers.users.db") as mock_db:
            # No membership in AGENCY_ID for this foreign user
            mock_db.agencymembership.find_unique = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await get_employee(user_id=EMPLOYEE_ID, agency_ctx=ctx)

        assert exc_info.value.status_code == 404

    async def test_admin_user_in_agency_returns_404(self):
        """Only EMPLOYEE-role members are exposed via this endpoint."""
        ctx = _admin_ctx()
        membership = _make_membership(ADMIN_ID, AGENCY_ID, "ADMIN")
        membership.user.role = "ADMIN"

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            with pytest.raises(HTTPException) as exc_info:
                await get_employee(user_id=ADMIN_ID, agency_ctx=ctx)

        assert exc_info.value.status_code == 404

    async def test_membership_lookup_uses_agency_id(self):
        """Verifies the membership lookup is keyed on the correct agency."""
        ctx = _admin_ctx(agency_id=AGENCY_ID)

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=None)
            with pytest.raises(HTTPException):
                await get_employee(user_id=EMPLOYEE_ID, agency_ctx=ctx)

        lookup = mock_db.agencymembership.find_unique.call_args.kwargs
        assert lookup["where"]["userId_agencyId"]["agencyId"] == AGENCY_ID


# ===========================================================================
# PUT /users/{user_id}
# ===========================================================================

class TestUpdateEmployee:
    async def test_updates_employee_within_agency(self):
        ctx = _admin_ctx()
        membership = fake_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")
        existing_user = fake_user(EMPLOYEE_ID, "EMPLOYEE")
        existing_user.email = "old@example.com"
        updated_user = fake_user(EMPLOYEE_ID, "EMPLOYEE")
        updated_user.name = "New Name"
        updated_user.email = "old@example.com"

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            mock_db.user.find_unique = AsyncMock(return_value=existing_user)
            mock_db.user.update = AsyncMock(return_value=updated_user)

            result = await update_employee(
                user_id=EMPLOYEE_ID,
                user_data=UserUpdate(name="New Name"),
                agency_ctx=ctx,
            )

        assert result["status"] is True
        assert result["message"] == "User updated successfully"

    async def test_cross_agency_update_raises_404(self):
        ctx = _admin_ctx(agency_id=AGENCY_ID)

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await update_employee(
                    user_id=EMPLOYEE_ID,
                    user_data=UserUpdate(name="Hacked"),
                    agency_ctx=ctx,
                )

        assert exc_info.value.status_code == 404

    async def test_duplicate_email_raises_409(self):
        ctx = _admin_ctx()
        membership = fake_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")
        existing_user = fake_user(EMPLOYEE_ID, "EMPLOYEE")
        existing_user.email = "old@example.com"
        conflicting = fake_user("other-id", "EMPLOYEE")

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            mock_db.user.find_unique = AsyncMock(
                side_effect=[existing_user, conflicting]
            )
            with pytest.raises(HTTPException) as exc_info:
                await update_employee(
                    user_id=EMPLOYEE_ID,
                    user_data=UserUpdate(email="taken@example.com"),
                    agency_ctx=ctx,
                )

        assert exc_info.value.status_code == 409


# ===========================================================================
# DELETE /users/{user_id}
# ===========================================================================

class TestDeleteEmployee:
    async def test_removes_membership_not_user_account(self):
        """Deletion must only remove the AgencyMembership, not the User row."""
        ctx = _admin_ctx()
        membership = _make_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")
        membership.user.role = "EMPLOYEE"

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            mock_db.agencymembership.delete = AsyncMock()
            # user.delete must NOT be called
            mock_db.user.delete = AsyncMock()

            result = await delete_employee(user_id=EMPLOYEE_ID, agency_ctx=ctx)

        mock_db.agencymembership.delete.assert_awaited_once()
        mock_db.user.delete.assert_not_awaited()
        assert result["status"] is True

    async def test_cross_agency_delete_raises_404(self):
        ctx = _admin_ctx(agency_id=AGENCY_ID)

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await delete_employee(user_id=EMPLOYEE_ID, agency_ctx=ctx)

        assert exc_info.value.status_code == 404

    async def test_deleting_admin_raises_403(self):
        ctx = _admin_ctx()
        membership = _make_membership(ADMIN_ID, AGENCY_ID, "ADMIN")
        membership.user.role = "ADMIN"

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            with pytest.raises(HTTPException) as exc_info:
                await delete_employee(user_id=ADMIN_ID, agency_ctx=ctx)

        assert exc_info.value.status_code == 403

    async def test_delete_uses_compound_key(self):
        """The delete call must use the userId_agencyId compound key."""
        ctx = _admin_ctx(agency_id=AGENCY_ID)
        membership = _make_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")
        membership.user.role = "EMPLOYEE"

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            mock_db.agencymembership.delete = AsyncMock()
            await delete_employee(user_id=EMPLOYEE_ID, agency_ctx=ctx)

        delete_call = mock_db.agencymembership.delete.call_args.kwargs
        assert delete_call["where"]["userId_agencyId"]["userId"] == EMPLOYEE_ID
        assert delete_call["where"]["userId_agencyId"]["agencyId"] == AGENCY_ID
