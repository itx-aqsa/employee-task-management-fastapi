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
    create_employee,
    get_employees,
    dashboard_stats,
    platform_stats,
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
            mock_db.agencymembership.count = AsyncMock(side_effect=[1, 4])
            mock_db.task.count = AsyncMock(side_effect=[10, 3, 5, 2])

            result = await dashboard_stats(agency_ctx=ctx)

        assert result["data"]["totalAdmins"] == 1
        assert result["data"]["totalEmployees"] == 4
        assert result["data"]["totalTasks"] == 10
        assert result["data"]["pendingTasks"] == 3
        assert result["data"]["inProgressTasks"] == 5
        assert result["data"]["completedTasks"] == 2

        # All task.count calls must include the agency filter
        calls = mock_db.task.count.call_args_list
        for c in calls:
            assert c.kwargs["where"]["agencyId"] == AGENCY_ID

    async def test_membership_count_filters_by_employee_role(self):
        ctx = _admin_ctx()

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.count = AsyncMock(return_value=2)
            mock_db.task.count = AsyncMock(return_value=0)
            await dashboard_stats(agency_ctx=ctx)

        calls = mock_db.agencymembership.count.call_args_list
        # First call: ADMIN count, second call: EMPLOYEE count
        assert any(
            c.kwargs["where"]["agencyId"] == AGENCY_ID and c.kwargs["where"]["role"] == "EMPLOYEE"
            for c in calls
        )

    async def test_membership_count_includes_admin_role(self):
        """dashboard_stats must also count ADMIN memberships in the agency."""
        ctx = _admin_ctx()

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.count = AsyncMock(return_value=1)
            mock_db.task.count = AsyncMock(return_value=0)
            await dashboard_stats(agency_ctx=ctx)

        calls = mock_db.agencymembership.count.call_args_list
        assert any(
            c.kwargs["where"]["agencyId"] == AGENCY_ID and c.kwargs["where"]["role"] == "ADMIN"
            for c in calls
        )

    async def test_in_progress_and_completed_task_counts_included(self):
        """dashboard_stats must return inProgressTasks and completedTasks."""
        ctx = _admin_ctx()

        with patch("app.routers.users.db") as mock_db:
            mock_db.agencymembership.count = AsyncMock(return_value=0)
            mock_db.task.count = AsyncMock(side_effect=[7, 2, 3, 2])

            result = await dashboard_stats(agency_ctx=ctx)

        assert "inProgressTasks" in result["data"]
        assert "completedTasks" in result["data"]
        assert result["data"]["inProgressTasks"] == 3
        assert result["data"]["completedTasks"] == 2


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


# ===========================================================================
# GET /users/platform-stats
# ===========================================================================

class TestPlatformStats:
    async def test_returns_platform_wide_counts(self):
        """SUPER_ADMIN receives aggregated counts across all agencies."""
        from app.schemas.auth import UserContext
        super_admin = UserContext(id=SUPER_ADMIN_ID, platform_role="SUPER_ADMIN")

        with patch("app.routers.users.db") as mock_db:
            # user.count is called 3 times: total, admins, employees
            mock_db.user.count = AsyncMock(side_effect=[10, 2, 8])
            mock_db.agency.count = AsyncMock(return_value=3)
            mock_db.task.count = AsyncMock(side_effect=[25, 8, 10, 7])

            result = await platform_stats(current_user=super_admin)

        assert result["status"] is True
        assert result["data"]["totalUsers"] == 10
        assert result["data"]["totalAgencies"] == 3
        assert result["data"]["totalAdmins"] == 2
        assert result["data"]["totalEmployees"] == 8
        assert result["data"]["totalTasks"] == 25
        assert result["data"]["pendingTasks"] == 8
        assert result["data"]["inProgressTasks"] == 10
        assert result["data"]["completedTasks"] == 7

    async def test_pending_tasks_count_uses_status_filter(self):
        """The pending task.count call must filter by PENDING status."""
        from app.schemas.auth import UserContext
        super_admin = UserContext(id=SUPER_ADMIN_ID, platform_role="SUPER_ADMIN")

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.count = AsyncMock(side_effect=[5, 1, 4])
            mock_db.agency.count = AsyncMock(return_value=1)
            mock_db.task.count = AsyncMock(side_effect=[12, 4, 5, 3])

            await platform_stats(current_user=super_admin)

        # Find the task.count call with status=PENDING
        from prisma.enums import Status
        task_calls = mock_db.task.count.call_args_list
        statuses = [c.kwargs.get("where", {}).get("status") for c in task_calls]
        assert Status.PENDING in statuses

    async def test_in_progress_and_completed_counts_present(self):
        """platform_stats must return inProgressTasks and completedTasks."""
        from app.schemas.auth import UserContext
        super_admin = UserContext(id=SUPER_ADMIN_ID, platform_role="SUPER_ADMIN")

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.count = AsyncMock(side_effect=[5, 1, 4])
            mock_db.agency.count = AsyncMock(return_value=1)
            mock_db.task.count = AsyncMock(side_effect=[12, 4, 5, 3])

            result = await platform_stats(current_user=super_admin)

        assert "inProgressTasks" in result["data"]
        assert "completedTasks" in result["data"]

    async def test_admin_and_employee_counts_use_user_table(self):
        """totalAdmins and totalEmployees must be counted from User rows, not memberships.

        This ensures each person is counted once even if they belong to multiple
        agencies, and the count never returns 0 due to a membership lookup miss.
        """
        from app.schemas.auth import UserContext
        from prisma.enums import Role
        super_admin = UserContext(id=SUPER_ADMIN_ID, platform_role="SUPER_ADMIN")

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.count = AsyncMock(side_effect=[10, 3, 7])
            mock_db.agency.count = AsyncMock(return_value=2)
            mock_db.task.count = AsyncMock(side_effect=[20, 5, 8, 7])

            result = await platform_stats(current_user=super_admin)

        assert "totalAdmins" in result["data"]
        assert "totalEmployees" in result["data"]

        # user.count must be called with role=Role.ADMIN and role=Role.EMPLOYEE
        user_calls = mock_db.user.count.call_args_list
        role_filters = [c.kwargs.get("where", {}).get("role") for c in user_calls]
        assert Role.ADMIN in role_filters
        assert Role.EMPLOYEE in role_filters

        # agencymembership.count must NOT be called for admin/employee counts
        mock_db.agencymembership.count.assert_not_called()

    async def test_no_agency_header_needed(self):
        """platform_stats accepts a plain UserContext — no AgencyContext required."""
        import inspect
        sig = inspect.signature(platform_stats)
        assert "current_user" in sig.parameters
        assert "agency_ctx" not in sig.parameters


# ===========================================================================
# GET /users/profile
# ===========================================================================

class TestGetProfile:
    async def test_employee_profile_includes_agency_id(self):
        """An EMPLOYEE with a membership gets agencyId in the response."""
        from app.schemas.auth import UserContext
        from app.routers.users import get_profile

        user_ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")
        mock_user = fake_user(EMPLOYEE_ID, "EMPLOYEE")
        mock_user.name = "Alice"
        mock_user.email = "alice@example.com"
        mock_membership = fake_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=mock_user)
            mock_db.agencymembership.find_first = AsyncMock(return_value=mock_membership)

            result = await get_profile(current_user=user_ctx)

        assert result["status"] is True
        assert result["data"]["id"] == EMPLOYEE_ID
        assert result["data"]["agencyId"] == AGENCY_ID

    async def test_admin_profile_includes_agency_id(self):
        """An ADMIN with a membership also gets agencyId in the response."""
        from app.schemas.auth import UserContext
        from app.routers.users import get_profile

        user_ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        mock_user = fake_user(ADMIN_ID, "ADMIN")
        mock_user.name = "Bob"
        mock_user.email = "bob@example.com"
        mock_membership = fake_membership(ADMIN_ID, AGENCY_ID, "ADMIN")

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=mock_user)
            mock_db.agencymembership.find_first = AsyncMock(return_value=mock_membership)

            result = await get_profile(current_user=user_ctx)

        assert result["data"]["agencyId"] == AGENCY_ID

    async def test_super_admin_profile_has_null_agency_id(self):
        """A SUPER_ADMIN with no membership gets agencyId: None."""
        from app.schemas.auth import UserContext
        from app.routers.users import get_profile

        user_ctx = UserContext(id=SUPER_ADMIN_ID, platform_role="SUPER_ADMIN")
        mock_user = fake_user(SUPER_ADMIN_ID, "SUPER_ADMIN")
        mock_user.name = "Root"
        mock_user.email = "root@example.com"

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=mock_user)

            result = await get_profile(current_user=user_ctx)

        assert result["data"]["agencyId"] is None

    async def test_membership_lookup_uses_user_id(self):
        """The membership query must be scoped to the current user's id."""
        from app.schemas.auth import UserContext
        from app.routers.users import get_profile

        user_ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")
        mock_user = fake_user(EMPLOYEE_ID, "EMPLOYEE")
        mock_user.name = "Charlie"
        mock_user.email = "charlie@example.com"
        mock_membership = fake_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=mock_user)
            mock_db.agencymembership.find_first = AsyncMock(return_value=mock_membership)

            await get_profile(current_user=user_ctx)

        call_kwargs = mock_db.agencymembership.find_first.call_args.kwargs
        assert call_kwargs["where"]["userId"] == EMPLOYEE_ID

    async def test_employee_profile_membership_lookup_filters_by_employee_role(self):
        """The membership query for EMPLOYEE must include role=EMPLOYEE filter.

        Without this filter an EMPLOYEE who also has a stale membership in another
        agency (e.g. created more recently) would receive the wrong agencyId and
        see 0 tasks / 0 employees on their dashboard.
        """
        from app.schemas.auth import UserContext
        from app.routers.users import get_profile
        from prisma.enums import Role

        user_ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")
        mock_user = fake_user(EMPLOYEE_ID, "EMPLOYEE")
        mock_user.name = "Dana"
        mock_user.email = "dana@example.com"
        mock_membership = fake_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=mock_user)
            mock_db.agencymembership.find_first = AsyncMock(return_value=mock_membership)

            await get_profile(current_user=user_ctx)

        call_kwargs = mock_db.agencymembership.find_first.call_args.kwargs
        assert call_kwargs["where"]["userId"] == EMPLOYEE_ID
        assert call_kwargs["where"]["role"] == Role.EMPLOYEE

    async def test_admin_profile_membership_lookup_filters_by_admin_role(self):
        """The membership query for ADMIN must include role=ADMIN filter.

        This is the core fix for the Agency Admin dashboard showing 0 employees
        and 0 tasks. Without a role filter, if the ADMIN also has a more recently
        created EMPLOYEE membership in another agency, get_profile returns that
        other agency's ID. The frontend sends it as X-Agency-ID, and all
        agency-scoped queries target the wrong agency, returning 0 results.
        """
        from app.schemas.auth import UserContext
        from app.routers.users import get_profile
        from prisma.enums import Role

        user_ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        mock_user = fake_user(ADMIN_ID, "ADMIN")
        mock_user.name = "Eve"
        mock_user.email = "eve@example.com"
        mock_membership = fake_membership(ADMIN_ID, AGENCY_ID, "ADMIN")

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=mock_user)
            mock_db.agencymembership.find_first = AsyncMock(return_value=mock_membership)

            await get_profile(current_user=user_ctx)

        call_kwargs = mock_db.agencymembership.find_first.call_args.kwargs
        assert call_kwargs["where"]["userId"] == ADMIN_ID
        assert call_kwargs["where"]["role"] == Role.ADMIN

    async def test_admin_with_stale_employee_membership_returns_admin_agency_id(self):
        """ADMIN with a newer EMPLOYEE membership in OTHER_AGENCY must still get their
        ADMIN agency's ID from get_profile, not the EMPLOYEE agency's ID.

        This directly reproduces the dashboard bug: if get_profile returns the
        EMPLOYEE agency's ID, all dashboard requests use the wrong agencyId,
        querying a different agency where the admin has no employees or tasks.
        """
        from app.schemas.auth import UserContext
        from app.routers.users import get_profile
        from prisma.enums import Role

        user_ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        mock_user = fake_user(ADMIN_ID, "ADMIN")
        mock_user.name = "Frank"
        mock_user.email = "frank@example.com"

        # The DB returns the ADMIN membership (role filter applied), even though
        # there is theoretically a newer EMPLOYEE membership in OTHER_AGENCY.
        admin_membership = fake_membership(ADMIN_ID, AGENCY_ID, "ADMIN")

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=mock_user)
            # find_first with role=ADMIN returns the correct agency membership.
            mock_db.agencymembership.find_first = AsyncMock(return_value=admin_membership)

            result = await get_profile(current_user=user_ctx)

        # Must return the ADMIN's agency, not the stale EMPLOYEE agency.
        assert result["data"]["agencyId"] == AGENCY_ID

        # Confirm the role filter was sent to the DB.
        call_kwargs = mock_db.agencymembership.find_first.call_args.kwargs
        assert call_kwargs["where"]["role"] == Role.ADMIN

    async def test_super_admin_profile_skips_membership_lookup(self):
        """SUPER_ADMIN profile must return agencyId=None without querying AgencyMembership."""
        from app.schemas.auth import UserContext
        from app.routers.users import get_profile

        user_ctx = UserContext(id=SUPER_ADMIN_ID, platform_role="SUPER_ADMIN")
        mock_user = fake_user(SUPER_ADMIN_ID, "SUPER_ADMIN")
        mock_user.name = "Root"
        mock_user.email = "root@example.com"

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=mock_user)
            mock_db.agencymembership.find_first = AsyncMock(return_value=None)

            result = await get_profile(current_user=user_ctx)

        # SUPER_ADMIN has no membership to look up — must not call find_first.
        mock_db.agencymembership.find_first.assert_not_called()
        assert result["data"]["agencyId"] is None


# ===========================================================================
# POST /users/employees
# ===========================================================================

class TestCreateEmployee:
    async def test_creates_user_and_membership_in_agency(self):
        """Happy path: new EMPLOYEE user is created and enrolled in the agency."""
        from app.schemas.user import EmployeeCreate
        from app.routers.users import create_employee

        ctx = _admin_ctx()
        new_user_id = "eeeeeeee-0000-0000-0000-000000000005"

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=None)  # email free

            created_user = fake_user(new_user_id, "EMPLOYEE")
            created_user.name = "Eve"
            created_user.email = "eve@example.com"
            mock_db.user.create = AsyncMock(return_value=created_user)

            created_membership = fake_membership(new_user_id, AGENCY_ID, "EMPLOYEE")
            created_membership.id = "mem-99"
            mock_db.agencymembership.create = AsyncMock(return_value=created_membership)

            result = await create_employee(
                payload=EmployeeCreate(name="Eve", email="eve@example.com", password="pass123"),
                agency_ctx=ctx,
            )

        assert result["status"] is True
        assert result["data"]["user"]["id"] == new_user_id
        assert result["data"]["user"]["role"] == "EMPLOYEE"
        assert result["data"]["membership"]["agencyId"] == AGENCY_ID
        assert result["data"]["membership"]["role"] == "EMPLOYEE"

    async def test_create_employee_sets_employee_platform_role(self):
        """The user.create call must pass role='EMPLOYEE' regardless of the caller's role."""
        from app.schemas.user import EmployeeCreate
        from app.routers.users import create_employee

        ctx = _admin_ctx()
        captured = {}

        async def fake_create_user(*, data):
            captured.update(data)
            u = fake_user("new-id", data["role"])
            u.name = data["name"]
            u.email = data["email"]
            return u

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=None)
            mock_db.user.create = AsyncMock(side_effect=fake_create_user)
            mock_db.agencymembership.create = AsyncMock(
                return_value=fake_membership("new-id", AGENCY_ID, "EMPLOYEE")
            )

            await create_employee(
                payload=EmployeeCreate(name="Frank", email="frank@example.com", password="pw"),
                agency_ctx=ctx,
            )

        assert captured["role"] == "EMPLOYEE"

    async def test_create_employee_hashes_password(self):
        """The stored password must not be the plain-text value sent by the client."""
        from app.schemas.user import EmployeeCreate
        from app.routers.users import create_employee

        ctx = _admin_ctx()
        captured = {}

        async def fake_create_user(*, data):
            captured.update(data)
            u = fake_user("new-id", "EMPLOYEE")
            u.name = data["name"]
            u.email = data["email"]
            return u

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=None)
            mock_db.user.create = AsyncMock(side_effect=fake_create_user)
            mock_db.agencymembership.create = AsyncMock(
                return_value=fake_membership("new-id", AGENCY_ID, "EMPLOYEE")
            )

            await create_employee(
                payload=EmployeeCreate(name="Grace", email="grace@example.com", password="plaintext"),
                agency_ctx=ctx,
            )

        assert captured["password"] != "plaintext"

    async def test_create_employee_membership_uses_agency_from_context(self):
        """The membership must be linked to the agency from AgencyContext, not user input."""
        from app.schemas.user import EmployeeCreate
        from app.routers.users import create_employee

        ctx = _admin_ctx(agency_id=AGENCY_ID)
        membership_data = {}

        async def fake_create_membership(*, data):
            membership_data.update(data)
            return fake_membership(data["userId"], data["agencyId"], data["role"])

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=None)
            created_user = fake_user("new-id", "EMPLOYEE")
            created_user.name = "Heidi"
            created_user.email = "heidi@example.com"
            mock_db.user.create = AsyncMock(return_value=created_user)
            mock_db.agencymembership.create = AsyncMock(side_effect=fake_create_membership)

            await create_employee(
                payload=EmployeeCreate(name="Heidi", email="heidi@example.com", password="pw"),
                agency_ctx=ctx,
            )

        assert membership_data["agencyId"] == AGENCY_ID
        assert membership_data["role"] == "EMPLOYEE"

    async def test_create_employee_duplicate_email_raises_400(self):
        """400 when the email is already registered."""
        from app.schemas.user import EmployeeCreate
        from app.routers.users import create_employee

        ctx = _admin_ctx()

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(
                return_value=fake_user(EMPLOYEE_ID, "EMPLOYEE")  # email taken
            )
            with pytest.raises(HTTPException) as exc_info:
                await create_employee(
                    payload=EmployeeCreate(name="Ivan", email="taken@example.com", password="pw"),
                    agency_ctx=ctx,
                )

        assert exc_info.value.status_code == 400
        # No user or membership should have been created
        mock_db.user.create.assert_not_called()

    async def test_super_admin_can_create_employee(self):
        """SUPER_ADMIN context must also be accepted by the endpoint."""
        from app.schemas.user import EmployeeCreate
        from app.routers.users import create_employee

        ctx = _super_admin_ctx(agency_id=AGENCY_ID)

        with patch("app.routers.users.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=None)
            created_user = fake_user("new-id", "EMPLOYEE")
            created_user.name = "Judy"
            created_user.email = "judy@example.com"
            mock_db.user.create = AsyncMock(return_value=created_user)
            mock_db.agencymembership.create = AsyncMock(
                return_value=fake_membership("new-id", AGENCY_ID, "EMPLOYEE")
            )

            result = await create_employee(
                payload=EmployeeCreate(name="Judy", email="judy@example.com", password="pw"),
                agency_ctx=ctx,
            )

        assert result["status"] is True
        assert result["data"]["membership"]["agencyId"] == AGENCY_ID
