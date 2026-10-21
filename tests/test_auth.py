"""
Auth layer tests — security.py, auth.py, role.py.
All DB calls are mocked; no live server or database needed.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import HTTPException
from starlette.requests import Request

from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.middleware.auth import get_current_user
from app.middleware.role import (
    require_platform_role,
    require_agency_role,
    require_role,
    _validate_uuid,
)
from app.schemas.auth import UserContext, AgencyContext

from tests.conftest import (
    make_token,
    make_legacy_token,
    make_expired_token,
    fake_user,
    fake_membership,
    SUPER_ADMIN_ID,
    ADMIN_ID,
    EMPLOYEE_ID,
    AGENCY_ID,
    OTHER_AGENCY,
)


# ===========================================================================
# A. JWT — security.py
# ===========================================================================

class TestJWT:
    def test_token_contains_sub_only(self):
        """New tokens must NOT contain a role claim."""
        token = create_access_token(ADMIN_ID)
        payload = decode_access_token(token)
        assert payload["sub"] == ADMIN_ID
        assert "role" not in payload

    def test_token_is_decodable(self):
        token = create_access_token(SUPER_ADMIN_ID)
        payload = decode_access_token(token)
        assert payload["sub"] == SUPER_ADMIN_ID

    def test_expired_token_raises(self):
        from jose import JWTError
        token = make_expired_token(ADMIN_ID)
        with pytest.raises(JWTError):
            decode_access_token(token)

    def test_tampered_token_raises(self):
        from jose import JWTError
        token = create_access_token(ADMIN_ID) + "tampered"
        with pytest.raises(JWTError):
            decode_access_token(token)

    def test_legacy_token_decodes_without_error(self):
        """Old tokens with a role claim must still decode — claim is ignored."""
        token = make_legacy_token(ADMIN_ID, "ADMIN")
        payload = decode_access_token(token)
        assert payload["sub"] == ADMIN_ID
        assert "role" in payload  # present in payload but never read by middleware

    def test_password_hash_and_verify(self):
        hashed = hash_password("secret123")
        assert verify_password("secret123", hashed)
        assert not verify_password("wrong", hashed)


# ===========================================================================
# B. get_current_user — auth.py
# ===========================================================================

def _make_request(token: str | None) -> Request:
    scope = {"type": "http", "method": "GET", "path": "/", "query_string": b"", "headers": []}
    req = Request(scope)
    req._cookies = {"token": token} if token else {}
    return req


class TestGetCurrentUser:
    async def test_valid_token_returns_user_context(self):
        token = make_token(ADMIN_ID)
        req = _make_request(token)
        user_obj = fake_user(ADMIN_ID, "ADMIN")

        with patch("app.middleware.auth.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=user_obj)
            result = await get_current_user(req)

        assert isinstance(result, UserContext)
        assert result.id == ADMIN_ID
        assert result.platform_role == "ADMIN"

    async def test_no_cookie_raises_401(self):
        req = _make_request(None)
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(req)
        assert exc_info.value.status_code == 401

    async def test_expired_token_raises_401(self):
        token = make_expired_token(ADMIN_ID)
        req = _make_request(token)
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(req)
        assert exc_info.value.status_code == 401

    async def test_tampered_token_raises_401(self):
        token = create_access_token(ADMIN_ID) + "bad"
        req = _make_request(token)
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(req)
        assert exc_info.value.status_code == 401

    async def test_deleted_user_raises_401(self):
        """Token is valid but the account has been deleted from the DB."""
        token = make_token(ADMIN_ID)
        req = _make_request(token)
        with patch("app.middleware.auth.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(req)
        assert exc_info.value.status_code == 401

    async def test_legacy_token_role_is_ignored(self):
        """Token claims ADMIN but DB says EMPLOYEE — DB must win."""
        token = make_legacy_token(ADMIN_ID, "ADMIN")
        req = _make_request(token)
        user_obj = fake_user(ADMIN_ID, "EMPLOYEE")

        with patch("app.middleware.auth.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=user_obj)
            result = await get_current_user(req)

        assert result.platform_role == "EMPLOYEE"

    async def test_super_admin_role_loaded_from_db(self):
        token = make_token(SUPER_ADMIN_ID)
        req = _make_request(token)
        user_obj = fake_user(SUPER_ADMIN_ID, "SUPER_ADMIN")

        with patch("app.middleware.auth.db") as mock_db:
            mock_db.user.find_unique = AsyncMock(return_value=user_obj)
            result = await get_current_user(req)

        assert result.platform_role == "SUPER_ADMIN"


# ===========================================================================
# C. require_platform_role — role.py
# ===========================================================================

class TestRequirePlatformRole:
    async def test_super_admin_passes_super_admin_guard(self):
        ctx = UserContext(id=SUPER_ADMIN_ID, platform_role="SUPER_ADMIN")
        result = await require_platform_role("SUPER_ADMIN")(current_user=ctx)
        assert result.platform_role == "SUPER_ADMIN"

    async def test_admin_blocked_from_super_admin_endpoint(self):
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        with pytest.raises(HTTPException) as exc_info:
            await require_platform_role("SUPER_ADMIN")(current_user=ctx)
        assert exc_info.value.status_code == 403

    async def test_employee_blocked_from_super_admin_endpoint(self):
        ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")
        with pytest.raises(HTTPException) as exc_info:
            await require_platform_role("SUPER_ADMIN")(current_user=ctx)
        assert exc_info.value.status_code == 403

    async def test_multi_role_any_match_passes(self):
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        result = await require_platform_role("ADMIN", "SUPER_ADMIN")(current_user=ctx)
        assert result.platform_role == "ADMIN"

    async def test_super_admin_not_implicitly_granted_to_non_listed_guards(self):
        """SUPER_ADMIN must be explicitly listed — no implicit escalation."""
        ctx = UserContext(id=SUPER_ADMIN_ID, platform_role="SUPER_ADMIN")
        with pytest.raises(HTTPException) as exc_info:
            await require_platform_role("EMPLOYEE")(current_user=ctx)
        assert exc_info.value.status_code == 403


# ===========================================================================
# D. require_agency_role — role.py
# ===========================================================================

class TestRequireAgencyRole:
    async def test_valid_membership_returns_agency_context(self):
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        membership = fake_membership(ADMIN_ID, AGENCY_ID, "ADMIN")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            result = await require_agency_role("ADMIN")(x_agency_id=AGENCY_ID, current_user=ctx)

        assert isinstance(result, AgencyContext)
        assert result.agency_id == AGENCY_ID
        assert result.agency_role == "ADMIN"
        assert result.user.id == ADMIN_ID

    async def test_missing_agency_header_raises_400_for_unknown_role(self):
        """A role that is neither EMPLOYEE, ADMIN, nor SUPER_ADMIN gets 400 on missing header."""
        # Construct a context with a role that falls through all auto-resolve branches.
        ctx = UserContext(id=ADMIN_ID, platform_role="UNKNOWN_ROLE")
        with pytest.raises(HTTPException) as exc_info:
            await require_agency_role("ADMIN")(x_agency_id=None, current_user=ctx)
        assert exc_info.value.status_code == 400

    async def test_admin_missing_header_resolves_from_db_not_400(self):
        """ADMIN without header no longer gets 400 — it auto-resolves from the membership table."""
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        membership = fake_membership(ADMIN_ID, AGENCY_ID, "ADMIN")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_first = AsyncMock(return_value=membership)
            # Must succeed, not raise 400
            result = await require_agency_role("ADMIN")(x_agency_id=None, current_user=ctx)

        assert result.agency_id == AGENCY_ID

    async def test_invalid_uuid_agency_header_raises_400(self):
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        with pytest.raises(HTTPException) as exc_info:
            await require_agency_role("ADMIN")(x_agency_id="not-a-uuid", current_user=ctx)
        assert exc_info.value.status_code == 400

    async def test_no_membership_raises_403(self):
        ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await require_agency_role("ADMIN")(x_agency_id=AGENCY_ID, current_user=ctx)

        assert exc_info.value.status_code == 403
        assert "not a member" in exc_info.value.detail

    async def test_wrong_agency_role_raises_403(self):
        """User is EMPLOYEE in the agency but endpoint requires ADMIN."""
        ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")
        membership = fake_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            with pytest.raises(HTTPException) as exc_info:
                await require_agency_role("ADMIN")(x_agency_id=AGENCY_ID, current_user=ctx)

        assert exc_info.value.status_code == 403

    async def test_super_admin_bypasses_membership_check(self):
        """SUPER_ADMIN must pass without any AgencyMembership row."""
        ctx = UserContext(id=SUPER_ADMIN_ID, platform_role="SUPER_ADMIN")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=None)
            result = await require_agency_role("ADMIN")(x_agency_id=AGENCY_ID, current_user=ctx)

        mock_db.agencymembership.find_unique.assert_not_called()
        assert result.agency_role == "SUPER_ADMIN"
        assert result.agency_id == AGENCY_ID

    async def test_super_admin_without_agency_header_raises_400(self):
        """SUPER_ADMIN still needs to supply X-Agency-ID for agency-scoped endpoints."""
        ctx = UserContext(id=SUPER_ADMIN_ID, platform_role="SUPER_ADMIN")
        with pytest.raises(HTTPException) as exc_info:
            await require_agency_role("ADMIN")(x_agency_id=None, current_user=ctx)
        assert exc_info.value.status_code == 400

    async def test_cross_agency_access_denied(self):
        """User is ADMIN in AGENCY_ID but requests access to OTHER_AGENCY."""
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await require_agency_role("ADMIN")(x_agency_id=OTHER_AGENCY, current_user=ctx)

        assert exc_info.value.status_code == 403

    async def test_employee_role_accepted_for_employee_endpoint(self):
        ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")
        membership = fake_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            result = await require_agency_role("EMPLOYEE")(x_agency_id=AGENCY_ID, current_user=ctx)

        assert result.agency_role == "EMPLOYEE"


# ===========================================================================
# E. require_role shim — role.py
# ===========================================================================

class TestRequireRoleShim:
    async def test_admin_passes_admin_guard(self):
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        result = await require_role("ADMIN")(current_user=ctx)
        assert result.platform_role == "ADMIN"

    async def test_super_admin_passes_admin_guard(self):
        """SUPER_ADMIN must be allowed through require_role('ADMIN')."""
        ctx = UserContext(id=SUPER_ADMIN_ID, platform_role="SUPER_ADMIN")
        result = await require_role("ADMIN")(current_user=ctx)
        assert result.platform_role == "SUPER_ADMIN"

    async def test_employee_blocked_from_admin_guard(self):
        ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")
        with pytest.raises(HTTPException) as exc_info:
            await require_role("ADMIN")(current_user=ctx)
        assert exc_info.value.status_code == 403

    async def test_employee_passes_employee_guard(self):
        ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")
        result = await require_role("EMPLOYEE")(current_user=ctx)
        assert result.platform_role == "EMPLOYEE"

    async def test_admin_blocked_from_employee_guard(self):
        """ADMIN must not silently pass an employee-only guard."""
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        with pytest.raises(HTTPException) as exc_info:
            await require_role("EMPLOYEE")(current_user=ctx)
        assert exc_info.value.status_code == 403


# ===========================================================================
# F. _validate_uuid — role.py
# ===========================================================================

class TestValidateUUID:
    def test_valid_uuid_passes(self):
        _validate_uuid(AGENCY_ID)  # must not raise

    def test_invalid_string_raises_400(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_uuid("definitely-not-a-uuid")
        assert exc_info.value.status_code == 400

    def test_empty_string_raises_400(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_uuid("")
        assert exc_info.value.status_code == 400


# ===========================================================================
# G. require_agency_role — EMPLOYEE auto-resolve (no X-Agency-ID header)
# ===========================================================================

class TestRequireAgencyRoleEmployeeAutoResolve:
    async def test_employee_without_header_resolves_agency_from_membership(self):
        """EMPLOYEE omitting X-Agency-ID gets agency from their membership row."""
        ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")
        membership = fake_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_first = AsyncMock(return_value=membership)
            result = await require_agency_role("EMPLOYEE")(x_agency_id=None, current_user=ctx)

        assert isinstance(result, AgencyContext)
        assert result.agency_id == AGENCY_ID
        assert result.agency_role == "EMPLOYEE"
        assert result.user.id == EMPLOYEE_ID

    async def test_employee_without_header_uses_find_first_not_find_unique(self):
        """The auto-resolve path must use find_first filtered by userId AND role=EMPLOYEE."""
        ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")
        membership = fake_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_first = AsyncMock(return_value=membership)
            await require_agency_role("EMPLOYEE")(x_agency_id=None, current_user=ctx)

        from prisma.enums import Role
        mock_db.agencymembership.find_first.assert_awaited_once()
        call_kwargs = mock_db.agencymembership.find_first.call_args.kwargs
        assert call_kwargs["where"]["userId"] == EMPLOYEE_ID
        assert call_kwargs["where"]["role"] == Role.EMPLOYEE
        assert "order" in call_kwargs

    async def test_employee_without_header_no_membership_raises_403(self):
        """If auto-resolve finds no membership, the response must be 403, not 400."""
        ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_first = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await require_agency_role("EMPLOYEE")(x_agency_id=None, current_user=ctx)

        assert exc_info.value.status_code == 403
        assert "No agency membership found" in exc_info.value.detail

    async def test_employee_without_header_wrong_role_raises_403(self):
        """Auto-resolved membership role must still satisfy the endpoint's allowed_roles."""
        ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")
        # Membership exists but with EMPLOYEE role; endpoint requires ADMIN
        membership = fake_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_first = AsyncMock(return_value=membership)
            with pytest.raises(HTTPException) as exc_info:
                await require_agency_role("ADMIN")(x_agency_id=None, current_user=ctx)

        assert exc_info.value.status_code == 403

    async def test_admin_without_header_auto_resolves_agency(self):
        """ADMIN omitting X-Agency-ID now auto-resolves from their membership row."""
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        membership = fake_membership(ADMIN_ID, AGENCY_ID, "ADMIN")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_first = AsyncMock(return_value=membership)
            result = await require_agency_role("ADMIN")(x_agency_id=None, current_user=ctx)

        assert isinstance(result, AgencyContext)
        assert result.agency_id == AGENCY_ID
        assert result.agency_role == "ADMIN"

    async def test_employee_with_explicit_header_still_uses_find_unique(self):
        """When an EMPLOYEE does supply X-Agency-ID, the normal path must be used."""
        ctx = UserContext(id=EMPLOYEE_ID, platform_role="EMPLOYEE")
        membership = fake_membership(EMPLOYEE_ID, AGENCY_ID, "EMPLOYEE")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            result = await require_agency_role("EMPLOYEE")(
                x_agency_id=AGENCY_ID, current_user=ctx
            )

        mock_db.agencymembership.find_unique.assert_awaited_once()
        assert result.agency_id == AGENCY_ID


# ===========================================================================
# H. require_agency_role — ADMIN auto-resolve (no X-Agency-ID header)
# ===========================================================================

class TestRequireAgencyRoleAdminAutoResolve:
    async def test_admin_without_header_resolves_agency_from_membership(self):
        """ADMIN omitting X-Agency-ID gets agency resolved from their membership row."""
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        membership = fake_membership(ADMIN_ID, AGENCY_ID, "ADMIN")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_first = AsyncMock(return_value=membership)
            result = await require_agency_role("ADMIN")(x_agency_id=None, current_user=ctx)

        assert isinstance(result, AgencyContext)
        assert result.agency_id == AGENCY_ID
        assert result.agency_role == "ADMIN"
        assert result.user.id == ADMIN_ID

    async def test_admin_without_header_uses_find_first_not_find_unique(self):
        """The ADMIN auto-resolve path must use find_first filtered by userId AND role=ADMIN."""
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        membership = fake_membership(ADMIN_ID, AGENCY_ID, "ADMIN")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_first = AsyncMock(return_value=membership)
            await require_agency_role("ADMIN")(x_agency_id=None, current_user=ctx)

        from prisma.enums import Role
        mock_db.agencymembership.find_first.assert_awaited_once()
        call_kwargs = mock_db.agencymembership.find_first.call_args.kwargs
        assert call_kwargs["where"]["userId"] == ADMIN_ID
        assert call_kwargs["where"]["role"] == Role.ADMIN
        assert "order" in call_kwargs

    async def test_admin_without_header_no_membership_raises_403(self):
        """If ADMIN auto-resolve finds no membership, reject with 403, not 400."""
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_first = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await require_agency_role("ADMIN")(x_agency_id=None, current_user=ctx)

        assert exc_info.value.status_code == 403
        assert "No agency membership found" in exc_info.value.detail

    async def test_admin_without_header_employee_membership_raises_403(self):
        """ADMIN whose membership role is EMPLOYEE is rejected when endpoint needs ADMIN."""
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        membership = fake_membership(ADMIN_ID, AGENCY_ID, "EMPLOYEE")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_first = AsyncMock(return_value=membership)
            with pytest.raises(HTTPException) as exc_info:
                await require_agency_role("ADMIN")(x_agency_id=None, current_user=ctx)

        assert exc_info.value.status_code == 403

    async def test_admin_with_explicit_header_uses_find_unique(self):
        """When ADMIN supplies X-Agency-ID explicitly, the normal find_unique path runs."""
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        membership = fake_membership(ADMIN_ID, AGENCY_ID, "ADMIN")

        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_unique = AsyncMock(return_value=membership)
            result = await require_agency_role("ADMIN")(
                x_agency_id=AGENCY_ID, current_user=ctx
            )

        mock_db.agencymembership.find_unique.assert_awaited_once()
        mock_db.agencymembership.find_first.assert_not_called()
        assert result.agency_id == AGENCY_ID
        assert result.agency_role == "ADMIN"

    async def test_super_admin_still_requires_header_after_change(self):
        """SUPER_ADMIN must not be affected by the ADMIN auto-resolve change."""
        ctx = UserContext(id=SUPER_ADMIN_ID, platform_role="SUPER_ADMIN")
        with pytest.raises(HTTPException) as exc_info:
            await require_agency_role("ADMIN")(x_agency_id=None, current_user=ctx)
        assert exc_info.value.status_code == 400

    async def test_admin_role_filter_prevents_resolving_stale_employee_membership(self):
        """find_first for ADMIN must filter role=ADMIN so a stale EMPLOYEE membership
        in another agency is never returned and never causes wrong-agency data."""
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        # DB returns None because find_first is filtered to role=ADMIN — no match.
        with patch("app.middleware.role.db") as mock_db:
            mock_db.agencymembership.find_first = AsyncMock(return_value=None)
            with pytest.raises(HTTPException) as exc_info:
                await require_agency_role("ADMIN")(x_agency_id=None, current_user=ctx)

        # Must be 403 (no membership), not 400 (header missing), not 200 with wrong data.
        assert exc_info.value.status_code == 403
        # Confirm the role filter was actually sent to the DB.
        from prisma.enums import Role
        call_kwargs = mock_db.agencymembership.find_first.call_args.kwargs
        assert call_kwargs["where"].get("role") == Role.ADMIN
