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

    async def test_missing_agency_header_raises_400(self):
        ctx = UserContext(id=ADMIN_ID, platform_role="ADMIN")
        with pytest.raises(HTTPException) as exc_info:
            await require_agency_role("ADMIN")(x_agency_id=None, current_user=ctx)
        assert exc_info.value.status_code == 400

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
