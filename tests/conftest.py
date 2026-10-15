"""
Shared helpers and constants for auth tests.
All DB calls are mocked — no live database or server required.
"""
from unittest.mock import MagicMock
from app.core.security import create_access_token, ALGORITHM
from app.core.config import JWT_SECRET
from jose import jwt
from datetime import datetime, timedelta, timezone


# -- Token builders ----------------------------------------------------------

def make_token(user_id: str) -> str:
    return create_access_token(user_id)


def make_legacy_token(user_id: str, role: str) -> str:
    """Token with an old-style 'role' claim — must still decode cleanly."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=60)
    return jwt.encode({"sub": user_id, "role": role, "exp": expire}, JWT_SECRET, algorithm=ALGORITHM)


def make_expired_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) - timedelta(minutes=5)
    return jwt.encode({"sub": user_id, "exp": expire}, JWT_SECRET, algorithm=ALGORITHM)


# -- Fake DB objects ---------------------------------------------------------

def fake_user(user_id: str, role: str) -> MagicMock:
    u = MagicMock()
    u.id = user_id
    u.role = role
    return u


def fake_membership(user_id: str, agency_id: str, role: str) -> MagicMock:
    m = MagicMock()
    m.userId = user_id
    m.agencyId = agency_id
    m.role = role
    return m


# -- Reusable IDs ------------------------------------------------------------

SUPER_ADMIN_ID = "8ac50b13-a1e2-4874-98a8-528e8dc9c86d"
ADMIN_ID       = "aaaaaaaa-0000-0000-0000-000000000001"
EMPLOYEE_ID    = "bbbbbbbb-0000-0000-0000-000000000002"
AGENCY_ID      = "cccccccc-0000-0000-0000-000000000003"
OTHER_AGENCY   = "dddddddd-0000-0000-0000-000000000004"
