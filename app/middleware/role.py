"""
Authorization middleware — answers "Is this caller allowed to do X?"

Platform role vs. Agency role
------------------------------
*Platform role* (User.role in the DB): a single global role for the whole
system.  Only SUPER_ADMIN exists at this level in the intended final design.

*Agency role* (AgencyMembership.role): the role a user holds *inside a
specific agency*.  The same user can be ADMIN in Agency A and EMPLOYEE in
Agency B simultaneously.

Why agency membership is checked server-side
--------------------------------------------
The client sends an ``X-Agency-ID`` header to say "I want to act on agency X".
We never trust that claim blindly.  Before honouring it we look up
``AgencyMembership`` in the database to confirm the calling user actually
belongs to that agency and has the required role there.  This prevents any
user from constructing a request that claims membership in an agency they
don't belong to.

SUPER_ADMIN is special
-----------------------
A SUPER_ADMIN is a platform-level administrator, not an agency member.  They
are not expected to have rows in AgencyMembership.  ``require_platform_role``
accepts them unconditionally.  ``require_agency_role`` also grants them
platform-wide access by returning an AgencyContext with agency_role="SUPER_ADMIN"
(no membership row required), so they can inspect any agency's data when needed.

Backward compatibility shim
----------------------------
The old ``require_role("ADMIN")`` / ``require_role("EMPLOYEE")`` calls in
users.py and tasks.py continue to work unchanged through the ``require_role``
shim at the bottom of this file.  Those routers will be converted to the new
guards in the next step (agency-scoped queries).
"""

import uuid
from fastapi import Depends, HTTPException, Header
from typing import Optional

from app.middleware.auth import get_current_user
from app.database import db
from app.schemas.auth import UserContext, AgencyContext


# ---------------------------------------------------------------------------
# Platform-level guard
# ---------------------------------------------------------------------------

def require_platform_role(*allowed_roles: str):
    """
    Dependency factory.  Ensures the caller's *platform* role is in
    ``allowed_roles``.  No agency header is required or checked.

    Usage::

        @router.get("/admin-only")
        async def endpoint(user=Depends(require_platform_role("SUPER_ADMIN"))):
            ...
    """
    async def _check(
        current_user: UserContext = Depends(get_current_user)
    ) -> UserContext:
        if current_user.platform_role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail="Access denied: insufficient platform role"
            )
        return current_user

    return _check


# ---------------------------------------------------------------------------
# Agency-level guard
# ---------------------------------------------------------------------------

def require_agency_role(*allowed_roles: str):
    """
    Dependency factory.  Ensures:

      1. The ``X-Agency-ID`` header is present and is a valid UUID.
      2. The authenticated user has a membership in that agency with a role
         in ``allowed_roles`` — OR the user is a SUPER_ADMIN.

    Returns an ``AgencyContext`` containing the resolved user, agency ID,
    and effective agency role.

    SUPER_ADMIN bypass: a SUPER_ADMIN does not need an AgencyMembership row.
    They receive agency_role="SUPER_ADMIN" so downstream code can distinguish
    them from ordinary agency members.

    Usage::

        @router.post("/tasks")
        async def create_task(ctx=Depends(require_agency_role("ADMIN"))):
            agency_id = ctx.agency_id
            ...
    """
    async def _check(
        x_agency_id: Optional[str] = Header(default=None, alias="X-Agency-ID"),
        current_user: UserContext = Depends(get_current_user)
    ) -> AgencyContext:

        # --- SUPER_ADMIN platform bypass ------------------------------------
        if current_user.platform_role == "SUPER_ADMIN":
            # SUPER_ADMIN still needs to supply a valid agency ID when calling
            # agency-scoped endpoints so the query knows which agency to act on.
            # But we do NOT check for a membership row.
            if not x_agency_id:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "X-Agency-ID header is required even for SUPER_ADMIN "
                        "when calling agency-scoped endpoints"
                    )
                )
            _validate_uuid(x_agency_id)
            return AgencyContext(
                user=current_user,
                agency_id=x_agency_id,
                agency_role="SUPER_ADMIN"
            )

        # --- Regular user: header must be present and a valid UUID ----------
        if not x_agency_id:
            raise HTTPException(
                status_code=400,
                detail="X-Agency-ID header is required for this endpoint"
            )

        _validate_uuid(x_agency_id)

        # --- Look up membership in the database (server-side check) ---------
        membership = await db.agencymembership.find_unique(
            where={
                "userId_agencyId": {
                    "userId": current_user.id,
                    "agencyId": x_agency_id,
                }
            }
        )

        if not membership:
            raise HTTPException(
                status_code=403,
                detail="You are not a member of this agency"
            )

        # --- Check that the membership role satisfies the requirement -------
        member_role = str(membership.role)
        if member_role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Access denied: this endpoint requires one of "
                    f"{list(allowed_roles)} in the selected agency"
                )
            )

        return AgencyContext(
            user=current_user,
            agency_id=x_agency_id,
            agency_role=member_role
        )

    return _check


# ---------------------------------------------------------------------------
# Backward-compatibility shim
# ---------------------------------------------------------------------------

def require_role(required_role: str):
    """
    Shim that preserves the old ``require_role("ADMIN")`` / ``require_role("EMPLOYEE")``
    call signature used in users.py and tasks.py.

    Behaviour mapping:

      - "ADMIN"      → accepts ADMIN **or** SUPER_ADMIN (SUPER_ADMIN can do
                        everything an ADMIN can on the platform level)
      - "EMPLOYEE"   → accepts EMPLOYEE only
      - anything else → exact match on platform_role

    This keeps those routers working without modification until the next step
    converts them to agency-scoped queries.
    """
    async def _check(
        current_user: UserContext = Depends(get_current_user)
    ) -> UserContext:
        role = current_user.platform_role

        if required_role == "ADMIN":
            # SUPER_ADMIN has all ADMIN privileges on the platform level
            if role not in ("ADMIN", "SUPER_ADMIN"):
                raise HTTPException(
                    status_code=403,
                    detail="Access denied"
                )
        else:
            if role != required_role:
                raise HTTPException(
                    status_code=403,
                    detail="Access denied"
                )

        return current_user

    return _check


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _validate_uuid(value: str) -> None:
    """Raise HTTP 400 if ``value`` is not a well-formed UUID."""
    try:
        uuid.UUID(value)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"X-Agency-ID '{value}' is not a valid UUID"
        )
