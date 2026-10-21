import uuid
from fastapi import Depends, HTTPException, Header
from typing import Optional
from prisma.enums import Role

from app.middleware.auth import get_current_user
from app.database import db
from app.schemas.auth import UserContext, AgencyContext


def require_platform_role(*allowed_roles: str):
    """Guard for platform-level endpoints. Checks User.role — no agency header needed."""
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


def require_agency_role(*allowed_roles: str):
    """
    Guard for agency-scoped endpoints.

    Requires a valid X-Agency-ID header and verifies the user has a matching
    AgencyMembership row. SUPER_ADMIN bypasses the membership check but still
    needs the header so queries know which agency to act on.

    Special case — EMPLOYEE or ADMIN without X-Agency-ID header:
        If the platform role is EMPLOYEE or ADMIN and the header is absent (or
        empty), the guard automatically resolves the agency by looking up the
        user's most-recent AgencyMembership row. This lets both employee and
        admin clients omit the header entirely when they belong to exactly one
        agency; the agency context is derived from the DB instead.
        If no membership is found the request is rejected with 403.
    """
    async def _check(
        x_agency_id: Optional[str] = Header(default=None, alias="X-Agency-ID"),
        current_user: UserContext = Depends(get_current_user)
    ) -> AgencyContext:

        # SUPER_ADMIN: skip membership lookup but still require the agency header.
        if current_user.platform_role == "SUPER_ADMIN":
            if not x_agency_id:
                raise HTTPException(
                    status_code=400,
                    detail="X-Agency-ID header is required even for SUPER_ADMIN when calling agency-scoped endpoints"
                )
            _validate_uuid(x_agency_id)
            return AgencyContext(user=current_user, agency_id=x_agency_id, agency_role="SUPER_ADMIN")

        # EMPLOYEE or ADMIN without header: auto-resolve agency from the membership table.
        # Filter by the user's platform role so we always get the right membership kind —
        # an ADMIN who was previously an EMPLOYEE in another agency won't accidentally
        # resolve to that EMPLOYEE membership and return stale/wrong agency data.
        if not x_agency_id and current_user.platform_role in ("EMPLOYEE", "ADMIN"):
            lookup_role = Role.ADMIN if current_user.platform_role == "ADMIN" else Role.EMPLOYEE
            membership = await db.agencymembership.find_first(
                where={"userId": current_user.id, "role": lookup_role},
                order={"createdAt": "desc"},
            )
            if not membership:
                raise HTTPException(
                    status_code=403,
                    detail="No agency membership found for this user"
                )
            member_role = str(membership.role)
            if member_role not in allowed_roles:
                raise HTTPException(
                    status_code=403,
                    detail=f"Access denied: this endpoint requires one of {list(allowed_roles)} in the selected agency"
                )
            return AgencyContext(
                user=current_user,
                agency_id=str(membership.agencyId),
                agency_role=member_role,
            )

        # All other cases still require the header explicitly.
        if not x_agency_id:
            raise HTTPException(
                status_code=400,
                detail="X-Agency-ID header is required for this endpoint"
            )

        _validate_uuid(x_agency_id)

        membership = await db.agencymembership.find_unique(
            where={
                "userId_agencyId": {
                    "userId": current_user.id,
                    "agencyId": x_agency_id,
                }
            }
        )

        if not membership:
            raise HTTPException(status_code=403, detail="You are not a member of this agency")

        member_role = str(membership.role)
        if member_role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Access denied: this endpoint requires one of {list(allowed_roles)} in the selected agency"
            )

        return AgencyContext(user=current_user, agency_id=x_agency_id, agency_role=member_role)

    return _check


def require_role(required_role: str):
    """
    Backward-compat shim for existing users.py / tasks.py call sites.

    "ADMIN" also accepts SUPER_ADMIN. All other roles require an exact match.
    Will be replaced by require_agency_role() in the next step.
    """
    async def _check(
        current_user: UserContext = Depends(get_current_user)
    ) -> UserContext:
        role = current_user.platform_role

        if required_role == "ADMIN":
            # SUPER_ADMIN has full platform-admin access
            if role not in ("ADMIN", "SUPER_ADMIN"):
                raise HTTPException(status_code=403, detail="Access denied")
        else:
            if role != required_role:
                raise HTTPException(status_code=403, detail="Access denied")

        return current_user

    return _check


def _validate_uuid(value: str) -> None:
    try:
        uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"X-Agency-ID '{value}' is not a valid UUID")
