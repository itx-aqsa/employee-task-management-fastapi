from fastapi import Depends, HTTPException
from app.database import db
from app.middleware.auth import get_current_user
from app.schemas.auth import UserContext


async def get_agency_admin(current_user: UserContext = Depends(get_current_user)):
    """Resolve the agency that the logged-in user is an ADMIN of.

    Agency-level roles live in AgencyMembership.role:
      - "ADMIN"    -> the user is an agency admin of that agency
      - "EMPLOYEE" -> the user is an employee of that agency
    """
    membership = await db.agencymembership.find_first(
        where={
            "userId": current_user.id,
            "role": "ADMIN"
        }
    )

    if not membership:
        raise HTTPException(
            status_code=403,
            detail="You are not an admin of any agency"
        )

    return {
        "id": current_user.id,
        "role": current_user.role,
        "agencyId": membership.agencyId,
        "membershipRole": membership.role
    }


async def get_agency_member(current_user: UserContext = Depends(get_current_user)):
    """Resolve the agency the logged-in user belongs to (admin or employee)."""
    membership = await db.agencymembership.find_first(
        where={
            "userId": current_user.id
        }
    )

    if not membership:
        raise HTTPException(
            status_code=403,
            detail="You do not belong to any agency"
        )

    return {
        "id": current_user.id,
        "role": current_user.role,
        "agencyId": membership.agencyId,
        "membershipRole": membership.role
    }
