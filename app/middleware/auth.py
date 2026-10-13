"""
Authentication middleware — answers the question "Who is this caller?"

Authentication vs. Authorization
---------------------------------
*Authentication* means proving your identity — "I am user X".
*Authorization* means checking what you are allowed to do — "user X may do Y".

This file handles *authentication only*.  It reads the JWT cookie, verifies
the signature, extracts the user ID, then loads that user's current platform
role from the database.

Why load the role from the DB instead of trusting the token?
------------------------------------------------------------
The JWT cookie can be valid for up to 60 minutes.  If an admin is demoted
during that window, a role stored inside the token would give them continued
access.  By re-reading the role from the database on every request we always
use the current, authoritative value.  The cost is one extra DB query per
request — acceptable and correct.

Cookie + Header together
-------------------------
The cookie carries the JWT (proves identity).
The ``X-Agency-ID`` header (handled in role.py) says which agency to act on.
They work independently: every request needs the cookie; only requests that
touch agency-scoped resources also need the header.
"""
from fastapi import Request, HTTPException
from jose import JWTError
from app.core.security import decode_access_token
from app.database import db
from app.schemas.auth import UserContext


async def get_current_user(request: Request) -> UserContext:
    """
    FastAPI dependency.  Reads the ``token`` cookie, decodes the JWT,
    then fetches the live User record to get the current platform role.

    Returns a ``UserContext`` dataclass.  Raises HTTP 401 on any failure.
    """
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    # --- 1. Verify JWT signature and expiry ---------------------------------
    try:
        payload = decode_access_token(token)
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    user_id: str | None = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid token: missing subject"
        )

    # --- 2. Load the user's current platform role from the database ---------
    # We do NOT trust any ``role`` claim that may exist in a legacy token.
    user = await db.user.find_unique(where={"id": user_id})
    if not user:
        # The account was deleted after the token was issued.
        raise HTTPException(
            status_code=401,
            detail="User account not found"
        )

    return UserContext(
        id=user_id,
        platform_role=str(user.role)
    )
