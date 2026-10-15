from fastapi import Request, HTTPException
from jose import JWTError
from app.core.security import decode_access_token
from app.database import db
from app.schemas.auth import UserContext


async def get_current_user(request: Request) -> UserContext:
    """
    Verifies the JWT cookie and returns a UserContext with the user's
    current platform role loaded from the database.

    The role is never read from the token — loading it from the DB on every
    request ensures role changes take effect immediately.
    """
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        payload = decode_access_token(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id: str | None = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token: missing subject")

    user = await db.user.find_unique(where={"id": user_id})
    if not user:
        raise HTTPException(status_code=401, detail="User account not found")

    return UserContext(id=user_id, platform_role=str(user.role))
