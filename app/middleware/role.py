from fastapi import Depends, HTTPException
from app.middleware.auth import get_current_user
from app.schemas.auth import UserContext


def require_role(required_role: str):
    async def role_checker(
        current_user: UserContext = Depends(get_current_user)
    ) -> UserContext:
        if current_user.role != required_role:
            raise HTTPException(
                status_code=403,
                detail="Access denied"
            )

        return current_user
    return role_checker