from fastapi import Depends, HTTPException
from app.middleware.auth import get_current_user

def require_role(require_role: str):
    async def role_checker(
        current_user = Depends(get_current_user)
    ):
        if current_user["role"] != require_role:
            raise HTTPException(
                status_code=403,
                detail="Access denied"
            )

        return current_user
    return role_checker