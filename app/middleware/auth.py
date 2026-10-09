from fastapi import Request, HTTPException
from jose import jwt, JWTError
from app.core.config import JWT_SECRET
from app.core.security import ALGORITHM

async def get_current_user(request: Request):
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )
    try:
        payload = jwt.decode(
            token, 
            JWT_SECRET,
            algorithms=[ALGORITHM]
        )
        user_id = payload.get("sub")
        role = payload.get("role")

        if not user_id:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )

        return {
            "id": user_id,
            "role": role
        }

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )