from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
from app.core.config import JWT_SECRET

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def create_access_token(user_id: str) -> str:
    # Role is intentionally excluded — it is always fetched live from the DB
    # so a role change takes effect immediately without waiting for token expiry.
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": user_id, "exp": expire}, JWT_SECRET, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    # Raises JWTError on invalid signature, expiry, or malformed input.
    # Legacy tokens that carry a "role" claim decode fine; the claim is ignored.
    return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
