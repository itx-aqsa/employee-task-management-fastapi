"""
Low-level cryptographic helpers: password hashing and JWT creation/decoding.

Design note — JWT is identity-only
------------------------------------
The access token encodes only the user's ID (``sub``) and expiry (``exp``).
It intentionally does NOT encode a role.

Reason: roles can change while a token is still valid.  If we baked the role
into the token, a user demoted from ADMIN would keep admin-level access until
their cookie expired (up to 60 minutes).  By looking the role up from the
database on every request we always get the current, authoritative value.

Old tokens that still carry a ``role`` claim (issued before this change) are
harmless — the claim is simply not read anywhere in the new middleware.
"""

from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
from app.core.config import JWT_SECRET

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)

# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(user_id: str) -> str:
    """
    Create a signed JWT that identifies the user.

    Only ``sub`` (user ID) and ``exp`` (expiry) are stored.
    The role is deliberately omitted — it is always fetched live from the DB.

    Backward-compat note: the old signature was create_access_token(user_id, role).
    The ``role`` parameter has been removed.  The single call-site in users.py
    has been updated to pass only ``user_id``.
    """
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": user_id,
        "exp": expire,
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Decode and verify a JWT.  Raises ``JWTError`` on any failure
    (invalid signature, expired, malformed).

    Returns the full payload dict so callers can read ``sub``.
    Extra claims in legacy tokens (e.g. ``role``) are returned but ignored
    by the middleware.
    """
    return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
