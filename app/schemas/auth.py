"""
Shared context objects carried through the auth middleware stack.

UserContext   – produced by get_current_user after JWT + DB lookup.
AgencyContext – produced by require_agency_role after membership check.

Using dataclasses (not plain dicts) gives us type-safety and makes
it easy to add fields later without hunting down every dict key.
"""

from dataclasses import dataclass


@dataclass
class UserContext:
    """
    Who is the caller?

    Populated from the JWT cookie (identity) and a live DB look-up
    (platform_role).  Never trusts a role value embedded in the token.
    """
    id: str             # UUID string, matches User.id in the database
    platform_role: str  # "SUPER_ADMIN" | "ADMIN" | "EMPLOYEE"  — from DB


@dataclass
class AgencyContext:
    """
    Which agency is the caller acting on behalf of, and what is their
    role inside that agency?

    Populated only when require_agency_role() is used.
    """
    user: UserContext
    agency_id: str    # validated UUID from X-Agency-ID header
    agency_role: str  # "ADMIN" | "EMPLOYEE" | "SUPER_ADMIN"  — from DB or bypass
