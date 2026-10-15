from dataclasses import dataclass


@dataclass
class UserContext:
    """Authenticated caller. Platform role is always loaded from the DB, never from the token."""
    id: str            # User.id (UUID)
    platform_role: str  # "SUPER_ADMIN" | "ADMIN" | "EMPLOYEE"


@dataclass
class AgencyContext:
    """Caller acting within a specific agency. Produced by require_agency_role()."""
    user: UserContext
    agency_id: str    # validated UUID from X-Agency-ID header
    agency_role: str  # role from AgencyMembership, or "SUPER_ADMIN" for platform admins
