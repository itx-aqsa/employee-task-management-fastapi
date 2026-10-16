from dataclasses import dataclass


@dataclass
class UserContext:
    id: str             # User.id from the database
    platform_role: str  # "SUPER_ADMIN" | "ADMIN" | "EMPLOYEE" — always loaded from DB


@dataclass
class AgencyContext:
    user: UserContext
    agency_id: str    # validated UUID from X-Agency-ID header
    agency_role: str  # role from AgencyMembership, or "SUPER_ADMIN" for the bypass path
