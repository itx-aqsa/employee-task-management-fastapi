from dataclasses import dataclass


@dataclass
class UserContext:
    id: str           # User.id from the database
    role: str         # "SUPER_ADMIN" | "ADMIN" | "EMPLOYEE" — always loaded from DB
