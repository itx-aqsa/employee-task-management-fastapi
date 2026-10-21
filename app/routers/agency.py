from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from prisma.enums import Role
from app.database import db
from app.schemas.agency import (
    AgencyCreate, AgencyUpdate, AgencyAdminCreate,
)
from app.core.security import hash_password
from app.middleware.role import require_role

router = APIRouter(
    prefix="/agencies",
    tags=["Agencies"]
)


# Register both "" and "/" to accept /agencies and /agencies/ without a redirect.

@router.post("/")
@router.post("")
async def create_agency(
    agency: AgencyCreate,
    current_user=Depends(require_role("SUPER_ADMIN"))
):
    existing_agency = await db.agency.find_first(
        where={
            "name": agency.name
        }
    )

    if existing_agency:
        raise HTTPException(
            status_code=400,
            detail="Agency with this name already exists"
        )

    new_agency = await db.agency.create(
        data={
            "name": agency.name,
            "description": agency.description,
            "isDefault": agency.isDefault,
            "isActive": agency.isActive,
        }
    )

    return {
        "status": True,
        "message": "Agency created successfully",
        "data": {
            "id": new_agency.id,
            "name": new_agency.name,
            "description": new_agency.description,
            "isDefault": new_agency.isDefault,
            "isActive": new_agency.isActive,
            "createdAt": new_agency.createdAt,
            "updatedAt": new_agency.updatedAt,
        },
    }


@router.get("/")
@router.get("")
async def get_agencies(
    current_user=Depends(require_role("SUPER_ADMIN"))
):
    agencies = await db.agency.find_many(
        order=[
            {
                "createdAt": "desc"
            }
        ]
    )

    return {
        "status": True,
        "data": agencies
    }


@router.get("/{agency_id}")
async def get_agency(
    agency_id: UUID,
    current_user=Depends(require_role("SUPER_ADMIN"))
):
    agency = await db.agency.find_unique(
        where={
            "id": str(agency_id)
        }
    )

    if not agency:
        raise HTTPException(
            status_code=404,
            detail="Agency not found"
        )

    return {
        "status": True,
        "data": agency
    }


@router.put("/{agency_id}")
async def update_agency(
    agency_id: UUID,
    agency_data: AgencyUpdate,
    current_user=Depends(require_role("SUPER_ADMIN"))
):
    existing_agency = await db.agency.find_first(
        where={
            "id": str(agency_id)
        }
    )

    if not existing_agency:
        raise HTTPException(
            status_code=404,
            detail="Agency not found"
        )

    update_data = {}

    if "name" in agency_data.model_fields_set and agency_data.name is not None:
        if agency_data.name != existing_agency.name:
            name_exists = await db.agency.find_first(
                where={
                    "name": agency_data.name
                }
            )

            if name_exists:
                raise HTTPException(
                    status_code=400,
                    detail="Agency with this name already exists"
                )

        update_data["name"] = agency_data.name

    if "description" in agency_data.model_fields_set:
        update_data["description"] = agency_data.description

    if "isDefault" in agency_data.model_fields_set and agency_data.isDefault is not None:
        update_data["isDefault"] = agency_data.isDefault

    if "isActive" in agency_data.model_fields_set and agency_data.isActive is not None:
        update_data["isActive"] = agency_data.isActive

    if not update_data:
        raise HTTPException(status_code=400, detail="At least one agency field must be provided")

    updated_agency = await db.agency.update(
        where={
            "id": str(agency_id)
        },
        data=update_data
    )

    return {
        "status": True,
        "message": "Agency updated successfully",
        "data": updated_agency
    }


@router.delete("/{agency_id}")
async def deactivate_agency(
    agency_id: UUID,
    current_user=Depends(require_role("SUPER_ADMIN"))
):
    """Soft-delete: sets isActive=False rather than dropping the record."""
    existing = await db.agency.find_unique(where={"id": str(agency_id)})
    if not existing:
        raise HTTPException(status_code=404, detail="Agency not found")

    if not existing.isActive:
        raise HTTPException(status_code=400, detail="Agency is already inactive")

    updated = await db.agency.update(
        where={"id": str(agency_id)},
        data={"isActive": False},
    )
    return {"status": True, "message": "Agency deactivated successfully", "data": updated}


@router.post("/{agency_id}/admins")
async def assign_admin_to_agency(
    agency_id: UUID,
    payload: AgencyAdminCreate,
    current_user=Depends(require_role("SUPER_ADMIN"))
):
    # 1. Verify the target agency exists.
    agency = await db.agency.find_unique(where={"id": str(agency_id)})
    if not agency:
        raise HTTPException(status_code=404, detail="Agency not found")

    # 2. Guard against duplicate email.
    existing_user = await db.user.find_unique(where={"email": payload.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="A user with this email already exists")

    # 3. Create the new user with platform role ADMIN.
    new_user = await db.user.create(
        data={
            "name": payload.name,
            "email": payload.email,
            "password": hash_password(payload.password),
            "role": Role.ADMIN,
        }
    )

    # 4. Create the AgencyMembership linking the new user to the agency as ADMIN.
    membership = await db.agencymembership.create(
        data={
            "userId": new_user.id,
            "agencyId": str(agency_id),
            "role": Role.ADMIN,
        }
    )

    return {
        "status": True,
        "message": "Admin created and assigned to agency successfully",
        "data": {
            "user": {
                "id": new_user.id,
                "name": new_user.name,
                "email": new_user.email,
                "role": str(new_user.role),
            },
            "membership": {
                "id": membership.id,
                "userId": membership.userId,
                "agencyId": membership.agencyId,
                "role": str(membership.role),
            },
        },
    }


