import unittest
from types import SimpleNamespace

from fastapi import HTTPException
from pydantic import ValidationError

from app.database import db
from app.routers.agency import (
    create_agency,
    deactivate_agency,
    get_agencies,
    get_agency,
    assign_admin_to_agency,
    update_agency,
)
from app.schemas.agency import AgencyAssignAdmin, AgencyCreate, AgencyUpdate


class AgencyApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.original_agency = db.agency
        self.original_user = db.user
        self.original_membership = db.agencymembership

    def tearDown(self):
        db.agency = self.original_agency
        db.user = self.original_user
        db.agencymembership = self.original_membership

    async def test_create_agency_saves_validated_values(self):
        created = {}

        async def find_first(*, where):
            return None

        async def create(*, data):
            created.update(data)
            return SimpleNamespace(
                id="agency-a", name=data["name"], description=data["description"],
                isDefault=data["isDefault"], createdAt="now", updatedAt="now",
            )

        db.agency = SimpleNamespace(find_first=find_first, create=create)
        result = await create_agency(
            AgencyCreate(name="  North Office  ", description="Main office"),
            {"id": "root", "role": "SUPER_ADMIN"},
        )

        self.assertEqual(created["name"], "North Office")
        self.assertTrue(result["status"])

    async def test_create_rejects_blank_agency_name(self):
        with self.assertRaises(ValidationError):
            AgencyCreate(name="   ")

    async def test_create_rejects_duplicate_name(self):
        async def find_first(*, where):
            return SimpleNamespace(id="existing")

        db.agency = SimpleNamespace(find_first=find_first)
        with self.assertRaises(HTTPException) as error:
            await create_agency(
                AgencyCreate(name="North Office"),
                {"id": "root", "role": "SUPER_ADMIN"},
            )

        self.assertEqual(error.exception.status_code, 400)

    async def test_list_agencies_orders_by_created_date(self):
        seen = {}

        async def find_many(**kwargs):
            seen.update(kwargs)
            return []

        db.agency = SimpleNamespace(find_many=find_many)
        result = await get_agencies({"id": "root", "role": "SUPER_ADMIN"})

        self.assertEqual(seen["order"], [{"createdAt": "desc"}])
        self.assertEqual(result["data"], [])

    async def test_agency_details_returns_404_when_missing(self):
        async def find_unique(*, where):
            return None

        db.agency = SimpleNamespace(find_unique=find_unique)
        with self.assertRaises(HTTPException) as error:
            await get_agency("missing", {"id": "root", "role": "SUPER_ADMIN"})

        self.assertEqual(error.exception.status_code, 404)

    async def test_agency_details_returns_existing_agency(self):
        expected = SimpleNamespace(id="agency-a", name="North Office")

        async def find_unique(*, where):
            return expected

        db.agency = SimpleNamespace(find_unique=find_unique)
        result = await get_agency("agency-a", {"id": "root", "role": "SUPER_ADMIN"})

        self.assertIs(result["data"], expected)

    async def test_update_changes_provided_fields(self):
        update_call = {}

        async def find_first(*, where):
            if "name" in where:
                return None
            return SimpleNamespace(id="agency-a", name="North Office")

        async def update(*, where, data):
            update_call.update(data)
            return SimpleNamespace(id=where["id"], **data)

        db.agency = SimpleNamespace(find_first=find_first, update=update)
        result = await update_agency(
            "agency-a", AgencyUpdate(name="East Office"),
            {"id": "root", "role": "SUPER_ADMIN"},
        )

        self.assertEqual(update_call, {"name": "East Office"})
        self.assertEqual(result["data"].name, "East Office")

    async def test_update_can_clear_description(self):
        update_call = {}

        async def find_first(*, where):
            return SimpleNamespace(id="agency-a", name="North Office")

        async def update(*, where, data):
            update_call.update(data)
            return SimpleNamespace(id=where["id"], name="North Office", **data)

        db.agency = SimpleNamespace(find_first=find_first, update=update)
        await update_agency(
            "agency-a", AgencyUpdate(description=None),
            {"id": "root", "role": "SUPER_ADMIN"},
        )

        self.assertEqual(update_call, {"description": None})

    async def test_update_rejects_empty_body(self):
        async def find_first(*, where):
            return SimpleNamespace(id="agency-a", name="North Office")

        db.agency = SimpleNamespace(find_first=find_first)
        with self.assertRaises(HTTPException) as error:
            await update_agency(
                "agency-a", AgencyUpdate(), {"id": "root", "role": "SUPER_ADMIN"}
            )

        self.assertEqual(error.exception.status_code, 400)

    async def test_deactivate_reports_unsupported_schema_operation(self):
        with self.assertRaises(HTTPException) as error:
            await deactivate_agency("agency-a", {"id": "root", "role": "SUPER_ADMIN"})

        self.assertEqual(error.exception.status_code, 501)

    async def test_admin_assignment_uses_role_defined_by_schema(self):
        create_call = {}
        user_id = "11111111-1111-4111-8111-111111111111"

        async def find_agency(*, where):
            return SimpleNamespace(id=where["id"])

        async def find_user(*, where):
            return SimpleNamespace(id=where["id"], role="EMPLOYEE")

        async def find_membership(*, where):
            return None

        async def create_membership(*, data):
            create_call.update(data)
            return SimpleNamespace(**data)

        db.agency = SimpleNamespace(find_unique=find_agency)
        db.user = SimpleNamespace(find_unique=find_user)
        db.agencymembership = SimpleNamespace(
            find_unique=find_membership, create=create_membership
        )

        await assign_admin_to_agency(
            "agency-a", AgencyAssignAdmin(userId=user_id),
            {"id": "root", "role": "SUPER_ADMIN"},
        )

        self.assertEqual(create_call["userId"], user_id)
        self.assertEqual(create_call["role"], "ADMIN")

    async def test_admin_assignment_rejects_malformed_user_id(self):
        with self.assertRaises(ValidationError):
            AgencyAssignAdmin(userId="not-a-uuid")


if __name__ == "__main__":
    unittest.main()
