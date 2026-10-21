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
from app.schemas.agency import AgencyAdminCreate, AgencyCreate, AgencyUpdate


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
                isDefault=data["isDefault"], isActive=data["isActive"],
                createdAt="now", updatedAt="now",
            )

        db.agency = SimpleNamespace(find_first=find_first, create=create)
        result = await create_agency(
            AgencyCreate(name="  North Office  ", description="Main office"),
            {"id": "root", "role": "SUPER_ADMIN"},
        )

        self.assertEqual(created["name"], "North Office")
        self.assertTrue(created["isActive"])
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

    async def test_update_can_set_is_active(self):
        update_call = {}

        async def find_first(*, where):
            return SimpleNamespace(id="agency-a", name="North Office")

        async def update(*, where, data):
            update_call.update(data)
            return SimpleNamespace(id=where["id"], name="North Office", **data)

        db.agency = SimpleNamespace(find_first=find_first, update=update)
        await update_agency(
            "agency-a", AgencyUpdate(isActive=False),
            {"id": "root", "role": "SUPER_ADMIN"},
        )

        self.assertFalse(update_call["isActive"])

    async def test_deactivate_sets_is_active_false(self):
        """DELETE should soft-delete by setting isActive=False."""
        updated_data = {}

        async def find_unique(*, where):
            return SimpleNamespace(id=where["id"], isActive=True)

        async def update(*, where, data):
            updated_data.update(data)
            return SimpleNamespace(id=where["id"], isActive=data["isActive"])

        db.agency = SimpleNamespace(find_unique=find_unique, update=update)
        result = await deactivate_agency("agency-a", {"id": "root", "role": "SUPER_ADMIN"})

        self.assertFalse(updated_data["isActive"])
        self.assertTrue(result["status"])

    async def test_deactivate_returns_404_for_missing_agency(self):
        async def find_unique(*, where):
            return None

        db.agency = SimpleNamespace(find_unique=find_unique)
        with self.assertRaises(HTTPException) as error:
            await deactivate_agency("missing", {"id": "root", "role": "SUPER_ADMIN"})

        self.assertEqual(error.exception.status_code, 404)

    async def test_deactivate_returns_400_when_already_inactive(self):
        async def find_unique(*, where):
            return SimpleNamespace(id=where["id"], isActive=False)

        db.agency = SimpleNamespace(find_unique=find_unique)
        with self.assertRaises(HTTPException) as error:
            await deactivate_agency("agency-a", {"id": "root", "role": "SUPER_ADMIN"})

        self.assertEqual(error.exception.status_code, 400)

    async def test_admin_assignment_creates_user_and_membership(self):
        """Happy path: new user is created with ADMIN role and linked to the agency."""
        created_user = {}
        created_membership = {}
        new_user_id = "22222222-2222-4222-8222-222222222222"

        async def find_agency(*, where):
            return SimpleNamespace(id=where["id"])

        async def find_user_by_email(*, where):
            return None  # no duplicate — email is free

        async def create_user(*, data):
            created_user.update(data)
            return SimpleNamespace(
                id=new_user_id,
                name=data["name"],
                email=data["email"],
                role=data["role"],
            )

        async def create_membership(*, data):
            created_membership.update(data)
            return SimpleNamespace(
                id="mem-1",
                userId=data["userId"],
                agencyId=data["agencyId"],
                role=data["role"],
            )

        db.agency = SimpleNamespace(find_unique=find_agency)
        db.user = SimpleNamespace(find_unique=find_user_by_email, create=create_user)
        db.agencymembership = SimpleNamespace(create=create_membership)

        result = await assign_admin_to_agency(
            "agency-a",
            AgencyAdminCreate(name="Alice", email="alice@example.com", password="secret123"),
            {"id": "root", "role": "SUPER_ADMIN"},
        )

        # User was created with ADMIN platform role and hashed password
        self.assertEqual(created_user["name"], "Alice")
        self.assertEqual(created_user["email"], "alice@example.com")
        self.assertEqual(created_user["role"], "ADMIN")
        self.assertNotEqual(created_user["password"], "secret123")  # must be hashed

        # Membership links the new user to the agency as ADMIN
        self.assertEqual(created_membership["userId"], new_user_id)
        self.assertEqual(created_membership["role"], "ADMIN")

        self.assertTrue(result["status"])
        self.assertEqual(result["data"]["user"]["id"], new_user_id)
        self.assertEqual(result["data"]["membership"]["role"], "ADMIN")

    async def test_admin_assignment_rejects_duplicate_email(self):
        """400 when the provided email is already taken."""

        async def find_agency(*, where):
            return SimpleNamespace(id=where["id"])

        async def find_user_by_email(*, where):
            return SimpleNamespace(id="existing-user", email=where["email"])

        db.agency = SimpleNamespace(find_unique=find_agency)
        db.user = SimpleNamespace(find_unique=find_user_by_email)

        with self.assertRaises(HTTPException) as error:
            await assign_admin_to_agency(
                "agency-a",
                AgencyAdminCreate(name="Bob", email="taken@example.com", password="pw"),
                {"id": "root", "role": "SUPER_ADMIN"},
            )

        self.assertEqual(error.exception.status_code, 400)

    async def test_admin_assignment_rejects_missing_agency(self):
        """404 when the agency does not exist."""

        async def find_agency(*, where):
            return None

        db.agency = SimpleNamespace(find_unique=find_agency)

        with self.assertRaises(HTTPException) as error:
            await assign_admin_to_agency(
                "agency-a",
                AgencyAdminCreate(name="Carol", email="carol@example.com", password="pw"),
                {"id": "root", "role": "SUPER_ADMIN"},
            )

        self.assertEqual(error.exception.status_code, 404)

    async def test_admin_assignment_rejects_invalid_email(self):
        """ValidationError when the email field is not a valid email address."""
        with self.assertRaises(ValidationError):
            AgencyAdminCreate(name="Dave", email="not-an-email", password="pw")


if __name__ == "__main__":
    unittest.main()
