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
    update_agency,
)
from app.schemas.agency import AgencyCreate, AgencyUpdate


class AgencyApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.original_agency = db.agency

    def tearDown(self):
        db.agency = self.original_agency

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

    async def test_update_rejects_empty_body(self):
        async def find_first(*, where):
            return SimpleNamespace(id="agency-a", name="North Office")

        db.agency = SimpleNamespace(find_first=find_first)
        with self.assertRaises(HTTPException) as error:
            await update_agency(
                "agency-a", AgencyUpdate(), {"id": "root", "role": "SUPER_ADMIN"}
            )

        self.assertEqual(error.exception.status_code, 400)

    async def test_deactivate_sets_is_active_false(self):
        update_call = {}

        async def find_unique(*, where):
            return SimpleNamespace(id=where["id"])

        async def update(*, where, data):
            update_call.update(data)
            return SimpleNamespace(id=where["id"], isActive=data["isActive"])

        db.agency = SimpleNamespace(find_unique=find_unique, update=update)
        result = await deactivate_agency(
            "agency-a", {"id": "root", "role": "SUPER_ADMIN"}
        )

        self.assertEqual(update_call, {"isActive": False})
        self.assertFalse(result["data"].isActive)


if __name__ == "__main__":
    unittest.main()
