"""Audit/hardening target catalog: the registry's integrity, per-asset
version detection, and the /api/targets/catalog endpoint."""
import importlib
import re
import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.asset_icons import ICON_KEYS, suggest_icon
from app.core.database import engine
from app.core.target_catalog import ALL_DEVICE_TYPES, CATEGORIES, TARGETS, target_for_device_type, targets_for
from app.models import Asset, User, UserRole
from app.models.asset_types import AssetType
from app.models.audit import DeviceType
from app.modules.linux.hardening.service import _SUB_DEVICE_TO_DISTRO_ID
from app.utils.device_classification import infer_device_variant, normalize_device_type

targets_router = importlib.import_module("app.modules.targets.router")

# The 19 device types the Auditing/Hardening forms offered before the picker.
LEGACY_DEVICE_TYPES = {
    "cisco", "fortinet", "apache", "mongodb", "mssql-2016", "mssql-2019", "mssql-2022",
    "windows-2016", "windows-2022", "windows-2025",
    "linux-ubuntu-24", "linux-ubuntu-22", "linux-ubuntu-20",
    "linux-redhat-10", "linux-redhat-9", "linux-redhat-8",
    "linux-rocky-10", "linux-rocky-9", "linux-rocky-8",
}


class TestRegistry:
    def test_ids_unique_and_fields_valid(self):
        ids = [t.id for t in TARGETS]
        assert len(ids) == len(set(ids))
        categories = {c for c, _ in CATEGORIES}
        for t in TARGETS:
            assert t.category in categories
            assert t.icon in ICON_KEYS
            assert re.fullmatch(r"[A-Z0-9]{2}", t.monogram)
            assert bool(t.device_type) != bool(t.versions), t.id  # exactly one of the two

    def test_every_device_type_reaches_a_real_backend(self):
        families = {d.value for d in DeviceType}
        for dt in ALL_DEVICE_TYPES:
            assert normalize_device_type(dt) in families, dt

    def test_linux_variants_are_known_to_hardening(self):
        linux = {dt for dt in ALL_DEVICE_TYPES if dt.startswith("linux-")}
        assert linux == set(_SUB_DEVICE_TO_DISTRO_ID)

    def test_family_matches_device_types(self):
        for t in TARGETS:
            assert {normalize_device_type(dt) for dt in t.device_types} == {t.family}

    def test_nothing_offered_before_was_lost(self):
        # The picker replaced hard-coded lists; it must still offer every value they did.
        assert LEGACY_DEVICE_TYPES <= ALL_DEVICE_TYPES
        for mode in ("audit", "hardening"):
            offered = {dt for t in targets_for(mode) for dt in t.device_types}
            assert LEGACY_DEVICE_TYPES <= offered, mode

    def test_lookup(self):
        assert target_for_device_type("linux-rocky-9").id == "linux"
        assert target_for_device_type("cisco").id == "cisco"
        assert target_for_device_type("nope") is None
        assert targets_for("audit") and targets_for("hardening")


def _asset(type_name=None, os_name=None, os_version=None, manufacturer=None, model=None, name="a"):
    return SimpleNamespace(asset_name=name, manufacturer=manufacturer, os_name=os_name, os_version=os_version,
                           model=model, asset_type=SimpleNamespace(type_name=type_name) if type_name else None)


class TestVariant:
    @pytest.mark.parametrize("kwargs, expected", [
        (dict(os_name="Ubuntu", os_version="22.04"), "linux-ubuntu-22"),
        (dict(os_name="Ubuntu 24.04 LTS"), "linux-ubuntu-24"),
        (dict(os_name="Red Hat Enterprise Linux", os_version="9.4"), "linux-redhat-9"),
        (dict(os_name="RHEL", os_version="8.10"), "linux-redhat-8"),
        (dict(os_name="Rocky Linux", os_version="10.0"), "linux-rocky-10"),
        (dict(os_name="Ubuntu"), None),
        (dict(os_name="Windows Server 2022"), "windows-2022"),
        (dict(os_name="Windows Server", os_version="2016 Datacenter"), "windows-2016"),
        (dict(type_name="Database Server", model="SQL Server 2019", os_name="Windows Server 2022"), "mssql-2019"),
        (dict(type_name="MSSQL", os_name="Windows Server 2022"), None),  # the OS year is not the SQL year
        (dict(manufacturer="Cisco", os_name="IOS XE"), None),
    ])
    def test_detection(self, kwargs, expected):
        assert infer_device_variant(_asset(**kwargs)) == expected


class TestNewIcons:
    @pytest.mark.parametrize("name, icon", [
        ("Docker Host", "container"), ("Kubernetes Node", "cluster"), ("Active Directory", "directory"),
        ("Domain Controller", "directory"), ("Windows DNS Server", "dns"), ("DHCP Server", "dhcp"),
        ("Windows Server", "windows"),
    ])
    def test_suggestions(self, name, icon):
        assert suggest_icon(name) == icon


@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    yield session
    session.close()
    trans.rollback()
    connection.close()


@pytest.fixture
def admin(db):
    user = User(username="catalog-admin", email="catalog@example.com", hashed_password="x",
                role=UserRole.ADMIN, is_active=True)
    db.add(user)
    db.flush()
    return user


class TestApi:
    def test_counts_reflect_inventory(self, db, admin):
        before = targets_router.get_catalog(mode="audit", current_user=admin, db=db)
        t = AssetType(type_name="Catalog Test Server", category="Infrastructure")
        db.add(t)
        db.flush()
        db.add(Asset(asset_name="cat-web-01", asset_type_id=t.id, os_name="Ubuntu", os_version="22.04", user_id=admin.id))
        db.flush()
        after = targets_router.get_catalog(mode="audit", current_user=admin, db=db)
        linux = lambda c: next(x for x in c.targets if x.id == "linux")  # noqa: E731
        assert linux(after).asset_count == linux(before).asset_count + 1
        v = lambda c: next(x for x in linux(c).versions if x.device_type == "linux-ubuntu-22")  # noqa: E731
        assert v(after).asset_count == v(before).asset_count + 1
        assert [c.id for c in after.categories] == [c for c, _ in CATEGORIES if any(x.category == c for x in after.targets)]

    def test_bad_mode(self, db, admin):
        with pytest.raises(HTTPException) as exc:
            targets_router.get_catalog(mode="delete", current_user=admin, db=db)
        assert exc.value.status_code == 400

    def test_needs_the_forms_permission(self, db, admin):
        admin.role = UserRole.USER
        with pytest.raises(HTTPException) as exc:
            targets_router.get_catalog(mode="hardening", current_user=admin, db=db)
        assert exc.value.status_code == 403
