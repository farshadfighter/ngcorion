"""Asset icons: the resolver's order, the name suggestions, API validation
and the icon carried by the asset, topology and backup payloads."""
import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from pydantic import ValidationError

from app.core.asset_icons import ICON_KEYS, icon_badge, resolve_icon, suggest_icon
from app.modules.assets.schemas import AssetTypeCreate, AssetTypeResponse, AssetUpdate


def asset(type_name=None, type_icon=None, icon=None, role=None, os_name=None, os_version=None, vendor=None):
    asset_type = SimpleNamespace(type_name=type_name, icon=type_icon) if type_name or type_icon else None
    return SimpleNamespace(icon=icon, asset_type=asset_type, asset_role=role, os_name=os_name,
                           os_version=os_version, manufacturer=vendor)


class TestSuggestIcon:
    @pytest.mark.parametrize("name, expected", [
        ("Cisco Router", "router"),
        ("Firewall", "firewall"),
        ("FortiGate 100F", "firewall"),
        ("Switch", "switch"),
        ("Core Switch", "switch"),
        ("Access Point", "wireless"),
        ("Load Balancer", "load_balancer"),
        ("Ubuntu Linux Server", "linux"),
        ("Windows Server", "windows"),
        ("Linux Web Server", "web"),
        ("Database Server", "database"),
        ("MongoDB", "database"),
        ("Physical Server", "server"),
        ("VMware ESXi Host", "hypervisor"),
        ("NAS", "storage"),
        ("Workstation", "workstation"),
        ("IP Camera", "iot"),
        ("Internet", "internet"),
        ("Generic Asset", "other"),
        (None, "other"),
    ])
    def test_names(self, name, expected):
        assert suggest_icon(name) == expected

    def test_short_keywords_need_word_boundaries(self):
        # "asa" and "ap" must not fire inside ordinary words.
        assert suggest_icon("Nasa Lab Gear") == "other"
        assert suggest_icon("Laptop") == "workstation"


class TestResolveOrder:
    def test_override_beats_everything(self):
        assert resolve_icon(asset("Firewall", type_icon="router", icon="storage")) == "storage"
        assert resolve_icon(asset("Firewall", type_icon="router", icon="storage"), use_override=False) == "router"

    def test_type_icon_beats_keywords(self):
        assert resolve_icon(asset("Firewall", type_icon="router")) == "router"

    def test_keywords_then_os_then_vendor(self):
        assert resolve_icon(asset("Generic Asset", os_name="Ubuntu")) == "linux"
        assert resolve_icon(asset("Generic Asset", vendor="Fortinet")) == "firewall"
        assert resolve_icon(asset("Generic Asset", os_name="Ubuntu", vendor="Fortinet")) == "linux"
        assert resolve_icon(asset("Generic Asset")) == "other"

    def test_role_counts_as_a_keyword(self):
        assert resolve_icon(asset("Appliance", role="Perimeter firewall")) == "firewall"

    def test_unknown_stored_values_are_ignored(self):
        assert resolve_icon(asset("Switch", type_icon="spaceship", icon="nope")) == "switch"

    def test_every_rule_returns_a_known_key(self):
        for name in ["router", "wan", "nas", "esxi", "camera", "iis", "ad", "pc"]:
            assert suggest_icon(name) in ICON_KEYS


class TestBadge:
    def test_network_gear_shows_vendor(self):
        a = asset("Firewall", vendor="Fortinet", os_name="FortiOS", os_version="7.2.8")
        assert icon_badge(a) == "Fortinet"

    def test_hosts_show_os(self):
        a = asset("Web Server", vendor="VMware", os_name="Ubuntu", os_version="22.04")
        assert icon_badge(a) == "Ubuntu 22.04"

    def test_nothing_known(self):
        assert icon_badge(asset("Generic Asset")) is None


class TestSchemas:
    def test_unknown_icon_rejected(self):
        with pytest.raises(ValidationError):
            AssetTypeCreate(type_name="Firewall", category="Security", icon="spaceship")
        with pytest.raises(ValidationError):
            AssetUpdate(icon="<script>")

    def test_blank_means_automatic(self):
        assert AssetTypeCreate(type_name="Firewall", category="Security", icon="").icon is None
        assert AssetUpdate(icon="").icon is None

    def test_effective_icon(self):
        r = AssetTypeResponse(id=1, type_name="Ubuntu Linux Server", category="Infrastructure")
        assert r.effective_icon == "linux"
        r = AssetTypeResponse(id=1, type_name="Ubuntu Linux Server", category="Infrastructure", icon="web")
        assert r.effective_icon == "web"


# --------------------------------------------------------------------------- #
#  Database-backed: the payloads carry the resolved icon                      #
# --------------------------------------------------------------------------- #

from sqlalchemy.orm import Session  # noqa: E402

from app.core.database import engine  # noqa: E402
from app.models import Asset, DeviceBackup, User, UserRole  # noqa: E402
from app.models.asset_types import AssetType  # noqa: E402
from app.modules.assets.service import AssetService  # noqa: E402


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
def setup(db):
    user = User(username="icon-tester", email="icon@example.com", hashed_password="x",
                role=UserRole.ADMIN, is_active=True)
    db.add(user)
    db.flush()
    ftype = AssetType(type_name="Icon Test Firewall", category="Security")
    db.add(ftype)
    db.flush()
    fw = Asset(asset_name="FGT-Icon-01", asset_type_id=ftype.id, ip_address="10.9.0.1",
               manufacturer="Fortinet", os_name="FortiOS", user_id=user.id)
    db.add(fw)
    db.flush()
    return user, ftype, fw


class TestPayloads:
    def test_asset_properties(self, db, setup):
        _, ftype, fw = setup
        assert fw.resolved_icon == "firewall" and fw.icon_badge == "Fortinet"
        ftype.icon = "router"
        db.flush()
        db.refresh(fw)
        assert fw.resolved_icon == "router"

    def test_override_can_be_cleared(self, db, setup, monkeypatch):
        _, _, fw = setup
        monkeypatch.setattr(db, "commit", db.flush)
        AssetService.update_asset(db, fw.id, {"icon": "storage"})
        assert fw.resolved_icon == "storage"
        _, changes = AssetService.update_asset(db, fw.id, {"icon": None})
        assert fw.icon is None and fw.resolved_icon == "firewall"
        assert any(c["field"] == "icon" for c in changes)

    def test_topology_node_carries_icon(self, db, setup):
        user, _, fw = setup
        topology = importlib.import_module("app.modules.topology.router")
        graph = topology.get_topology(current_user=user, db=db)
        node = next(n for n in graph.nodes if n.id == fw.id)
        assert node.icon == "firewall" and node.icon_badge == "Fortinet"

    def test_backup_group_carries_icon(self, db, setup):
        user, _, fw = setup
        db.add(DeviceBackup(asset_id=fw.id, asset_name=fw.asset_name, device_ip=fw.ip_address,
                            device_type="fortinet", config_content="x", source="manual", created_by=user.id))
        db.flush()
        backup = importlib.import_module("app.modules.backup.router")
        groups = backup.list_backups_by_asset(search="FGT-Icon", device_type=None, current_user=user, db=db)
        assert groups and groups[0].icon == "firewall"
