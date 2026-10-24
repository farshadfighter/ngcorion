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
        ("PC", "workstation"),
        ("Printer", "printer"),
        ("Network Printer", "printer"),
        ("MFP", "printer"),
        ("Copier", "printer"),
        ("IP Camera", "camera"),
        ("CCTV", "camera"),
        ("NVR", "nvr"),
        ("Video Recorder", "nvr"),
        ("Laptop", "laptop"),
        ("IP Phone", "ip_phone"),
        ("VoIP Phone", "ip_phone"),
        ("UPS", "ups"),
        ("PLC", "plc"),
        ("SCADA HMI", "plc"),
        ("IoT Sensor", "iot"),
        ("WAF", "waf"),
        ("Web Application Firewall", "waf"),
        ("FortiWeb", "waf"),
        ("IPS", "ips"),
        ("Intrusion Prevention", "ips"),
        ("VPN Gateway", "vpn"),
        ("Industrial Switch", "switch"),
        ("Domain Controller", "directory"),
        ("Internet", "internet"),
        ("Generic Asset", "other"),
        (None, "other"),
    ])
    def test_names(self, name, expected):
        assert suggest_icon(name) == expected

    def test_short_keywords_need_word_boundaries(self):
        # "asa" and "ap" must not fire inside ordinary words.
        assert suggest_icon("Nasa Lab Gear") == "other"
        assert suggest_icon("Backups") == "other"      # not "ups"
        assert suggest_icon("Laptop") == "laptop"


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

    def test_device_makers(self):
        assert resolve_icon(asset("Generic Asset", vendor="Hangzhou Hikvision Digital Technology")) == "camera"
        assert resolve_icon(asset("Generic Asset", vendor="Yealink(Xiamen) Network Technology")) == "ip_phone"
        assert resolve_icon(asset("Generic Asset", vendor="American Power Conversion")) == "ups"
        assert resolve_icon(asset("Generic Asset", vendor="Rockwell Automation")) == "plc"

    def test_the_zone_is_not_a_keyword(self):
        """asset_role holds the asset's network zone: a server in "Internet / Public" is a server."""
        assert resolve_icon(asset("Server", role="Internet / Public")) == "server"
        assert resolve_icon(asset("Appliance", role="Perimeter firewall")) == "other"

    def test_unknown_stored_values_are_ignored(self):
        assert resolve_icon(asset("Switch", type_icon="spaceship", icon="nope")) == "switch"

    def test_every_rule_returns_a_known_key(self):
        for name in ["router", "wan", "nas", "esxi", "camera", "iis", "ad", "pc", "ups", "waf", "nvr"]:
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


def test_asset_whose_owner_was_deleted_still_lists():
    # asset_inventory.user_id is ON DELETE SET NULL: deleting the user who owned an asset leaves it
    # ownerless, and the asset list must still answer instead of failing validation for everyone.
    from datetime import datetime

    from app.modules.assets.schemas import AssetResponse
    now = datetime(2026, 10, 11)
    row = AssetResponse.model_validate({"id": 7, "asset_name": "srv-007", "asset_type_id": 1, "user_id": None,
                                        "created_at": now, "updated_at": now})
    assert row.user_id is None


def test_printer_vendor_and_badge():
    # A printer whose type says nothing is known by its maker; HP is not taken as a printer.
    assert resolve_icon(asset("Device", vendor="Kyocera")) == "printer"
    assert resolve_icon(asset("Device", vendor="HP")) == "other"
    assert icon_badge(asset("Printer", vendor="Kyocera", os_name="Embedded")) == "Kyocera"


class TestFrontendMirror:
    """front/src/components/shared/assetIcons.js draws the keys this resolver returns and repeats its
    name rules; a key missing there would draw as "other"."""
    JS = (PROJECT_ROOT / "front/src/components/shared/assetIcons.js").read_text(encoding="utf-8")

    def test_same_icon_keys(self):
        import re
        block = self.JS[self.JS.index("export const ASSET_ICONS"):self.JS.index("export const ICON_KEYS")]
        js_keys = re.findall(r"^    (\w+): \{", block, re.M)
        assert js_keys and set(js_keys) == set(ICON_KEYS)

    def test_same_name_rules(self):
        import re
        from app.core.asset_icons import _NAME_RULES
        block = self.JS[self.JS.index("const NAME_RULES"):]
        js_rules = re.findall(r'\[/(.+?)/i, "(\w+)"\]', block)
        assert [(p.pattern, key) for p, key in _NAME_RULES] == [(p.replace("\\\\", "\\"), k) for p, k in js_rules]
