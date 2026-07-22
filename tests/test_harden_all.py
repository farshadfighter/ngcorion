"""
Tests for the unified Harden All layer.

These cover the normalization logic that sits between the UI contract and the
per-family hardening services — no database and no device access.
"""

import pytest

from app.models.audit import DeviceType
from app.modules.hardening.harden_all.contract import (
    HardenAllPlan,
    HardenAllRequest,
    PlanCheck,
    PlanParameter,
)
from app.modules.hardening.harden_all.families import (
    _normalize_status_rows,
    _normalize_success_rows,
    get_family,
)
from app.modules.hardening.harden_all.service import (
    _per_check_payload,
    _reattach_result_ids,
    _selected_checks,
    _validate,
)


# ============================================================
# Family registry
# ============================================================

class TestFamilyRegistry:

    @pytest.mark.parametrize("device_type", list(DeviceType))
    def test_every_device_type_is_supported(self, device_type):
        spec = get_family(device_type)
        assert spec.key == device_type.value
        assert spec.credential_fields, "every family must declare credential fields"
        assert callable(spec.execute)

    @pytest.mark.parametrize("device_type", list(DeviceType))
    def test_credential_fields_are_renderable(self, device_type):
        """The UI renders these blind, so every field needs a label and a known type."""
        for field in get_family(device_type).credential_fields:
            assert field.label
            assert field.type in ("text", "password", "number", "select")
            if field.type == "select":
                assert field.options

    @pytest.mark.parametrize("device_type", list(DeviceType))
    def test_every_family_requires_a_username_and_password(self, device_type):
        required = [f.name for f in get_family(device_type).credential_fields if f.required]
        assert any("username" in n for n in required)
        assert any("password" in n for n in required)

    def test_unknown_device_type_is_rejected(self):
        with pytest.raises(ValueError, match="does not support"):
            get_family("solaris")


# ============================================================
# Result normalization
# ============================================================

class TestNormalization:

    def test_status_dialect(self):
        """Cisco/FortiGate report an explicit status string."""
        rows = _normalize_status_rows({"results": [
            {"check_number": "IOS-L1-001", "status": "success"},
            {"check_number": "IOS-L1-002", "status": "failed", "error": "rejected"},
            {"check_number": "IOS-L1-003", "status": "skipped", "reason": "Already passing"},
        ]})
        assert [r["status"] for r in rows] == ["success", "failed", "skipped"]
        assert rows[1]["detail"] == "rejected"
        assert rows[2]["detail"] == "Already passing"

    def test_success_dialect(self):
        """Linux/Apache/MongoDB/MSSQL/Windows report a boolean."""
        rows = _normalize_success_rows({"results": [
            {"check_id": "LNX-L1-1", "success": True, "verification_result": "ok"},
            {"check_id": "LNX-L1-2", "success": False, "error_message": "sudo failed"},
        ]})
        assert [r["status"] for r in rows] == ["success", "failed"]
        assert rows[0]["detail"] == "ok"
        assert rows[1]["detail"] == "sudo failed"

    def test_unknown_status_falls_back_to_failed(self):
        """An unrecognized status must never be optimistically read as success."""
        rows = _normalize_status_rows({"results": [{"check_number": "X", "status": "weird"}]})
        assert rows[0]["status"] == "failed"

    def test_dry_run_rows_are_not_reported_as_applied(self):
        rows = _normalize_success_rows({"dry_run": True, "results": [
            {"check_id": "LNX-L1-1", "commands": ["sysctl -w a=1"]},
            {"check_id": "LNX-L1-2", "error_message": "no template"},
        ]})
        assert rows[0]["commands"] == ["sysctl -w a=1"]
        assert rows[1]["status"] == "skipped"

    def test_legacy_skipped_list_is_carried_over(self):
        rows = _normalize_success_rows({"results": [], "skipped": ["LNX-L1-9"]})
        assert rows == [{
            "check_number": "LNX-L1-9", "check_title": None, "vdom": None,
            "status": "skipped", "detail": "Not auto-fixable", "commands": [],
        }]


# ============================================================
# Result-id reattachment
# ============================================================

class TestReattachResultIds:

    def test_multi_vdom_rows_map_to_their_own_result(self):
        """The same check number in two VDOMs is two findings, not one."""
        selected = [
            PlanCheck(result_id=1, check_number="FG-BL-002", vdom="root"),
            PlanCheck(result_id=2, check_number="FG-BL-002", vdom="vd1"),
        ]
        rows = _normalize_status_rows({"results": [
            {"check_number": "FG-BL-002", "status": "success", "vdom": "vd1"},
            {"check_number": "FG-BL-002", "status": "failed", "vdom": "root"},
        ]})
        outcomes = {o.result_id: o.status for o in _reattach_result_ids(rows, selected)}
        assert outcomes == {2: "success", 1: "failed"}

    def test_rows_without_a_vdom_still_match_by_check_number(self):
        selected = [PlanCheck(result_id=7, check_number="LNX-L1-1")]
        rows = _normalize_success_rows({"results": [{"check_id": "LNX-L1-1", "success": True}]})
        outcome = _reattach_result_ids(rows, selected)[0]
        assert outcome.result_id == 7

    def test_unmatched_row_is_kept_without_a_result_id(self):
        """A check the family reports but the plan never selected is still shown."""
        rows = _normalize_status_rows({"results": [{"check_number": "SURPRISE", "status": "success"}]})
        outcome = _reattach_result_ids(rows, [])[0]
        assert outcome.result_id is None
        assert outcome.check_number == "SURPRISE"


# ============================================================
# Parameter routing
# ============================================================

class TestPerCheckPayload:

    def test_each_check_gets_only_its_own_parameters(self):
        selected = [
            PlanCheck(result_id=1, check_number="A", parameters=["BANNER"]),
            PlanCheck(result_id=2, check_number="B", parameters=["TIMEOUT"]),
        ]
        payload = _per_check_payload(selected, {"BANNER": "hi", "TIMEOUT": "5"})
        assert payload == [
            {"check_id": "A", "parameters": {"BANNER": "hi"}},
            {"check_id": "B", "parameters": {"TIMEOUT": "5"}},
        ]

    def test_blank_values_are_dropped_so_template_defaults_win(self):
        selected = [PlanCheck(result_id=1, check_number="A", parameters=["TIMEOUT"])]
        assert _per_check_payload(selected, {"TIMEOUT": "   "}) == [
            {"check_id": "A", "parameters": {}}
        ]

    def test_values_are_trimmed(self):
        selected = [PlanCheck(result_id=1, check_number="A", parameters=["TIMEOUT"])]
        assert _per_check_payload(selected, {"TIMEOUT": " 5 "})[0]["parameters"] == {"TIMEOUT": "5"}

    def test_multi_vdom_check_is_sent_once(self):
        """Families that execute by check number must not receive duplicates."""
        selected = [
            PlanCheck(result_id=1, check_number="A", vdom="root"),
            PlanCheck(result_id=2, check_number="A", vdom="vd1"),
        ]
        assert len(_per_check_payload(selected, {})) == 1


# ============================================================
# Validation and selection
# ============================================================

def _plan(**overrides):
    base = dict(
        session_id=1, device_family="cisco", device_label="Cisco",
        fixable=[PlanCheck(result_id=10, check_number="A")],
        parameters=[],
        credential_fields=get_family(DeviceType.CISCO).credential_fields,
    )
    base.update(overrides)
    return HardenAllPlan(**base)


class TestValidation:

    def test_missing_credentials_are_reported_by_label(self):
        plan = _plan()
        request = HardenAllRequest(session_id=1, credentials={"ssh_username": "u"})
        with pytest.raises(ValueError, match="SSH Password"):
            _validate(plan, request)

    def test_blank_credential_counts_as_missing(self):
        plan = _plan()
        request = HardenAllRequest(session_id=1, credentials={"ssh_username": " ", "ssh_password": "p"})
        with pytest.raises(ValueError, match="SSH Username"):
            _validate(plan, request)

    def test_missing_required_parameter_is_reported(self):
        plan = _plan(parameters=[PlanParameter(name="SECRET", label="Enable Secret", required=True)])
        request = HardenAllRequest(session_id=1, credentials={"ssh_username": "u", "ssh_password": "p"})
        with pytest.raises(ValueError, match="Enable Secret"):
            _validate(plan, request)

    def test_optional_parameter_may_be_omitted(self):
        plan = _plan(parameters=[PlanParameter(name="TIMEOUT", label="Timeout", default="10")])
        request = HardenAllRequest(session_id=1, credentials={"ssh_username": "u", "ssh_password": "p"})
        _validate(plan, request)  # must not raise


class TestSelection:

    def test_omitting_result_ids_selects_everything_fixable(self):
        plan = _plan()
        assert [c.result_id for c in _selected_checks(plan, HardenAllRequest(session_id=1))] == [10]

    def test_unfixable_result_id_is_rejected(self):
        """Silently dropping an unknown id would report a fix that never ran."""
        plan = _plan()
        request = HardenAllRequest(session_id=1, result_ids=[10, 999])
        with pytest.raises(ValueError, match="999"):
            _selected_checks(plan, request)


# ============================================================
# Pre-hardening backup
# ============================================================

from app.modules.shared.hardening_backup import (  # noqa: E402
    build_file_bundle_command,
    save_device_backup,
)


class TestBackupCapability:

    @pytest.mark.parametrize("device_type", list(DeviceType))
    def test_every_family_supports_backup(self, device_type):
        """The wizard's backup toggle is gated on this flag — every family that
        can be hardened must be able to snapshot first."""
        assert get_family(device_type).capabilities.backup is True

    @pytest.mark.parametrize("device_type", list(DeviceType))
    def test_create_backup_reaches_the_family_service(self, device_type, monkeypatch):
        """The family adapter must thread create_backup down to whichever service
        it calls — a dropped flag means a silently skipped backup. Cisco/FortiGate
        express it as the inverse ``skip_backup``; everyone else as ``create_backup``."""
        from app.modules.hardening.harden_all.families import ExecutionContext, get_family
        from app.modules.cisco.hardening.service import HardeningService as CiscoService
        from app.modules.fortinet.hardening.service import FortiGateHardeningService
        from app.modules.linux.hardening.service import LinuxHardeningService
        from app.modules.apache.hardening.service import ApacheHardeningService
        from app.modules.mongodb.hardening.service import MongoDBHardeningService
        from app.modules.mssql.hardening.service import MSSQLHardeningService
        from app.modules.windows.hardening.service import WindowsHardeningService

        captured = {}

        def _fake_service(**kwargs):
            captured.update(kwargs)
            return {"total": 0, "successful": 0, "failed": 0, "results": []}

        for svc in (
            CiscoService, FortiGateHardeningService, LinuxHardeningService,
            ApacheHardeningService, MongoDBHardeningService,
            MSSQLHardeningService, WindowsHardeningService,
        ):
            monkeypatch.setattr(svc, "batch_execute_selected", staticmethod(_fake_service))

        class _Asset:
            id = 7
            ip_address = "10.0.0.9"
            asset_name = "unit-test"

        ctx = ExecutionContext(
            db=None, session=type("S", (), {"id": 1})(), asset=_Asset(),
            user_id=42, credentials={}, result_ids=[1], parameters={}, checks=[],
            create_backup=True, dry_run=False,
        )
        get_family(device_type).execute(ctx)
        assert captured.get("skip_backup") is False or captured.get("create_backup") is True


class TestBackupHelper:

    def test_bundle_command_skips_missing_files(self):
        cmd = build_file_bundle_command(["/etc/ssh/sshd_config", "/etc/sysctl.d/*.conf"])
        assert '[ -f "$f" ]' in cmd
        assert "/etc/ssh/sshd_config" in cmd
        assert "/etc/sysctl.d/*.conf" in cmd

    def test_empty_backup_is_not_saved(self):
        # No DB touched: an empty snapshot short-circuits before any query.
        assert save_device_backup(
            None, backup="", device_ip="1.2.3.4", device_type="linux",
            user_id=1, asset_id=5,
        ) is None

    def test_backup_without_asset_is_not_saved(self):
        # device_backups.asset_id is NOT NULL, so an asset-less run cannot record.
        assert save_device_backup(
            None, backup="some config", device_ip="1.2.3.4", device_type="linux",
            user_id=1, asset_id=None,
        ) is None
