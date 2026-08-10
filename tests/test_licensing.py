"""
Licensing plan tests (backend).

Covers the Pilot / 100 / 250 / 500 / Unlimited plan catalog and the removal
of Asset Management licensing:

- license_server plan catalog: `PlanType` enum values and `get_plan_limits()`
  match the new catalog, and no longer carry asset/discovery/monitor
  entitlement dimensions (only audit and harden are quota-gated).
- license_server `consume_operation()`: only "audit"/"harden" operation
  types are accepted; the old "asset"/"discovery"/"monitor" types are
  rejected outright.
- Main app `app.core.dependencies`: `require_asset_quota()` no longer
  exists (asset creation is not license-gated), and `check_quota_available()`
  / `app.core.license_state.update_usage()` only recognize audit/harden.

These are logic-level unit tests. Both the main app and the license server
create a SQLAlchemy engine at import time; the project targets PostgreSQL
(see the `db-postgresql` memory — never substitute SQLite, even for tests),
so DATABASE_URL below still points at Postgres. No test here performs real
database I/O: `consume_operation` is exercised against a stubbed session and
`validate_license` is monkeypatched, so the engine is never actually used.
"""
import os
import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Point both engines at a Postgres URL using the psycopg (v3) driver this
# project depends on, so import succeeds even without a reachable database
# (create_engine() doesn't open a connection). `setdefault` never overrides
# an already-configured environment (e.g. real CI credentials).
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://test:test@localhost/test_licensing_unused")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-license-tests-only-not-real")

import pytest
from fastapi import HTTPException

from license_server.app import crud as ls_crud
from license_server.app import models as ls_models

from app.core import dependencies as app_dependencies
from app.core import license_state


# ==================== license_server: plan catalog ====================

def test_plan_type_enum_matches_new_catalog():
    values = {p.value for p in ls_models.PlanType}
    assert values == {"pilot", "plan_100", "plan_250", "plan_500", "unlimited"}
    # The old Asset-Management-era plan names must be gone entirely.
    for old_name in ("BASIC1", "BASIC2", "BASIC3", "ENTERPRISE"):
        assert not hasattr(ls_models.PlanType, old_name)


@pytest.mark.parametrize("plan,expected", [
    (ls_models.PlanType.PILOT, {"max_audits": 2, "max_hardens": 2, "duration_days": 30}),
    (ls_models.PlanType.PLAN_100, {"max_audits": 100, "max_hardens": 100, "duration_days": 365}),
    (ls_models.PlanType.PLAN_250, {"max_audits": 250, "max_hardens": 250, "duration_days": 365}),
    (ls_models.PlanType.PLAN_500, {"max_audits": 500, "max_hardens": 500, "duration_days": 365}),
    (ls_models.PlanType.UNLIMITED, {"max_audits": None, "max_hardens": None, "duration_days": 365}),
])
def test_get_plan_limits(plan, expected):
    assert ls_crud.get_plan_limits(plan) == expected


def test_get_plan_limits_has_no_asset_management_dimensions():
    for plan in ls_models.PlanType:
        limits = ls_crud.get_plan_limits(plan)
        assert set(limits.keys()) == {"max_audits", "max_hardens", "duration_days"}


def test_license_model_has_no_asset_management_columns():
    columns = {c.name for c in ls_models.License.__table__.columns}
    for removed in (
        "max_assets", "used_assets",
        "max_discoveries", "used_discoveries",
        "max_monitors", "used_monitors",
    ):
        assert removed not in columns
    assert {"max_audits", "used_audits", "max_hardens", "used_hardens"} <= columns


# ==================== license_server: consume_operation ====================

class _FakeDB:
    """Stand-in for a SQLAlchemy Session. consume_operation only calls
    commit()/refresh() on the db argument, both harmless no-ops here."""

    def commit(self):
        pass

    def refresh(self, obj):
        pass


def _fake_license(**overrides):
    base = dict(max_audits=10, used_audits=0, max_hardens=10, used_hardens=0)
    base.update(overrides)
    return SimpleNamespace(**base)


def test_consume_operation_accepts_audit_and_harden(monkeypatch):
    license_row = _fake_license()
    monkeypatch.setattr(
        ls_crud, "validate_license",
        lambda db, key, token, fp: (True, "ok", license_row),
    )

    ok, message, license_out = ls_crud.consume_operation(_FakeDB(), "k", "t", "fp", "audit", 1)
    assert ok is True
    assert license_out.used_audits == 1

    ok, message, license_out = ls_crud.consume_operation(_FakeDB(), "k", "t", "fp", "harden", 2)
    assert ok is True
    assert license_out.used_hardens == 2


@pytest.mark.parametrize("operation_type", ["asset", "discovery", "monitor"])
def test_consume_operation_rejects_removed_asset_management_operations(monkeypatch, operation_type):
    license_row = _fake_license()
    monkeypatch.setattr(
        ls_crud, "validate_license",
        lambda db, key, token, fp: (True, "ok", license_row),
    )

    ok, message, license_out = ls_crud.consume_operation(_FakeDB(), "k", "t", "fp", operation_type, 1)
    assert ok is False
    assert license_out is None
    assert "invalid" in message.lower()


def test_consume_operation_enforces_the_cap(monkeypatch):
    license_row = _fake_license(max_audits=2, used_audits=2)
    monkeypatch.setattr(
        ls_crud, "validate_license",
        lambda db, key, token, fp: (True, "ok", license_row),
    )

    ok, message, license_out = ls_crud.consume_operation(_FakeDB(), "k", "t", "fp", "audit", 1)
    assert ok is False
    assert license_row.used_audits == 2  # unchanged


def test_consume_operation_unlimited_plan_still_increments_usage(monkeypatch):
    """max_* is None (Unlimited plan) never blocks, but used_* keeps
    counting so the frontend/admin UI can display real usage."""
    license_row = _fake_license(max_audits=None, used_audits=999)
    monkeypatch.setattr(
        ls_crud, "validate_license",
        lambda db, key, token, fp: (True, "ok", license_row),
    )

    ok, message, license_out = ls_crud.consume_operation(_FakeDB(), "k", "t", "fp", "audit", 1)
    assert ok is True
    assert license_row.used_audits == 1000


# ==================== main app: quota enforcement ====================

def test_require_asset_quota_removed():
    """Asset Management must have no license gate at all in the main app."""
    assert not hasattr(app_dependencies, "require_asset_quota")


def test_check_quota_available_gates_audit_and_harden():
    license_state.set_license_state({
        "valid": True,
        "plan_type": "plan_100",
        "is_pilot_mode": False,
        "limits": {"max_audits": 2, "max_hardens": 2},
        "usage": {"used_audits": 2, "used_hardens": 0},
        "message": "ok",
    })

    check_audit = app_dependencies.check_quota_available("audit")
    with pytest.raises(HTTPException) as exc_info:
        check_audit(request=None, current_user=None)
    assert exc_info.value.status_code == 403

    check_harden = app_dependencies.check_quota_available("harden")
    check_harden(request=None, current_user=None)  # must not raise: 0 < 2


def test_check_quota_available_ignores_asset_management_operations():
    """"asset"/"discovery"/"monitor" are no longer tracked dimensions, so
    they're never gated — even against a state with zeroed-out limits."""
    license_state.set_license_state({
        "valid": True,
        "plan_type": "pilot",
        "is_pilot_mode": True,
        "limits": {"max_audits": 0, "max_hardens": 0},
        "usage": {"used_audits": 0, "used_hardens": 0},
        "message": "ok",
    })

    for operation_type in ("asset", "discovery", "monitor"):
        check = app_dependencies.check_quota_available(operation_type)
        check(request=None, current_user=None)  # must not raise


def test_update_usage_only_tracks_audit_and_harden():
    license_state.set_license_state({
        "valid": True,
        "plan_type": "plan_100",
        "is_pilot_mode": False,
        "limits": {"max_audits": 100, "max_hardens": 100},
        "usage": {"used_audits": 0, "used_hardens": 0},
        "message": "ok",
    })

    license_state.update_usage("audit", 1)
    assert license_state.get_license_state().usage["used_audits"] == 1

    # No "asset"/"discovery"/"monitor" usage key exists any more, and
    # updating one must be a harmless no-op rather than raising or
    # inventing a new key.
    license_state.update_usage("asset", 1)
    assert "used_assets" not in license_state.get_license_state().usage
