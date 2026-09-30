"""
License server plan-catalog and consume_operation tests.

The license server lives in its own repository (split out in df3bd91); these
tests run only where that package is importable, e.g. in a combined checkout.
"""
import os
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://test:test@localhost/test_licensing_unused")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-license-tests-only-not-real")

import pytest

ls_crud = pytest.importorskip(
    "license_server.app.crud",
    reason="license_server is a separate repository and is not installed here",
)
from license_server.app import models as ls_models  # noqa: E402


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

