"""
Licensing tests for the main app (quota enforcement).

Asset Management is not license-gated: `require_asset_quota()` no longer
exists, and `check_quota_available()` / `license_state.update_usage()` only
recognize audit/harden. The license server's own plan catalog and
consume_operation tests live in test_license_server_plans.py.

These are logic-level unit tests. The main app creates a SQLAlchemy engine at
import time; the project targets PostgreSQL, so DATABASE_URL below still
points at Postgres, but no test here performs real database I/O.
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

from app.core import dependencies as app_dependencies
from app.core import license_state


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
