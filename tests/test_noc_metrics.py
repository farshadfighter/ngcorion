"""Tests for NOC historical metrics: raw sample recording on every poll,
rollup computation, time-based retention, storage-budget eviction, tier
selection, and the metrics API route (app/modules/noc/metrics_retention.py,
app/modules/noc/service.py's metric-series methods, and the /metrics route).

Needs a migrated PostgreSQL database; each test runs inside a transaction
that is rolled back, so nothing here touches real rows (same pattern as
test_noc.py).
"""

import asyncio
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import engine
from app.models.asset import Asset
from app.models.asset_types import AssetType
from app.models.user import User
from app.models.noc import AssetSnmpInterface
from app.models.noc_metrics import AssetMetricSample, AssetMetricRollup
from app.modules.noc.service import NocService
from app.modules.noc.snmp_client import DevicePollResult, InterfacePollResult
from app.modules.noc import metrics_retention


@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection)
    session.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(sess, transaction):
        if transaction.nested and not transaction._parent.nested:
            sess.begin_nested()

    try:
        yield session
    finally:
        event.remove(session, "after_transaction_end", _restart_savepoint)
        session.close()
        trans.rollback()
        connection.close()


_seq = [0]


def _next() -> int:
    _seq[0] += 1
    return _seq[0]


@pytest.fixture
def user(db) -> User:
    row = User(username=f"metrics_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


def _make_asset(db, ip="10.20.20.1") -> Asset:
    asset_type = AssetType(type_name=f"Firewall_{_next()}", category="network")
    db.add(asset_type)
    db.flush()
    row = Asset(asset_name=f"metrics-asset-{_next()}", asset_type_id=asset_type.id, ip_address=ip)
    db.add(row)
    db.flush()
    return row


def run(coro):
    return asyncio.run(coro)


# ======================================================================
# Raw sample recording on every poll
# ======================================================================

def test_persist_poll_result_writes_a_reachable_sample(db, user):
    asset = _make_asset(db)
    result = DevicePollResult(reachable=True, sys_name="fw1")
    NocService._persist_poll_result(db, asset.id, result)

    samples = db.query(AssetMetricSample).filter(
        AssetMetricSample.asset_id == asset.id, AssetMetricSample.metric_type == "reachable",
    ).all()
    assert len(samples) == 1
    assert samples[0].value == 1.0
    assert samples[0].interface_id is None


def test_persist_poll_result_records_unreachable_as_zero(db, user):
    asset = _make_asset(db)
    result = DevicePollResult(reachable=False, error_message="timeout")
    NocService._persist_poll_result(db, asset.id, result)

    sample = db.query(AssetMetricSample).filter(
        AssetMetricSample.asset_id == asset.id, AssetMetricSample.metric_type == "reachable",
    ).one()
    assert sample.value == 0.0


def test_persist_poll_result_writes_interface_octet_samples_linked_to_the_interface_row(db, user):
    asset = _make_asset(db)
    result = DevicePollResult(
        reachable=True,
        interfaces=[InterfacePollResult(if_index=1, if_descr="port1", in_octets=1000, out_octets=2000)],
    )
    NocService._persist_poll_result(db, asset.id, result)

    iface = db.query(AssetSnmpInterface).filter(AssetSnmpInterface.asset_id == asset.id).one()
    in_sample = db.query(AssetMetricSample).filter(
        AssetMetricSample.interface_id == iface.id, AssetMetricSample.metric_type == "if_in_octets",
    ).one()
    out_sample = db.query(AssetMetricSample).filter(
        AssetMetricSample.interface_id == iface.id, AssetMetricSample.metric_type == "if_out_octets",
    ).one()
    assert in_sample.value == 1000.0
    assert out_sample.value == 2000.0


def test_persist_poll_result_records_a_brand_new_interfaces_first_sample_too(db, user):
    """Regression: the interface row is created in the same poll as its
    first sample, so the lookup dict used to find its id for the FK must
    include rows created earlier in this same call, not only pre-existing
    ones - otherwise a device's interfaces never get their very first
    sample recorded."""
    asset = _make_asset(db)
    result = DevicePollResult(
        reachable=True,
        interfaces=[InterfacePollResult(if_index=7, if_descr="wan1", in_octets=500, out_octets=250)],
    )
    NocService._persist_poll_result(db, asset.id, result)

    iface = db.query(AssetSnmpInterface).filter(AssetSnmpInterface.asset_id == asset.id, AssetSnmpInterface.if_index == 7).one()
    count = db.query(AssetMetricSample).filter(AssetMetricSample.interface_id == iface.id).count()
    assert count == 2  # in + out


# ======================================================================
# Rollup computation
# ======================================================================

def test_compute_rollup_for_bucket_aggregates_avg_min_max_count(db, user):
    asset = _make_asset(db)
    bucket_start = datetime(2026, 1, 1, 10, 0, 0)
    for i, value in enumerate([10.0, 20.0, 30.0]):
        db.add(AssetMetricSample(
            asset_id=asset.id, interface_id=None, metric_type="reachable",
            value=value, sampled_at=bucket_start + timedelta(minutes=i),
        ))
    db.flush()

    written = metrics_retention.compute_rollup_for_bucket(db, "5m", bucket_start)
    assert written == 1

    rollup = db.query(AssetMetricRollup).filter(
        AssetMetricRollup.asset_id == asset.id, AssetMetricRollup.granularity == "5m",
        AssetMetricRollup.bucket_start == bucket_start,
    ).one()
    assert rollup.avg_value == 20.0
    assert rollup.min_value == 10.0
    assert rollup.max_value == 30.0
    assert rollup.sample_count == 3


def test_compute_rollup_for_bucket_is_idempotent_on_rerun(db, user):
    asset = _make_asset(db)
    bucket_start = datetime(2026, 1, 1, 12, 0, 0)
    db.add(AssetMetricSample(
        asset_id=asset.id, interface_id=None, metric_type="reachable",
        value=1.0, sampled_at=bucket_start + timedelta(minutes=1),
    ))
    db.flush()

    metrics_retention.compute_rollup_for_bucket(db, "5m", bucket_start)
    metrics_retention.compute_rollup_for_bucket(db, "5m", bucket_start)

    rows = db.query(AssetMetricRollup).filter(
        AssetMetricRollup.asset_id == asset.id, AssetMetricRollup.bucket_start == bucket_start,
    ).all()
    assert len(rows) == 1


def test_run_rollups_only_computes_1h_and_1d_at_their_own_boundary(db, user):
    with patch("app.modules.noc.metrics_retention.compute_rollup_for_bucket") as mocked:
        metrics_retention.run_rollups(db, datetime(2026, 1, 1, 14, 32, 0))
        granularities_called = {call.args[1] for call in mocked.call_args_list}
        assert granularities_called == {"5m"}

    with patch("app.modules.noc.metrics_retention.compute_rollup_for_bucket") as mocked:
        metrics_retention.run_rollups(db, datetime(2026, 1, 1, 15, 2, 0))
        granularities_called = {call.args[1] for call in mocked.call_args_list}
        assert granularities_called == {"5m", "1h"}

    with patch("app.modules.noc.metrics_retention.compute_rollup_for_bucket") as mocked:
        metrics_retention.run_rollups(db, datetime(2026, 1, 2, 0, 2, 0))
        granularities_called = {call.args[1] for call in mocked.call_args_list}
        assert granularities_called == {"5m", "1h", "1d"}


# ======================================================================
# Time-based retention
# ======================================================================

def test_apply_time_based_retention_deletes_old_raw_keeps_recent(db, user, monkeypatch):
    monkeypatch.setattr(settings, "NOC_METRICS_RAW_RETENTION_HOURS", 24)
    asset = _make_asset(db)
    now = datetime(2026, 1, 10, 0, 0, 0)
    old = AssetMetricSample(asset_id=asset.id, metric_type="reachable", value=1.0, sampled_at=now - timedelta(hours=48))
    recent = AssetMetricSample(asset_id=asset.id, metric_type="reachable", value=1.0, sampled_at=now - timedelta(hours=1))
    db.add_all([old, recent])
    db.flush()
    old_id, recent_id = old.id, recent.id  # apply_time_based_retention commits, which expires these instances

    metrics_retention.apply_time_based_retention(db, now)

    remaining_ids = {r.id for r in db.query(AssetMetricSample).filter(AssetMetricSample.asset_id == asset.id).all()}
    assert old_id not in remaining_ids
    assert recent_id in remaining_ids


def test_apply_time_based_retention_keeps_1d_rollups_forever_by_default(db, user, monkeypatch):
    monkeypatch.setattr(settings, "NOC_METRICS_1D_RETENTION_DAYS", 0)
    asset = _make_asset(db)
    ancient = AssetMetricRollup(
        asset_id=asset.id, metric_type="reachable", granularity="1d",
        bucket_start=datetime(2000, 1, 1), avg_value=1, min_value=1, max_value=1, sample_count=1,
    )
    db.add(ancient)
    db.flush()

    metrics_retention.apply_time_based_retention(db, datetime(2026, 1, 1))

    assert db.query(AssetMetricRollup).filter(AssetMetricRollup.id == ancient.id).first() is not None


# ======================================================================
# Storage-budget eviction
# ======================================================================

def test_enforce_storage_budget_evicts_raw_before_5m_and_leaves_1h_alone(db, user, monkeypatch):
    asset = _make_asset(db)
    for i in range(3):
        db.add(AssetMetricSample(asset_id=asset.id, metric_type="reachable", value=1.0, sampled_at=datetime(2026, 1, 1) + timedelta(minutes=i)))
    for i in range(2):
        db.add(AssetMetricRollup(
            asset_id=asset.id, metric_type="reachable", granularity="5m",
            bucket_start=datetime(2026, 1, 1) + timedelta(minutes=i * 5),
            avg_value=1, min_value=1, max_value=1, sample_count=1,
        ))
    kept_1h = AssetMetricRollup(
        asset_id=asset.id, metric_type="reachable", granularity="1h",
        bucket_start=datetime(2026, 1, 1), avg_value=1, min_value=1, max_value=1, sample_count=1,
    )
    db.add(kept_1h)
    db.flush()

    def fake_size(_db):
        raw_left = _db.query(AssetMetricSample).filter(AssetMetricSample.asset_id == asset.id).count()
        five_m_left = _db.query(AssetMetricRollup).filter(
            AssetMetricRollup.asset_id == asset.id, AssetMetricRollup.granularity == "5m",
        ).count()
        return 10**12 if (raw_left > 0 or five_m_left > 0) else 0

    monkeypatch.setattr(metrics_retention, "get_metrics_storage_bytes", fake_size)

    metrics_retention.enforce_storage_budget(db)

    assert db.query(AssetMetricSample).filter(AssetMetricSample.asset_id == asset.id).count() == 0
    assert db.query(AssetMetricRollup).filter(
        AssetMetricRollup.asset_id == asset.id, AssetMetricRollup.granularity == "5m",
    ).count() == 0
    assert db.query(AssetMetricRollup).filter(AssetMetricRollup.id == kept_1h.id).first() is not None


def test_enforce_storage_budget_never_evicts_1d_rollups(db, user, monkeypatch):
    asset = _make_asset(db)
    daily = AssetMetricRollup(
        asset_id=asset.id, metric_type="reachable", granularity="1d",
        bucket_start=datetime(2020, 1, 1), avg_value=1, min_value=1, max_value=1, sample_count=1,
    )
    db.add(daily)
    db.flush()

    # Always "over budget" no matter what is evicted - only 1d rollups remain
    # to evict, and the function must refuse to touch them.
    monkeypatch.setattr(metrics_retention, "get_metrics_storage_bytes", lambda _db: 10**12)

    metrics_retention.enforce_storage_budget(db)  # must return, not loop forever

    assert db.query(AssetMetricRollup).filter(AssetMetricRollup.id == daily.id).first() is not None


# ======================================================================
# Tier selection + metric series
# ======================================================================

@pytest.mark.parametrize(
    "range_seconds,expected",
    [(3600, "raw"), (6 * 3600, "raw"), (6 * 3600 + 1, "5m"), (7 * 86400, "5m"), (7 * 86400 + 1, "1h"), (90 * 86400, "1h"), (90 * 86400 + 1, "1d")],
)
def test_pick_granularity_boundaries(range_seconds, expected):
    assert NocService.pick_granularity(range_seconds) == expected


def test_get_metric_series_uses_raw_for_a_short_range(db, user):
    asset = _make_asset(db)
    now = datetime(2026, 1, 5, 12, 0, 0)
    db.add(AssetMetricSample(asset_id=asset.id, metric_type="reachable", value=1.0, sampled_at=now - timedelta(minutes=30)))
    db.flush()

    granularity, points = NocService.get_metric_series(
        db, asset.id, "reachable", now - timedelta(hours=1), now,
    )
    assert granularity == "raw"
    assert len(points) == 1
    assert points[0]["avg"] == 1.0
    assert points[0]["count"] == 1


def test_get_metric_series_uses_5m_rollups_for_a_multi_day_range(db, user):
    asset = _make_asset(db)
    now = datetime(2026, 1, 5, 12, 0, 0)
    db.add(AssetMetricRollup(
        asset_id=asset.id, metric_type="reachable", granularity="5m",
        bucket_start=now - timedelta(days=2), avg_value=0.8, min_value=0.0, max_value=1.0, sample_count=5,
    ))
    db.flush()

    granularity, points = NocService.get_metric_series(
        db, asset.id, "reachable", now - timedelta(days=3), now,
    )
    assert granularity == "5m"
    assert len(points) == 1
    assert points[0]["avg"] == 0.8
    assert points[0]["count"] == 5


# ======================================================================
# Router
# ======================================================================

def test_route_get_host_metrics_rejects_an_unknown_metric_name(db, user):
    from fastapi import HTTPException
    from app.modules.noc.router import get_host_metrics

    asset = _make_asset(db)
    with pytest.raises(HTTPException) as exc_info:
        get_host_metrics(asset_id=asset.id, metric="not_a_real_metric", current_user=user, db=db)
    assert exc_info.value.status_code == 400


def test_route_get_host_metrics_defaults_to_the_last_24_hours(db, user):
    from app.modules.noc.router import get_host_metrics

    asset = _make_asset(db)
    # A 24h default window is wider than the 6h raw cutoff (see
    # NocService.pick_granularity), so it resolves to 5m rollups.
    db.add(AssetMetricRollup(
        asset_id=asset.id, metric_type="reachable", granularity="5m",
        bucket_start=datetime.utcnow() - timedelta(hours=1),
        avg_value=1.0, min_value=1.0, max_value=1.0, sample_count=1,
    ))
    # Outside the default 24h window - must not come back.
    db.add(AssetMetricRollup(
        asset_id=asset.id, metric_type="reachable", granularity="5m",
        bucket_start=datetime.utcnow() - timedelta(days=3),
        avg_value=0.0, min_value=0.0, max_value=0.0, sample_count=1,
    ))
    db.flush()

    # start/end/interface_id must be passed explicitly here: calling the route
    # function directly (bypassing FastAPI's request handling) leaves an
    # omitted Query(...)-defaulted parameter as that sentinel object, not the
    # None it resolves to over real HTTP.
    result = get_host_metrics(
        asset_id=asset.id, metric="reachable", interface_id=None, start=None, end=None,
        current_user=user, db=db,
    )
    assert result.metric == "reachable"
    assert result.granularity == "5m"
    assert len(result.points) == 1
    assert result.points[0].avg == 1.0


def test_route_get_host_metrics_404s_for_an_unknown_asset(db, user):
    from fastapi import HTTPException
    from app.modules.noc.router import get_host_metrics

    with pytest.raises(HTTPException) as exc_info:
        get_host_metrics(asset_id=999999, metric="reachable", current_user=user, db=db)
    assert exc_info.value.status_code == 404
