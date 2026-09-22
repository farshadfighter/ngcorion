"""
NOC historical metrics: rollup computation + storage retention.

Three things happen here, all idempotent so a re-run (after a crash, or a
missed tick) never double-counts or errors out:

1. Rollup: each call to `run_once` aggregates the most recently *closed*
   5-minute bucket from raw samples into AssetMetricRollup, and - once per
   hour / once per day - also the closed 1h / 1d bucket. A bucket is
   recomputed with delete-then-insert (not a conflict-based upsert: the
   rollup table has no unique constraint that tolerates a NULL
   interface_id, and delete+insert is simpler and just as correct here)
   so re-running for a bucket already computed is harmless.
2. Time-based retention: rows older than their tier's configured window
   (NOC_METRICS_*_RETENTION_* in app/core/config.py) are deleted - raw
   first (it's the bulk of the volume), then 5m, then 1h. 1d rollups are
   kept forever unless NOC_METRICS_1D_RETENTION_DAYS is set.
3. Storage-budget eviction: a second, independent check. If the metrics
   tables' actual on-disk size (pg_total_relation_size, which includes
   indexes and TOAST - the whole footprint, not just row bytes) exceeds
   NOC_METRICS_STORAGE_EVICT_THRESHOLD of NOC_METRICS_STORAGE_BUDGET_GB,
   the oldest rows are dropped tier-by-tier (raw, then 5m, then 1h) in
   fixed-size batches until back under the threshold. This exists because
   the time-based windows above are a *guess* calibrated at some assumed
   asset/interface count - if the real deployment monitors far more devices
   than planned, the time windows alone would eventually fill the disk;
   this is the backstop that makes that impossible regardless of scale.

Not done here (left for the future, see app/models/noc_metrics.py's module
docstring): native table partitioning. At today's expected scale a plain
indexed DELETE is cheap enough; partitioning is the right upgrade once a
deployment's raw-table DELETE volume itself becomes a bottleneck.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.noc_metrics import AssetMetricSample, AssetMetricRollup

logger = logging.getLogger(__name__)

# How many rows a single eviction DELETE removes at a time - keeps one query
# from holding a long-running lock over an unbounded row count.
EVICTION_BATCH_SIZE = 5000

_GRANULARITY_STEP = {
    "5m": timedelta(minutes=5),
    "1h": timedelta(hours=1),
    "1d": timedelta(days=1),
}


def _floor(dt: datetime, step: timedelta) -> datetime:
    """Round `dt` down to the start of its `step`-sized bucket, epoch-aligned
    (not calendar-aligned) so 5m/1h/1d buckets never drift."""
    epoch = datetime(1970, 1, 1)
    elapsed = dt - epoch
    return epoch + timedelta(seconds=(elapsed // step) * step.total_seconds())


def _last_closed_bucket(now: datetime, granularity: str) -> datetime:
    """The most recent bucket_start whose bucket has fully elapsed as of `now`."""
    step = _GRANULARITY_STEP[granularity]
    current_bucket = _floor(now, step)
    return current_bucket - step


def compute_rollup_for_bucket(db: Session, granularity: str, bucket_start: datetime) -> int:
    """(Re)compute every (asset, interface, metric) rollup row for one closed
    bucket from raw samples. Returns how many rollup rows were written."""
    step = _GRANULARITY_STEP[granularity]
    bucket_end = bucket_start + step

    rows = (
        db.query(
            AssetMetricSample.asset_id,
            AssetMetricSample.interface_id,
            AssetMetricSample.metric_type,
            func.avg(AssetMetricSample.value).label("avg_value"),
            func.min(AssetMetricSample.value).label("min_value"),
            func.max(AssetMetricSample.value).label("max_value"),
            func.count(AssetMetricSample.id).label("sample_count"),
        )
        .filter(AssetMetricSample.sampled_at >= bucket_start, AssetMetricSample.sampled_at < bucket_end)
        .group_by(AssetMetricSample.asset_id, AssetMetricSample.interface_id, AssetMetricSample.metric_type)
        .all()
    )
    if not rows:
        return 0

    # Delete-then-insert: safe to recompute the same bucket more than once
    # (a missed run catching up, or a retry after a crash mid-job).
    db.query(AssetMetricRollup).filter(
        AssetMetricRollup.granularity == granularity,
        AssetMetricRollup.bucket_start == bucket_start,
    ).delete(synchronize_session=False)

    db.add_all([
        AssetMetricRollup(
            asset_id=r.asset_id, interface_id=r.interface_id, metric_type=r.metric_type,
            granularity=granularity, bucket_start=bucket_start,
            avg_value=r.avg_value, min_value=r.min_value, max_value=r.max_value,
            sample_count=r.sample_count,
        )
        for r in rows
    ])
    db.commit()
    return len(rows)


def run_rollups(db: Session, now: datetime) -> None:
    """Roll up the bucket(s) that just closed as of `now`. Called every run
    for 5m; 1h/1d only trigger once their own boundary has just passed, so a
    job that ticks every few minutes doesn't recompute an unchanged 1h/1d
    bucket on every single tick."""
    five_min_bucket = _last_closed_bucket(now, "5m")
    compute_rollup_for_bucket(db, "5m", five_min_bucket)

    if now.minute < 5:  # an hour boundary just passed
        compute_rollup_for_bucket(db, "1h", _last_closed_bucket(now, "1h"))

    if now.hour == 0 and now.minute < 5:  # a day boundary just passed
        compute_rollup_for_bucket(db, "1d", _last_closed_bucket(now, "1d"))


def apply_time_based_retention(db: Session, now: datetime) -> None:
    """Delete rows older than each tier's configured retention window. A
    retention of 0 means "keep forever" (used for 1d rollups by default)."""
    raw_cutoff = now - timedelta(hours=settings.NOC_METRICS_RAW_RETENTION_HOURS)
    db.query(AssetMetricSample).filter(AssetMetricSample.sampled_at < raw_cutoff).delete(synchronize_session=False)

    if settings.NOC_METRICS_5M_RETENTION_DAYS > 0:
        cutoff = now - timedelta(days=settings.NOC_METRICS_5M_RETENTION_DAYS)
        db.query(AssetMetricRollup).filter(
            AssetMetricRollup.granularity == "5m", AssetMetricRollup.bucket_start < cutoff,
        ).delete(synchronize_session=False)

    if settings.NOC_METRICS_1H_RETENTION_DAYS > 0:
        cutoff = now - timedelta(days=settings.NOC_METRICS_1H_RETENTION_DAYS)
        db.query(AssetMetricRollup).filter(
            AssetMetricRollup.granularity == "1h", AssetMetricRollup.bucket_start < cutoff,
        ).delete(synchronize_session=False)

    if settings.NOC_METRICS_1D_RETENTION_DAYS > 0:
        cutoff = now - timedelta(days=settings.NOC_METRICS_1D_RETENTION_DAYS)
        db.query(AssetMetricRollup).filter(
            AssetMetricRollup.granularity == "1d", AssetMetricRollup.bucket_start < cutoff,
        ).delete(synchronize_session=False)

    db.commit()


def get_metrics_storage_bytes(db: Session) -> int:
    """Actual on-disk footprint (table + indexes + TOAST) of both metrics
    tables, via Postgres's own accounting - the real number that matters for
    "is the disk about to fill up", not an estimate from row counts."""
    result = db.execute(
        text(
            "SELECT pg_total_relation_size('asset_metric_samples') "
            "     + pg_total_relation_size('asset_metric_rollups')"
        )
    ).scalar()
    return int(result or 0)


def _evict_oldest(db: Session, model, extra_filter=None) -> int:
    """Delete up to EVICTION_BATCH_SIZE of the oldest rows of `model`
    (ordered by its time column). Returns how many rows were removed."""
    time_col = model.sampled_at if model is AssetMetricSample else model.bucket_start
    query = db.query(model.id)
    if extra_filter is not None:
        query = query.filter(extra_filter)
    ids = [row[0] for row in query.order_by(time_col.asc()).limit(EVICTION_BATCH_SIZE).all()]
    if not ids:
        return 0
    db.query(model).filter(model.id.in_(ids)).delete(synchronize_session=False)
    db.commit()
    return len(ids)


def enforce_storage_budget(db: Session) -> None:
    """Second line of defense beyond the time-based windows: if actual disk
    usage has passed the configured threshold, delete the oldest rows
    tier-by-tier (raw, then 5m, then 1h - never 1d, whose volume is
    negligible and whose loss would erase long-term history for the least
    storage benefit) until back under it."""
    budget_bytes = settings.NOC_METRICS_STORAGE_BUDGET_GB * (1024 ** 3)
    threshold_bytes = budget_bytes * settings.NOC_METRICS_STORAGE_EVICT_THRESHOLD

    guard = 0  # a batch can only shrink the table so much; cap iterations so a
    # measurement lag (size doesn't update instantly after a DELETE, and
    # DELETE without VACUUM doesn't return space to the OS) can't loop forever.
    while guard < 200:
        guard += 1
        used = get_metrics_storage_bytes(db)
        if used <= threshold_bytes:
            return
        if _evict_oldest(db, AssetMetricSample) > 0:
            continue
        if _evict_oldest(db, AssetMetricRollup, AssetMetricRollup.granularity == "5m") > 0:
            continue
        if _evict_oldest(db, AssetMetricRollup, AssetMetricRollup.granularity == "1h") > 0:
            continue
        logger.warning(
            "[NOC metrics] Storage over budget (%d bytes) but only 1d rollups remain - not evicting those.",
            used,
        )
        return


def run_once(db: Session, now: datetime | None = None) -> None:
    now = now or datetime.utcnow()
    run_rollups(db, now)
    apply_time_based_retention(db, now)
    enforce_storage_budget(db)


# ==========================================
# Background loop
# ==========================================

# 5 minutes: matches the finest rollup granularity, so a bucket is rolled up
# shortly after it closes rather than sitting un-aggregated for a long time.
RETENTION_INTERVAL_SECONDS = 300


class MetricsRetentionWorker:
    def __init__(self, interval_seconds: int = RETENTION_INTERVAL_SECONDS):
        self.interval_seconds = interval_seconds
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    async def _run_once(self) -> None:
        db = SessionLocal()
        try:
            run_once(db)
        except Exception:
            logger.exception("[NOC metrics] Retention/rollup run failed")
        finally:
            db.close()

    async def _loop(self) -> None:
        while not self._stop_event.is_set():
            await self._run_once()
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval_seconds)
            except asyncio.TimeoutError:
                pass

    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        if self.is_running():
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._loop(), name="noc-metrics-retention")
        logger.info("[NOC metrics] Retention worker started (interval: %ds)", self.interval_seconds)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop_event.set()
        try:
            await asyncio.wait_for(self._task, timeout=5)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None
        logger.info("[NOC metrics] Retention worker stopped")


_worker: Optional[MetricsRetentionWorker] = None


def start_metrics_retention_worker() -> None:
    global _worker
    if _worker is None:
        _worker = MetricsRetentionWorker()
    if not _worker.is_running():
        _worker.start()


async def stop_metrics_retention_worker() -> None:
    global _worker
    if _worker is not None:
        await _worker.stop()
