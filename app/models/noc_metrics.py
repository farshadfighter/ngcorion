"""
NOC historical metrics - append-only time-series samples and their rollups,
powering history charts and the time-range picker (1h/6h/24h/7d/30d/custom).

This complements, and never replaces, the upserted "latest value" tables in
app/models/noc.py (AssetSnmpStatus / AssetSnmpInterface): those stay exactly
as they are and keep serving the dashboard/host-list "current status" views.
Every poll additionally appends one row here per metric collected, so a chart
can show a trend instead of a single point.

Storage is bounded by app/modules/noc/metrics_retention.py's background job,
not by table design: raw samples are rolled up into 5m/1h/1d aggregates and
then deleted once older than the configured retention window
(NOC_METRICS_*_RETENTION_* in app/core/config.py), and a second check evicts
the oldest rows tier-by-tier if actual disk usage passes
NOC_METRICS_STORAGE_EVICT_THRESHOLD of NOC_METRICS_STORAGE_BUDGET_GB even
though the time-based windows haven't expired yet (more devices/interfaces
than planned). Native table partitioning (dropping whole old partitions
instead of DELETEing rows) is the natural next step once real deployments
reach a scale where that DELETE cost matters - not needed at today's scale,
so it is deliberately left out for now.
"""
from sqlalchemy import Column, Integer, BigInteger, Float, String, DateTime, ForeignKey, Index
from app.core.database import Base


class AssetMetricSample(Base):
    """One raw SNMP sample, appended (never upserted) on every poll.
    `interface_id` is null for a device-level metric (e.g. `reachable`,
    `sys_uptime_seconds`) and set for a per-interface one (e.g.
    `if_in_octets`). `metric_type` is a short free-text tag rather than a DB
    enum so a new metric (e.g. CPU/memory once those OIDs are collected)
    needs no migration to start recording."""

    __tablename__ = "asset_metric_samples"
    __table_args__ = (
        Index("ix_asset_metric_samples_lookup", "asset_id", "metric_type", "sampled_at"),
        Index("ix_asset_metric_samples_interface_lookup", "interface_id", "metric_type", "sampled_at"),
    )

    id = Column(BigInteger, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False)
    interface_id = Column(Integer, ForeignKey("asset_snmp_interfaces.id", ondelete="CASCADE"), nullable=True)
    metric_type = Column(String(30), nullable=False)
    value = Column(Float, nullable=False)
    sampled_at = Column(DateTime, nullable=False, index=True)


class AssetMetricRollup(Base):
    """5m / 1h / 1d aggregate of AssetMetricSample rows for one metric,
    computed by the retention job as raw samples age. Not partitioned - its
    row count is orders of magnitude smaller than raw, so a plain indexed
    DELETE for its own retention window is cheap."""

    __tablename__ = "asset_metric_rollups"
    __table_args__ = (
        Index(
            "ix_asset_metric_rollups_lookup",
            "asset_id", "metric_type", "granularity", "bucket_start",
        ),
        Index(
            "ix_asset_metric_rollups_interface_lookup",
            "interface_id", "metric_type", "granularity", "bucket_start",
        ),
    )

    id = Column(BigInteger, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=False)
    interface_id = Column(Integer, ForeignKey("asset_snmp_interfaces.id", ondelete="CASCADE"), nullable=True)
    metric_type = Column(String(30), nullable=False)
    granularity = Column(String(4), nullable=False)  # "5m" | "1h" | "1d"
    bucket_start = Column(DateTime, nullable=False)
    avg_value = Column(Float, nullable=False)
    min_value = Column(Float, nullable=False)
    max_value = Column(Float, nullable=False)
    sample_count = Column(Integer, nullable=False)
