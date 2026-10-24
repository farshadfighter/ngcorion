"""NOC Service - SNMP credential management and poll orchestration/persistence."""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session, joinedload

from app.models.asset import Asset
from app.models.enums import StatusEnum
from app.models.noc import AssetSnmpCredential, AssetSnmpStatus, AssetSnmpInterface, DeviceReboot
from app.models.noc_metrics import AssetMetricSample, AssetMetricRollup
from app.core.snmp_crypto import encrypt_secret
from app.modules.noc.snmp_client import poll_asset, DevicePollResult

logger = logging.getLogger(__name__)

# Bound how many devices are polled at once - unattended background polling
# against dozens/hundreds of assets must not open unlimited concurrent
# sockets. Each poll is already bounded by its own per-request timeout
# (see snmp_client.DEFAULT_TIMEOUT_SECONDS).
MAX_CONCURRENT_POLLS = 20

# Consecutive failed polls before an SNMP-monitored asset flips to INACTIVE.
# A single dropped packet must not flip status (flapping); one success
# immediately flips it back to ACTIVE - see _apply_auto_status below.
NOC_INACTIVE_AFTER_FAILURES = 3

# Reboot detection (see _note_reboot): the boot time the uptime implies may move by poll latency
# between two polls; a later boot time by more than this is a restart.
REBOOT_TOLERANCE = timedelta(seconds=120)
# TimeTicks (hundredths of a second, 32 bits) wrap after about 497 days: the implied boot time then
# jumps forward by exactly this much, which is not a restart.
UPTIME_WRAP = timedelta(seconds=2 ** 32 / 100)

# Device health values recorded in the metric history (app/models/noc_metrics.py) and charted.
HEALTH_METRICS = ("cpu_percent", "memory_percent", "disk_percent", "temperature_c")


# Hosts whose stored SNMP credential could not be decrypted, warned about once until a poll succeeds.
_UNREADABLE: set = set()


class NocService:
    """NOC (SNMP monitoring) service."""

    # ==========================================
    # Credentials
    # ==========================================

    @staticmethod
    def get_credential(db: Session, asset_id: int) -> Optional[AssetSnmpCredential]:
        return db.query(AssetSnmpCredential).filter(AssetSnmpCredential.asset_id == asset_id).first()

    @staticmethod
    def set_credential(db: Session, asset_id: int, data: dict, user_id: Optional[int]) -> AssetSnmpCredential:
        """Upsert - one credential row per asset. Secrets in `data` are
        plaintext in (community / auth_key / priv_key); only their encrypted
        form is ever persisted."""
        row = NocService.get_credential(db, asset_id)
        if row is None:
            row = AssetSnmpCredential(asset_id=asset_id, created_by=user_id)
            db.add(row)

        row.version = data.get("version", "v2c")
        row.port = data.get("port", 161)
        if "poll_address" in data:
            row.poll_address = (data["poll_address"] or "").strip() or None

        community = data.get("community")
        if community:
            row.community_encrypted = encrypt_secret(community)

        row.username = data.get("username") or row.username
        row.auth_protocol = data.get("auth_protocol") or row.auth_protocol
        auth_key = data.get("auth_key")
        if auth_key:
            row.auth_key_encrypted = encrypt_secret(auth_key)

        row.priv_protocol = data.get("priv_protocol") or row.priv_protocol
        priv_key = data.get("priv_key")
        if priv_key:
            row.priv_key_encrypted = encrypt_secret(priv_key)

        db.commit()
        db.refresh(row)
        return row

    @staticmethod
    def delete_credential(db: Session, asset_id: int) -> bool:
        """Delete a host's SNMP credential; False if it had none."""
        row = NocService.get_credential(db, asset_id)
        if row is None:
            return False
        db.delete(row)
        db.commit()
        return True

    # ==========================================
    # Status / interfaces
    # ==========================================

    @staticmethod
    def get_status(db: Session, asset_id: int) -> Optional[AssetSnmpStatus]:
        return db.query(AssetSnmpStatus).filter(AssetSnmpStatus.asset_id == asset_id).first()

    @staticmethod
    def get_interfaces(db: Session, asset_id: int) -> list[AssetSnmpInterface]:
        """A host's interfaces in ifIndex order."""
        return (
            db.query(AssetSnmpInterface)
            .filter(AssetSnmpInterface.asset_id == asset_id)
            .order_by(AssetSnmpInterface.if_index)
            .all()
        )

    @staticmethod
    def _apply_auto_status(db: Session, asset_id: int, reachable: bool, consecutive_failures: int) -> None:
        """Drive Asset.status from live SNMP reachability - the asset's
        lifecycle status is otherwise fully manual, but once it has an SNMP
        credential configured, NOC becomes the source of truth for whether
        it's ACTIVE or INACTIVE (per product decision: "دستی ست نشه، اتوماتیک
        از NOC مشخصاتشو دریافت کنه"). DECOMMISSIONED is left alone - an
        explicit end-of-life marking must not be overridden by a device that
        happens to still answer SNMP."""
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset is None or asset.status == StatusEnum.DECOMMISSIONED:
            return
        if reachable:
            asset.status = StatusEnum.ACTIVE
        elif consecutive_failures >= NOC_INACTIVE_AFTER_FAILURES:
            asset.status = StatusEnum.INACTIVE

    @staticmethod
    def _persist_poll_result(db: Session, asset_id: int, result: DevicePollResult) -> AssetSnmpStatus:
        status = db.query(AssetSnmpStatus).filter(AssetSnmpStatus.asset_id == asset_id).first()
        if status is None:
            status = AssetSnmpStatus(asset_id=asset_id)
            db.add(status)

        now = datetime.utcnow()
        if result.reachable:
            NocService._apply_health(db, asset_id, status, result, now)
        status.reachable = result.reachable
        status.sys_descr = result.sys_descr
        status.sys_name = result.sys_name
        status.sys_contact = result.sys_contact
        status.sys_location = result.sys_location
        status.sys_uptime_ticks = result.sys_uptime_ticks
        status.error_message = result.error_message
        status.last_polled_at = now
        status.consecutive_poll_failures = 0 if result.reachable else (status.consecutive_poll_failures or 0) + 1

        NocService._apply_auto_status(db, asset_id, result.reachable, status.consecutive_poll_failures)

        existing = {
            row.if_index: row
            for row in db.query(AssetSnmpInterface).filter(AssetSnmpInterface.asset_id == asset_id).all()
        }
        for iface in result.interfaces:
            row = existing.get(iface.if_index)
            if row is None:
                row = AssetSnmpInterface(asset_id=asset_id, if_index=iface.if_index)
                db.add(row)
                existing[iface.if_index] = row
            row.if_descr = iface.if_descr
            row.if_name = iface.if_name
            row.if_alias = iface.if_alias
            row.if_type = iface.if_type
            row.if_speed = iface.if_speed
            row.if_admin_status = iface.if_admin_status
            row.if_oper_status = iface.if_oper_status
            row.in_octets = iface.in_octets
            row.out_octets = iface.out_octets
            row.last_polled_at = status.last_polled_at

        # New interface rows need an id before they can be referenced by a
        # metric sample's interface_id FK.
        db.flush()
        NocService._record_metric_samples(db, asset_id, status, result, existing)

        db.commit()
        db.refresh(status)
        return status

    @staticmethod
    def _apply_health(db: Session, asset_id: int, status: AssetSnmpStatus, result: DevicePollResult,
                      now: datetime) -> None:
        """Store the health of a successful poll and notice a restart. Health is kept as last known
        while the device does not answer (the history shows the gap)."""
        h = result.health
        ticks = h.uptime_ticks if h is not None and h.uptime_ticks is not None else result.sys_uptime_ticks
        if ticks is not None:
            NocService._note_reboot(db, asset_id, status, int(ticks), now)
            status.device_uptime_ticks = int(ticks)
        if h is None:
            return
        status.cpu_percent = h.cpu_percent
        status.memory_percent = h.memory_percent
        status.memory_total_bytes = h.memory_total_bytes
        status.disk_percent = h.disk_percent
        status.temperature_c = h.temperature_c
        status.health = h.detail()

    @staticmethod
    def _note_reboot(db: Session, asset_id: int, status: AssetSnmpStatus, ticks: int, now: datetime) -> None:
        """The uptime implies a boot time (now - uptime). Compared with the one the previous successful
        poll implied: later by more than REBOOT_TOLERANCE means the device restarted in between (a
        DeviceReboot row, which the alert "noc.device_rebooted" reports), unless it is the 497-day
        counter wrap. Re-anchored every poll, so clock drift never adds up to a false restart."""
        booted = now - timedelta(seconds=ticks / 100)
        previous = status.last_reboot_at
        status.last_reboot_at = booted
        if previous is None:
            return
        moved = booted - previous
        if moved <= REBOOT_TOLERANCE:
            return
        if abs(moved - UPTIME_WRAP) <= timedelta(minutes=10):
            return
        db.add(DeviceReboot(asset_id=asset_id, detected_at=now, booted_at=booted,
                            previous_uptime_seconds=max(int(moved.total_seconds()), 0)))
        logger.info("[NOC] asset %s restarted at %s", asset_id, booted.isoformat(timespec="seconds"))

    @staticmethod
    def _record_metric_samples(
        db: Session,
        asset_id: int,
        status: AssetSnmpStatus,
        result: DevicePollResult,
        interfaces_by_index: dict,
    ) -> None:
        """Append one history row per metric collected this poll (see
        app/models/noc_metrics.py). This is additive: it never reads or
        changes the upserted "latest value" rows above, so a failure here
        would only cost history, never current status - kept as a plain
        insert rather than wrapped in its own try/except because a poll that
        can't write its own history is exactly the kind of silent data loss
        the history feature exists to catch."""
        sampled_at = status.last_polled_at
        samples = [
            AssetMetricSample(
                asset_id=asset_id, interface_id=None,
                metric_type="reachable", value=1.0 if result.reachable else 0.0,
                sampled_at=sampled_at,
            )
        ]
        if result.reachable and result.health is not None:
            for metric in HEALTH_METRICS:
                value = getattr(result.health, metric)
                if value is not None:
                    samples.append(AssetMetricSample(asset_id=asset_id, interface_id=None, metric_type=metric,
                                                     value=float(value), sampled_at=sampled_at))
        for iface in result.interfaces:
            row = interfaces_by_index.get(iface.if_index)
            if row is None or row.id is None:
                continue
            if iface.in_octets is not None:
                samples.append(AssetMetricSample(
                    asset_id=asset_id, interface_id=row.id,
                    metric_type="if_in_octets", value=float(iface.in_octets), sampled_at=sampled_at,
                ))
            if iface.out_octets is not None:
                samples.append(AssetMetricSample(
                    asset_id=asset_id, interface_id=row.id,
                    metric_type="if_out_octets", value=float(iface.out_octets), sampled_at=sampled_at,
                ))
        db.add_all(samples)

    @staticmethod
    async def poll_one(db: Session, asset_id: int) -> AssetSnmpStatus:
        """Poll one asset right now and persist the result. Raises ValueError
        if the asset has no SNMP credential or no IP address configured."""
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset is None:
            raise ValueError(f"Asset {asset_id} not found")
        credential = NocService.get_credential(db, asset_id)
        if credential is None:
            raise ValueError(f"Asset {asset_id} has no SNMP credential configured")
        if not credential.target:
            raise ValueError(f"Asset {asset_id} has no IP address configured")

        result = await poll_asset(credential.target, credential)
        return NocService._persist_poll_result(db, asset_id, result)

    @staticmethod
    async def poll_all(db: Session) -> int:
        """Poll every asset that has an SNMP credential configured, bounded
        by MAX_CONCURRENT_POLLS. Returns how many assets were polled. Used by
        the background poller (app/modules/noc/poller.py) and available for
        an on-demand "poll everything now" action."""
        credentials = (
            db.query(AssetSnmpCredential)
            .options(joinedload(AssetSnmpCredential.asset))
            .all()
        )
        targets = [c for c in credentials if c.asset and c.target]

        semaphore = asyncio.Semaphore(MAX_CONCURRENT_POLLS)

        async def _poll_and_persist(credential: AssetSnmpCredential):
            async with semaphore:
                try:
                    result = await poll_asset(credential.target, credential)
                    NocService._persist_poll_result(db, credential.asset_id, result)
                    _UNREADABLE.discard(credential.asset_id)
                except Exception as exc:
                    # The stored community or v3 keys cannot be decrypted (SECRET_KEY changed, a
                    # restore from another server): one line per host, not a traceback per poll.
                    if isinstance(exc, ValueError) and "decrypt" in str(exc):
                        if credential.asset_id not in _UNREADABLE:
                            _UNREADABLE.add(credential.asset_id)
                            logger.warning("[NOC] Asset %s not polled: %s; enter its SNMP credential again",
                                           credential.asset_id, exc)
                        return
                    logger.exception("[NOC] Poll failed for asset %s", credential.asset_id)

        await asyncio.gather(*(_poll_and_persist(c) for c in targets))
        return len(targets)

    # ==========================================
    # Dashboard / host list assembly
    # ==========================================

    @staticmethod
    def list_assets_with_status(db: Session) -> list[tuple[Asset, Optional[AssetSnmpStatus], bool]]:
        """Every asset, its last SNMP status (if any), and whether it has a
        credential configured (a credential with no status yet means "not
        polled since it was added" - a distinct state from "unreachable")."""
        assets = db.query(Asset).options(joinedload(Asset.asset_type)).all()
        statuses = {s.asset_id: s for s in db.query(AssetSnmpStatus).all()}
        credential_asset_ids = {row[0] for row in db.query(AssetSnmpCredential.asset_id).all()}
        return [(a, statuses.get(a.id), a.id in credential_asset_ids) for a in assets]

    # ==========================================
    # Historical metrics (time-range charts)
    # ==========================================

    @staticmethod
    def pick_granularity(range_seconds: float) -> str:
        """Which tier answers a query of this width, without the caller (the
        time-range picker) needing to know about raw vs. rollups at all. A
        short window gets full resolution; a long one gets a coarser rollup
        so the response stays a reasonable number of points either way."""
        if range_seconds <= 6 * 3600:
            return "raw"
        if range_seconds <= 7 * 86400:
            return "5m"
        if range_seconds <= 90 * 86400:
            return "1h"
        return "1d"

    @staticmethod
    def get_metric_series(
        db: Session,
        asset_id: int,
        metric: str,
        start: datetime,
        end: datetime,
        interface_id: Optional[int] = None,
    ) -> tuple[str, list[dict]]:
        """Time series for one metric over [start, end], auto-picking raw vs.
        rollup granularity by range width (see pick_granularity). Returns
        (granularity, points) - each point a dict with t/avg/min/max/count,
        ready to hand to MetricSeriesResponse."""
        granularity = NocService.pick_granularity((end - start).total_seconds())

        if granularity == "raw":
            query = (
                db.query(AssetMetricSample.sampled_at, AssetMetricSample.value)
                .filter(
                    AssetMetricSample.asset_id == asset_id,
                    AssetMetricSample.metric_type == metric,
                    AssetMetricSample.interface_id == interface_id,
                    AssetMetricSample.sampled_at >= start,
                    AssetMetricSample.sampled_at <= end,
                )
                .order_by(AssetMetricSample.sampled_at.asc())
            )
            points = [
                {"t": row.sampled_at, "avg": row.value, "min": row.value, "max": row.value, "count": 1}
                for row in query.all()
            ]
            return granularity, points

        query = (
            db.query(AssetMetricRollup)
            .filter(
                AssetMetricRollup.asset_id == asset_id,
                AssetMetricRollup.metric_type == metric,
                AssetMetricRollup.interface_id == interface_id,
                AssetMetricRollup.granularity == granularity,
                AssetMetricRollup.bucket_start >= start,
                AssetMetricRollup.bucket_start <= end,
            )
            .order_by(AssetMetricRollup.bucket_start.asc())
        )
        points = [
            {"t": row.bucket_start, "avg": row.avg_value, "min": row.min_value, "max": row.max_value, "count": row.sample_count}
            for row in query.all()
        ]
        return granularity, points
