"""NOC Service - SNMP credential management and poll orchestration/persistence."""
import asyncio
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session, joinedload

from app.models.asset import Asset
from app.models.enums import StatusEnum
from app.models.noc import AssetSnmpCredential, AssetSnmpStatus, AssetSnmpInterface
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

        status.reachable = result.reachable
        status.sys_descr = result.sys_descr
        status.sys_name = result.sys_name
        status.sys_contact = result.sys_contact
        status.sys_location = result.sys_location
        status.sys_uptime_ticks = result.sys_uptime_ticks
        status.error_message = result.error_message
        status.last_polled_at = datetime.utcnow()
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
            row.if_descr = iface.if_descr
            row.if_type = iface.if_type
            row.if_speed = iface.if_speed
            row.if_admin_status = iface.if_admin_status
            row.if_oper_status = iface.if_oper_status
            row.in_octets = iface.in_octets
            row.out_octets = iface.out_octets
            row.last_polled_at = status.last_polled_at

        db.commit()
        db.refresh(status)
        return status

    @staticmethod
    async def poll_one(db: Session, asset_id: int) -> AssetSnmpStatus:
        """Poll one asset right now and persist the result. Raises ValueError
        if the asset has no SNMP credential or no IP address configured."""
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset is None:
            raise ValueError(f"Asset {asset_id} not found")
        if not asset.ip_address:
            raise ValueError(f"Asset {asset_id} has no IP address configured")
        credential = NocService.get_credential(db, asset_id)
        if credential is None:
            raise ValueError(f"Asset {asset_id} has no SNMP credential configured")

        result = await poll_asset(asset.ip_address, credential)
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
        targets = [c for c in credentials if c.asset and c.asset.ip_address]

        semaphore = asyncio.Semaphore(MAX_CONCURRENT_POLLS)

        async def _poll_and_persist(credential: AssetSnmpCredential):
            async with semaphore:
                try:
                    result = await poll_asset(credential.asset.ip_address, credential)
                    NocService._persist_poll_result(db, credential.asset_id, result)
                except Exception:
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
