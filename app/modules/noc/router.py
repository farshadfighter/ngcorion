"""
NOC Router

SNMP-based monitoring: per-asset credential management, host list/detail
with the last poll result, and on-demand polling. The background poller
(app/modules/noc/poller.py) keeps this data fresh on its own; these
endpoints are for reading it and for triggering an out-of-cycle poll.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, Asset
from app.modules.noc.service import NocService
from app.modules.noc.schemas import (
    SnmpCredentialSet,
    SnmpCredentialInfo,
    HostSummary,
    HostDetail,
    InterfaceInfo,
    PollNowResponse,
    PollAllResponse,
    MetricPoint,
    MetricSeriesResponse,
)

# What a metric name may legally be - keeps the endpoint from being used as
# an arbitrary column-name injection point and gives callers a clear 400
# instead of a silently-empty series for a typo'd metric name.
VALID_METRICS = {"reachable", "if_in_octets", "if_out_octets"}

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/noc", tags=["NOC"])


def _credential_info(credential) -> SnmpCredentialInfo | None:
    if credential is None:
        return None
    return SnmpCredentialInfo(
        version=credential.version,
        port=credential.port,
        has_community=bool(credential.community_encrypted),
        username=credential.username,
        auth_protocol=credential.auth_protocol,
        has_auth_key=bool(credential.auth_key_encrypted),
        priv_protocol=credential.priv_protocol,
        has_priv_key=bool(credential.priv_key_encrypted),
        updated_at=credential.updated_at,
    )


@router.get("/hosts", response_model=list[HostSummary])
def list_hosts(
    current_user: User = Depends(require_permission("noc", "read")),
    db: Session = Depends(get_db),
):
    """Every asset with its last SNMP status - backs both the Dashboard
    status table and the Host list page."""
    rows = NocService.list_assets_with_status(db)
    return [
        HostSummary(
            asset_id=asset.id,
            asset_name=asset.asset_name,
            ip_address=asset.ip_address,
            asset_type_name=asset.asset_type.type_name if asset.asset_type else None,
            has_credential=has_credential,
            reachable=status.reachable if status else None,
            sys_name=status.sys_name if status else None,
            last_polled_at=status.last_polled_at if status else None,
            error_message=status.error_message if status else None,
        )
        for asset, status, has_credential in rows
    ]


@router.get("/hosts/{asset_id}", response_model=HostDetail)
def get_host_detail(
    asset_id: int,
    current_user: User = Depends(require_permission("noc", "read")),
    db: Session = Depends(get_db),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    credential = NocService.get_credential(db, asset_id)
    status = NocService.get_status(db, asset_id)
    interfaces = NocService.get_interfaces(db, asset_id)

    return HostDetail(
        asset_id=asset.id,
        asset_name=asset.asset_name,
        ip_address=asset.ip_address,
        asset_type_name=asset.asset_type.type_name if asset.asset_type else None,
        credential=_credential_info(credential),
        reachable=status.reachable if status else None,
        sys_descr=status.sys_descr if status else None,
        sys_name=status.sys_name if status else None,
        sys_contact=status.sys_contact if status else None,
        sys_location=status.sys_location if status else None,
        sys_uptime_ticks=status.sys_uptime_ticks if status else None,
        error_message=status.error_message if status else None,
        last_polled_at=status.last_polled_at if status else None,
        interfaces=[InterfaceInfo.model_validate(i) for i in interfaces],
    )


@router.put("/hosts/{asset_id}/credential", response_model=SnmpCredentialInfo)
def set_host_credential(
    asset_id: int,
    request: SnmpCredentialSet,
    current_user: User = Depends(require_permission("noc", "write")),
    db: Session = Depends(get_db),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if request.version not in ("v2c", "v3"):
        raise HTTPException(status_code=400, detail="version must be 'v2c' or 'v3'")

    credential = NocService.set_credential(db, asset_id, request.model_dump(exclude_unset=True), current_user.id)
    return _credential_info(credential)


@router.delete("/hosts/{asset_id}/credential", status_code=204)
def delete_host_credential(
    asset_id: int,
    current_user: User = Depends(require_permission("noc", "delete")),
    db: Session = Depends(get_db),
):
    if not NocService.delete_credential(db, asset_id):
        raise HTTPException(status_code=404, detail="No SNMP credential configured for this asset")


@router.post("/hosts/{asset_id}/poll", response_model=PollNowResponse)
async def poll_host_now(
    asset_id: int,
    current_user: User = Depends(require_permission("noc", "write")),
    db: Session = Depends(get_db),
):
    try:
        status = await NocService.poll_one(db, asset_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return PollNowResponse(
        asset_id=asset_id,
        reachable=status.reachable,
        message="Reachable" if status.reachable else (status.error_message or "Unreachable"),
    )


@router.post("/poll-all", response_model=PollAllResponse)
async def poll_all_now(
    current_user: User = Depends(require_permission("noc", "write")),
    db: Session = Depends(get_db),
):
    count = await NocService.poll_all(db)
    return PollAllResponse(polled_count=count)


@router.get("/hosts/{asset_id}/metrics", response_model=MetricSeriesResponse)
def get_host_metrics(
    asset_id: int,
    metric: str = Query(..., description="e.g. reachable, if_in_octets, if_out_octets"),
    interface_id: Optional[int] = Query(None, description="Omit for a device-level metric like 'reachable'"),
    start: Optional[datetime] = Query(None, alias="from"),
    end: Optional[datetime] = Query(None, alias="to"),
    current_user: User = Depends(require_permission("noc", "read")),
    db: Session = Depends(get_db),
):
    """Backs the host detail page's time-range picker (1h/6h/24h/7d/30d/
    custom): the caller just asks for a window, and NocService.get_metric_series
    picks raw vs. the right rollup tier by how wide that window is - the
    caller never needs to know those tiers exist."""
    if metric not in VALID_METRICS:
        raise HTTPException(status_code=400, detail=f"metric must be one of: {', '.join(sorted(VALID_METRICS))}")

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    end = end or datetime.utcnow()
    start = start or (end - timedelta(hours=24))
    if start >= end:
        raise HTTPException(status_code=400, detail="'from' must be before 'to'")

    granularity, points = NocService.get_metric_series(db, asset_id, metric, start, end, interface_id)
    return MetricSeriesResponse(
        metric=metric,
        granularity=granularity,
        interface_id=interface_id,
        points=[MetricPoint(**p) for p in points],
    )
