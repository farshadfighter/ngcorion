"""
CVE Router

Per-asset and organization-wide vulnerability findings, the known-CVE
catalog, and an admin-triggered NVD sync.
"""
import logging
import requests
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, Asset
from app.modules.cve.service import CveService
from app.modules.cve.schemas import (
    CveFindingsResponse,
    CveRecordSummary,
    CveSyncResponse,
    CveSyncRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cve", tags=["CVE"])


@router.get("/findings", response_model=CveFindingsResponse)
def get_all_findings(
    current_user: User = Depends(require_permission("cve", "read")),
    db: Session = Depends(get_db),
):
    return CveService.get_findings(db)


@router.get("/findings/{asset_id}", response_model=CveFindingsResponse)
def get_asset_findings(
    asset_id: int,
    current_user: User = Depends(require_permission("cve", "read")),
    db: Session = Depends(get_db),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return CveService.get_findings(db, asset_id=asset_id)


@router.get("/records", response_model=list[CveRecordSummary])
def list_records(
    current_user: User = Depends(require_permission("cve", "read")),
    db: Session = Depends(get_db),
):
    return CveService.list_records(db)


@router.post("/sync", response_model=CveSyncResponse)
def sync_from_nvd(
    request: CveSyncRequest = CveSyncRequest(),
    current_user: User = Depends(require_permission("cve", "write")),
    db: Session = Depends(get_db),
):
    try:
        return CveService.sync_from_nvd(db, product_keyword=request.product_keyword)
    except requests.RequestException as exc:
        logger.warning("NVD sync request failed: %s", exc)
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach the NVD API from this server: {exc}",
        )
