"""
Drift Router

Analyzes one asset's live configuration against its most recent backup and
manages the resulting drift findings (open -> accepted | ignored).
"""
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User, Asset
from app.modules.drift.service import DriftService
from app.modules.drift.schemas import (
    DriftRunSummary,
    DriftResultSummary,
    DriftResultDetail,
    AnalyzeAssetRequest,
    ResolveResultRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/drift", tags=["Configuration Drift"])


@router.post("/analyze", response_model=DriftRunSummary)
def analyze(
    request: AnalyzeAssetRequest,
    current_user: User = Depends(require_permission("drift", "write")),
    db: Session = Depends(get_db),
):
    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return DriftService.analyze_asset(
        db, asset,
        username=request.ssh_username, password=request.ssh_password,
        secret=request.ssh_secret, port=request.ssh_port,
        user_id=current_user.id,
    )


@router.get("/runs", response_model=list[DriftRunSummary])
def list_runs(
    current_user: User = Depends(require_permission("drift", "read")),
    db: Session = Depends(get_db),
):
    return DriftService.list_runs(db)


@router.get("/results", response_model=list[DriftResultSummary])
def list_results(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    current_user: User = Depends(require_permission("drift", "read")),
    db: Session = Depends(get_db),
):
    return DriftService.list_results(db, status=status, severity=severity)


@router.get("/results/{result_id}", response_model=DriftResultDetail)
def get_result(
    result_id: int,
    current_user: User = Depends(require_permission("drift", "read")),
    db: Session = Depends(get_db),
):
    result = DriftService.get_result(db, result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Drift result not found")
    return result


@router.post("/results/{result_id}/accept", response_model=DriftResultSummary)
def accept_result(
    result_id: int,
    current_user: User = Depends(require_permission("drift", "write")),
    db: Session = Depends(get_db),
):
    result = DriftService.get_result(db, result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Drift result not found")
    return DriftService.resolve_result(db, result, "accepted", current_user.id)


@router.post("/results/{result_id}/ignore", response_model=DriftResultSummary)
def ignore_result(
    result_id: int,
    request: ResolveResultRequest,
    current_user: User = Depends(require_permission("drift", "write")),
    db: Session = Depends(get_db),
):
    result = DriftService.get_result(db, result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Drift result not found")
    return DriftService.resolve_result(db, result, "ignored", current_user.id, request.reason)
