"""
Architecture Validation Router

Runs the rule engine over every asset and manages the resulting findings
(open -> accepted | ignored).
"""
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User, Asset
from app.modules.architecture_validation.service import ArchitectureValidationService
from app.modules.architecture_validation.schemas import (
    ArchitectureFindingSummary,
    AnalyzeResult,
    ResolveFindingRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/architecture-validation", tags=["Architecture Validation"])


@router.post("/analyze", response_model=AnalyzeResult)
def analyze(
    current_user: User = Depends(require_permission("architecture_validation", "write")),
    db: Session = Depends(get_db),
):
    """Re-run every rule against every asset."""
    findings = ArchitectureValidationService.analyze(db)
    asset_count = db.query(Asset).count()
    return AnalyzeResult(findings=findings, asset_count=asset_count, finding_count=len(findings))


@router.get("/findings", response_model=list[ArchitectureFindingSummary])
def list_findings(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    current_user: User = Depends(require_permission("architecture_validation", "read")),
    db: Session = Depends(get_db),
):
    return ArchitectureValidationService.get_findings(db, status=status, severity=severity)


@router.post("/findings/{finding_id}/accept", response_model=ArchitectureFindingSummary)
def accept_finding(
    finding_id: int,
    current_user: User = Depends(require_permission("architecture_validation", "write")),
    db: Session = Depends(get_db),
):
    """Mark a finding as accepted (acknowledged, no further action planned)."""
    finding = ArchitectureValidationService.get_finding(db, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return ArchitectureValidationService.resolve_finding(db, finding, "accepted", current_user.id)


@router.post("/findings/{finding_id}/ignore", response_model=ArchitectureFindingSummary)
def ignore_finding(
    finding_id: int,
    request: ResolveFindingRequest,
    current_user: User = Depends(require_permission("architecture_validation", "write")),
    db: Session = Depends(get_db),
):
    """Mark a finding as ignored, with an optional reason."""
    finding = ArchitectureValidationService.get_finding(db, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return ArchitectureValidationService.resolve_finding(db, finding, "ignored", current_user.id, request.reason)
