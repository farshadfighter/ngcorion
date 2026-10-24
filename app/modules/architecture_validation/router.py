"""
Architecture Validation Router

Checks the topology against Cisco SAFE (rules/safe.yaml) for every asset and
manages the resulting findings (open -> accepted | ignored).
"""
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, Asset
from app.modules.architecture_validation.service import ArchitectureValidationService
from app.modules.architecture_validation.schemas import (
    ArchitectureFindingSummary,
    AnalyzeResult,
    ResolveFindingRequest,
    RuleInfo,
)
from app.modules.architecture_validation.engine import load_rules

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


@router.get("/rules", response_model=list[RuleInfo])
def list_rules(
    current_user: User = Depends(require_permission("architecture_validation", "read")),
):
    """What is checked: every rule of the set, with its SAFE domain and place."""
    return [RuleInfo(**{k: r.get(k) for k in RuleInfo.model_fields}) for r in load_rules()]


@router.get("/findings", response_model=list[ArchitectureFindingSummary])
def list_findings(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    current_user: User = Depends(require_permission("architecture_validation", "read")),
    db: Session = Depends(get_db),
):
    """Architecture findings, optionally by status and severity."""
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
