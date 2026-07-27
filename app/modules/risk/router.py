"""
Risk & Exposure Intelligence API Router

All routes require JWT authentication. Access is governed by the RISK
module permission (read/write/delete), matching the codebase-wide
require_permission(module, type) pattern:
  view/export endpoints  -> RISK read
  calculate/edit/create  -> RISK write
  zone delete            -> RISK delete
Admins bypass permission checks as everywhere else.
"""
import csv
import io
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, get_db
from app.core.dependencies import require_permission
from app.models import User, log_action, log_asset_updated
from app.models.asset import Asset
from app.models.audit import AuditResult, CheckStatus
from app.models.risk import (
    AssetOpenPort,
    AssetRiskHistory,
    AssetRiskProfile,
    AssetRiskScore,
    RiskSetting,
    RiskZone,
)
from .schemas import (
    CRITICALITY_LEVELS,
    PORT_SEVERITIES,
    PortUpdateRequest,
    ProfileUpdateRequest,
    ZoneCreateRequest,
    ZoneUpdateRequest,
)
from .service import (
    DEFAULT_SETTINGS,
    recalculate_all,
    risk_calculation_service,
)

logger = logging.getLogger(__name__)

router = APIRouter()

WEIGHT_KEYS = ("criticality_weight", "zone_weight", "open_port_weight", "audit_weight")

SORTABLE_COLUMNS = {
    "final_risk_score": AssetRiskScore.final_risk_score,
    "risk_level": AssetRiskScore.risk_level,
    "criticality_score": AssetRiskScore.criticality_score,
    "zone_score": AssetRiskScore.zone_score,
    "open_port_score": AssetRiskScore.open_port_score,
    "audit_risk_score": AssetRiskScore.audit_risk_score,
    "open_ports_count": AssetRiskScore.open_ports_count,
    "calculated_at": AssetRiskScore.calculated_at,
    "asset_name": Asset.asset_name,
}


# ======================================================================
# Helpers
# ======================================================================

def _num(value):
    """Numeric/Decimal column value -> float (None-safe) for JSON."""
    return float(value) if value is not None else None


def _dt(value):
    return value.isoformat() if value is not None else None


def _score_to_dict(score: AssetRiskScore) -> dict:
    return {
        "asset_id": score.asset_id,
        "criticality_level": score.criticality_level,
        "criticality_score": _num(score.criticality_score),
        "criticality_weight": _num(score.criticality_weight),
        "criticality_contribution": _num(score.criticality_contribution),
        "zone_id": score.zone_id,
        "zone_name": score.zone_name,
        "zone_score": _num(score.zone_score),
        "zone_weight": _num(score.zone_weight),
        "zone_contribution": _num(score.zone_contribution),
        "open_port_raw_score": _num(score.open_port_raw_score),
        "open_port_score": _num(score.open_port_score),
        "open_port_weight": _num(score.open_port_weight),
        "open_port_contribution": _num(score.open_port_contribution),
        "audit_failed_weight": _num(score.audit_failed_weight),
        "audit_applicable_weight": _num(score.audit_applicable_weight),
        "audit_risk_score": _num(score.audit_risk_score),
        "audit_weight": _num(score.audit_weight),
        "audit_contribution": _num(score.audit_contribution),
        "final_risk_score": _num(score.final_risk_score),
        "risk_level": score.risk_level,
        "critical_findings_count": score.critical_findings_count,
        "high_findings_count": score.high_findings_count,
        "medium_findings_count": score.medium_findings_count,
        "low_findings_count": score.low_findings_count,
        "open_ports_count": score.open_ports_count,
        "risky_ports_count": score.risky_ports_count,
        "resolved_by_hardening_count": score.resolved_by_hardening_count,
        "active_audit_findings_count": score.active_audit_findings_count,
        "incomplete_data": score.incomplete_data,
        "incomplete_reasons": score.incomplete_reasons_json or [],
        "audit_id": score.audit_id,
        "calculated_at": _dt(score.calculated_at),
    }


def _port_to_dict(port: AssetOpenPort) -> dict:
    return {
        "id": port.id,
        "asset_id": port.asset_id,
        "ip_address": port.ip_address,
        "port": port.port,
        "protocol": port.protocol,
        "service_name": port.service_name,
        "severity": port.severity,
        "severity_score": port.severity_score,
        "status": port.status,
        "source": port.source,
        "first_seen_at": _dt(port.first_seen_at),
        "last_seen_at": _dt(port.last_seen_at),
        "is_approved": port.is_approved,
        "is_included_in_risk": port.is_included_in_risk,
        "exclusion_reason": port.exclusion_reason,
    }


def _zone_to_dict(zone: RiskZone) -> dict:
    return {
        "id": zone.id,
        "name": zone.name,
        "description": zone.description,
        "score": _num(zone.score),
        "status": zone.status,
        "created_at": _dt(zone.created_at),
        "updated_at": _dt(zone.updated_at),
    }


def _profile_to_dict(profile: AssetRiskProfile) -> dict:
    return {
        "asset_id": profile.asset_id,
        "criticality_level": profile.criticality_level,
        "criticality_score": _num(profile.criticality_score),
        "zone_id": profile.zone_id,
        "criticality_is_default": profile.criticality_is_default,
        "zone_is_default": profile.zone_is_default,
        "updated_at": _dt(profile.updated_at),
    }


def _history_to_dict(row: AssetRiskHistory) -> dict:
    return {
        "id": row.id,
        "asset_id": row.asset_id,
        "risk_score": _num(row.risk_score),
        "risk_level": row.risk_level,
        "criticality_score": _num(row.criticality_score),
        "zone_score": _num(row.zone_score),
        "open_port_score": _num(row.open_port_score),
        "audit_risk_score": _num(row.audit_risk_score),
        "criticality_contribution": _num(row.criticality_contribution),
        "zone_contribution": _num(row.zone_contribution),
        "open_port_contribution": _num(row.open_port_contribution),
        "audit_contribution": _num(row.audit_contribution),
        "audit_id": row.audit_id,
        "reason": row.reason,
        "calculated_at": _dt(row.calculated_at),
    }


def _get_asset_or_404(db: Session, asset_id: int) -> Asset:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


def _settings_dict(db: Session) -> Dict[str, Any]:
    """All risk settings as {key: typed value}."""
    out = {}
    for row in db.query(RiskSetting).order_by(RiskSetting.setting_key).all():
        raw = row.setting_value
        try:
            if row.value_type == "bool":
                out[row.setting_key] = str(raw).strip().lower() in ("true", "1", "yes")
            elif row.value_type == "int":
                out[row.setting_key] = int(float(raw))
            elif row.value_type == "float":
                out[row.setting_key] = float(raw)
            else:
                out[row.setting_key] = raw
        except (TypeError, ValueError):
            out[row.setting_key] = raw
    return out


def _criticality_score_for_level(db: Session, level: str) -> float:
    settings = _settings_dict(db)
    return float(
        settings.get(
            f"criticality_{level}_score",
            DEFAULT_SETTINGS[f"criticality_{level}_score"],
        )
    )


def _severity_score_for(db: Session, severity: str) -> int:
    settings = _settings_dict(db)
    return int(
        settings.get(
            f"severity_{severity}_weight",
            DEFAULT_SETTINGS[f"severity_{severity}_weight"],
        )
    )


def _build_scores_query(
    db: Session,
    search: Optional[str],
    risk_level: Optional[str],
    criticality: Optional[str],
    zone_id: Optional[int],
    min_score: Optional[float],
    max_score: Optional[float],
    incomplete_data: Optional[bool],
):
    """Shared filter logic for the list and CSV export endpoints."""
    rank = (
        func.row_number()
        .over(order_by=AssetRiskScore.final_risk_score.desc())
        .label("rank")
    )
    query = (
        db.query(AssetRiskScore, Asset, rank)
        .join(Asset, Asset.id == AssetRiskScore.asset_id)
    )
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                Asset.asset_name.ilike(pattern),
                Asset.hostname.ilike(pattern),
                Asset.ip_address.ilike(pattern),
            )
        )
    if risk_level:
        query = query.filter(AssetRiskScore.risk_level == risk_level)
    if criticality:
        query = query.filter(AssetRiskScore.criticality_level == criticality)
    if zone_id is not None:
        query = query.filter(AssetRiskScore.zone_id == zone_id)
    if min_score is not None:
        query = query.filter(AssetRiskScore.final_risk_score >= min_score)
    if max_score is not None:
        query = query.filter(AssetRiskScore.final_risk_score <= max_score)
    if incomplete_data is not None:
        query = query.filter(AssetRiskScore.incomplete_data.is_(incomplete_data))
    return query


def _list_item(score: AssetRiskScore, asset: Asset, rank: int) -> dict:
    return {
        "rank": rank,
        "asset_id": asset.id,
        "asset_name": asset.asset_name,
        "hostname": asset.hostname,
        "ip_address": asset.ip_address,
        "vendor": asset.manufacturer,
        "product": asset.os_name,
        "model": asset.model,
        "os_version": asset.os_version,
        "criticality_level": score.criticality_level,
        "criticality_score": _num(score.criticality_score),
        "zone_name": score.zone_name,
        "zone_score": _num(score.zone_score),
        "open_ports_count": score.open_ports_count,
        "open_port_score": _num(score.open_port_score),
        "audit_risk_score": _num(score.audit_risk_score),
        "active_audit_findings_count": score.active_audit_findings_count,
        "final_risk_score": _num(score.final_risk_score),
        "risk_level": score.risk_level,
        "incomplete_data": score.incomplete_data,
        "calculated_at": _dt(score.calculated_at),
    }


def _recalculate_zone_assets_background(zone_id: int):
    """Recalculate every asset assigned to a zone; runs with its own session."""
    db = SessionLocal()
    try:
        asset_ids = [
            row[0]
            for row in db.query(AssetRiskProfile.asset_id)
            .filter(AssetRiskProfile.zone_id == zone_id)
            .all()
        ]
        for asset_id in asset_ids:
            try:
                risk_calculation_service.calculate(
                    asset_id, db,
                    trigger_type="zone_updated",
                    trigger_reference_id=zone_id,
                )
            except Exception:
                continue  # per-asset errors are logged by the service
    finally:
        db.close()


async def _recalculate_all_background():
    """Bulk recalculation with its own session (request session is closed)."""
    db = SessionLocal()
    try:
        await recalculate_all(db)
    finally:
        db.close()


# ======================================================================
# Asset risk list / detail
# ======================================================================

@router.get("/assets")
def list_asset_risks(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    zone_id: Optional[int] = Query(None),
    min_score: Optional[float] = Query(None, ge=0, le=100),
    max_score: Optional[float] = Query(None, ge=0, le=100),
    sort_by: str = Query("final_risk_score"),
    sort_order: str = Query("desc"),
    incomplete_data: Optional[bool] = Query(None),
    _current_user: User = Depends(require_permission("RISK", "read")),
    db: Session = Depends(get_db),
):
    """Paginated, filterable asset risk ranking."""
    if sort_by not in SORTABLE_COLUMNS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sort_by; allowed: {', '.join(sorted(SORTABLE_COLUMNS))}",
        )
    query = _build_scores_query(
        db, search, risk_level, criticality, zone_id,
        min_score, max_score, incomplete_data,
    )
    total = query.count()

    column = SORTABLE_COLUMNS[sort_by]
    order = column.desc() if sort_order.lower() == "desc" else column.asc()
    rows = (
        query.order_by(order, AssetRiskScore.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [_list_item(score, asset, rank) for score, asset, rank in rows],
    }


@router.get("/assets/{asset_id}")
def get_asset_risk_detail(
    asset_id: int,
    _current_user: User = Depends(require_permission("RISK", "read")),
    db: Session = Depends(get_db),
):
    """Full risk breakdown for one asset."""
    asset = _get_asset_or_404(db, asset_id)
    score = (
        db.query(AssetRiskScore)
        .filter(AssetRiskScore.asset_id == asset_id)
        .first()
    )

    ports = (
        db.query(AssetOpenPort)
        .filter(AssetOpenPort.asset_id == asset_id)
        .order_by(AssetOpenPort.severity_score.desc(), AssetOpenPort.port)
        .all()
    )
    history = (
        db.query(AssetRiskHistory)
        .filter(AssetRiskHistory.asset_id == asset_id)
        .order_by(AssetRiskHistory.calculated_at.desc())
        .limit(10)
        .all()
    )

    audit_summary = None
    if score is not None and score.audit_id is not None:
        applicable = (
            db.query(func.count(AuditResult.id))
            .filter(AuditResult.session_id == score.audit_id,
                    AuditResult.status.in_([CheckStatus.PASS, CheckStatus.FAIL]))
            .scalar()
        ) or 0
        passed = (
            db.query(func.count(AuditResult.id))
            .filter(AuditResult.session_id == score.audit_id,
                    AuditResult.status == CheckStatus.PASS)
            .scalar()
        ) or 0
        audit_summary = {
            "audit_session_id": score.audit_id,
            "total_applicable": applicable,
            "passed": passed,
            "active_failed": score.active_audit_findings_count,
            "resolved_by_hardening": score.resolved_by_hardening_count,
        }

    return {
        "asset": {
            "id": asset.id,
            "name": asset.asset_name,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "vendor": asset.manufacturer,
            "product": asset.os_name,
            "model": asset.model,
            "os_version": asset.os_version,
            "status": asset.status.value if asset.status else None,
        },
        "risk_score": _score_to_dict(score) if score else None,
        "open_ports": [_port_to_dict(p) for p in ports],
        "audit_summary": audit_summary,
        "history": [_history_to_dict(h) for h in history],
        "incomplete_data": score.incomplete_data if score else True,
        "incomplete_reasons": (score.incomplete_reasons_json or []) if score
                              else ["not_calculated"],
    }


# ======================================================================
# Calculation
# ======================================================================

@router.post("/assets/{asset_id}/calculate")
def calculate_asset_risk(
    asset_id: int,
    _current_user: User = Depends(require_permission("RISK", "write")),
    db: Session = Depends(get_db),
):
    """Recalculate one asset's risk score now."""
    try:
        score = risk_calculation_service.calculate(
            asset_id, db, trigger_type="manual"
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return _score_to_dict(score)


@router.post("/recalculate-all")
def recalculate_all_assets(
    background_tasks: BackgroundTasks,
    _current_user: User = Depends(require_permission("RISK", "write")),
):
    """Kick off a background recalculation for all active assets."""
    background_tasks.add_task(_recalculate_all_background)
    return {
        "status": "started",
        "message": "Recalculation started for all active assets",
    }


# ======================================================================
# Asset profile (criticality + zone)
# ======================================================================

@router.get("/assets/{asset_id}/profile")
def get_asset_profile(
    asset_id: int,
    _current_user: User = Depends(require_permission("RISK", "read")),
    db: Session = Depends(get_db),
):
    """Asset risk profile; unsaved defaults when none exists yet."""
    _get_asset_or_404(db, asset_id)
    profile = (
        db.query(AssetRiskProfile)
        .filter(AssetRiskProfile.asset_id == asset_id)
        .first()
    )
    if profile is None:
        return {
            "asset_id": asset_id,
            "criticality_level": "medium",
            "criticality_score": 50.0,
            "zone_id": None,
            "criticality_is_default": True,
            "zone_is_default": True,
            "updated_at": None,
        }
    return _profile_to_dict(profile)


@router.put("/assets/{asset_id}/profile")
def update_asset_profile(
    asset_id: int,
    data: ProfileUpdateRequest,
    current_user: User = Depends(require_permission("RISK", "write")),
    db: Session = Depends(get_db),
):
    """Set criticality and/or zone, then recalculate the risk score."""
    asset = _get_asset_or_404(db, asset_id)

    if data.criticality_level is not None \
            and data.criticality_level not in CRITICALITY_LEVELS:
        raise HTTPException(
            status_code=400,
            detail=f"criticality_level must be one of: {', '.join(CRITICALITY_LEVELS)}",
        )
    if data.zone_id is not None:
        zone = db.query(RiskZone).filter(RiskZone.id == data.zone_id).first()
        if zone is None:
            raise HTTPException(status_code=400, detail="Zone not found")

    profile = (
        db.query(AssetRiskProfile)
        .filter(AssetRiskProfile.asset_id == asset_id)
        .first()
    )
    if profile is None:
        profile = AssetRiskProfile(
            asset_id=asset_id,
            criticality_level="medium",
            criticality_score=50,
            created_by=current_user.id,
        )
        db.add(profile)

    changes = {}
    if data.criticality_level is not None:
        changes["criticality_level"] = data.criticality_level
        profile.criticality_level = data.criticality_level
        profile.criticality_score = _criticality_score_for_level(
            db, data.criticality_level
        )
        profile.criticality_is_default = False
    if "zone_id" in data.model_fields_set:
        changes["zone_id"] = data.zone_id
        profile.zone_id = data.zone_id
        profile.zone_is_default = False
    if data.reason:
        changes["reason"] = data.reason

    profile.updated_by = current_user.id
    db.commit()

    log_asset_updated(
        db, current_user.id, asset_id, asset.asset_name,
        changes={f"risk_profile.{k}": v for k, v in changes.items()},
        ip_address=asset.ip_address,
    )

    score = risk_calculation_service.calculate(
        asset_id, db, trigger_type="profile_updated"
    )
    return {
        "profile": _profile_to_dict(profile),
        "risk_score": _score_to_dict(score),
    }


# ======================================================================
# Zones
# ======================================================================

@router.get("/zones")
def list_zones(
    _current_user: User = Depends(require_permission("RISK", "read")),
    db: Session = Depends(get_db),
):
    """All active zones ordered by score."""
    zones = (
        db.query(RiskZone)
        .filter(RiskZone.status == "active")
        .order_by(RiskZone.score)
        .all()
    )
    return [_zone_to_dict(z) for z in zones]


@router.post("/zones", status_code=201)
def create_zone(
    data: ZoneCreateRequest,
    current_user: User = Depends(require_permission("RISK", "write")),
    db: Session = Depends(get_db),
):
    exists = db.query(RiskZone).filter(RiskZone.name == data.name).first()
    if exists:
        raise HTTPException(status_code=400, detail="Zone name already exists")

    zone = RiskZone(
        name=data.name,
        description=data.description,
        score=data.score,
        status="active",
        created_by=current_user.id,
        updated_by=current_user.id,
    )
    db.add(zone)
    db.commit()
    db.refresh(zone)
    log_action(
        db, user_id=current_user.id, username=current_user.username,
        action="risk.zone.create", module="risk", target_id=zone.id,
        detail=f"Created zone '{zone.name}' (score={data.score})",
    )
    return _zone_to_dict(zone)


@router.put("/zones/{zone_id}")
def update_zone(
    zone_id: int,
    data: ZoneUpdateRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_permission("RISK", "write")),
    db: Session = Depends(get_db),
):
    zone = db.query(RiskZone).filter(RiskZone.id == zone_id).first()
    if zone is None:
        raise HTTPException(status_code=404, detail="Zone not found")

    if data.name is not None and data.name != zone.name:
        clash = (
            db.query(RiskZone)
            .filter(RiskZone.name == data.name, RiskZone.id != zone_id)
            .first()
        )
        if clash:
            raise HTTPException(status_code=400, detail="Zone name already exists")

    score_changed = (
        data.score is not None and float(zone.score) != float(data.score)
    )
    changes = {}
    if data.name is not None:
        changes["name"] = data.name
        zone.name = data.name
    if "description" in data.model_fields_set:
        changes["description"] = data.description
        zone.description = data.description
    if data.score is not None:
        changes["score"] = data.score
        zone.score = data.score

    zone.updated_by = current_user.id
    db.commit()
    db.refresh(zone)
    log_action(
        db, user_id=current_user.id, username=current_user.username,
        action="risk.zone.update", module="risk", target_id=zone.id,
        detail=f"Updated zone '{zone.name}': {changes}",
    )

    if score_changed:
        background_tasks.add_task(_recalculate_zone_assets_background, zone_id)

    return {
        "zone": _zone_to_dict(zone),
        "recalculation_triggered": score_changed,
    }


@router.delete("/zones/{zone_id}")
def delete_zone(
    zone_id: int,
    current_user: User = Depends(require_permission("RISK", "delete")),
    db: Session = Depends(get_db),
):
    zone = db.query(RiskZone).filter(RiskZone.id == zone_id).first()
    if zone is None:
        raise HTTPException(status_code=404, detail="Zone not found")

    assigned = (
        db.query(func.count(AssetRiskProfile.id))
        .filter(AssetRiskProfile.zone_id == zone_id)
        .scalar()
    ) or 0
    if assigned > 0:
        raise HTTPException(
            status_code=400, detail="Cannot delete zone with assigned assets"
        )

    zone_name = zone.name
    db.delete(zone)
    db.commit()
    log_action(
        db, user_id=current_user.id, username=current_user.username,
        action="risk.zone.delete", module="risk", target_id=zone_id,
        detail=f"Deleted zone '{zone_name}'",
    )
    return {"message": "Deleted successfully"}


# ======================================================================
# Ports
# ======================================================================

@router.get("/assets/{asset_id}/ports")
def list_asset_ports(
    asset_id: int,
    _current_user: User = Depends(require_permission("RISK", "read")),
    db: Session = Depends(get_db),
):
    _get_asset_or_404(db, asset_id)
    ports = (
        db.query(AssetOpenPort)
        .filter(AssetOpenPort.asset_id == asset_id)
        .order_by(AssetOpenPort.severity_score.desc(), AssetOpenPort.port)
        .all()
    )
    return [_port_to_dict(p) for p in ports]


@router.put("/ports/{port_id}")
def update_port(
    port_id: int,
    data: PortUpdateRequest,
    current_user: User = Depends(require_permission("RISK", "write")),
    db: Session = Depends(get_db),
):
    port = db.query(AssetOpenPort).filter(AssetOpenPort.id == port_id).first()
    if port is None:
        raise HTTPException(status_code=404, detail="Port not found")

    if data.severity is not None and data.severity not in PORT_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail=f"severity must be one of: {', '.join(PORT_SEVERITIES)}",
        )

    changes = {}
    if data.severity is not None:
        changes["severity"] = data.severity
        port.severity = data.severity
        port.severity_score = _severity_score_for(db, data.severity)
    if data.is_approved is not None:
        changes["is_approved"] = data.is_approved
        port.is_approved = data.is_approved
    if data.is_included_in_risk is not None:
        changes["is_included_in_risk"] = data.is_included_in_risk
        port.is_included_in_risk = data.is_included_in_risk
    if "exclusion_reason" in data.model_fields_set:
        changes["exclusion_reason"] = data.exclusion_reason
        port.exclusion_reason = data.exclusion_reason

    port.updated_by = current_user.id
    db.commit()
    db.refresh(port)

    asset = db.query(Asset).filter(Asset.id == port.asset_id).first()
    log_asset_updated(
        db, current_user.id, port.asset_id,
        asset.asset_name if asset else None,
        changes={f"risk_port_{port.port}/{port.protocol}.{k}": v
                 for k, v in changes.items()},
        ip_address=port.ip_address,
    )

    score = risk_calculation_service.calculate(
        port.asset_id, db, trigger_type="port_updated", trigger_reference_id=port_id
    )
    return {
        "port": _port_to_dict(port),
        "risk_score": _score_to_dict(score),
    }


# ======================================================================
# Settings
# ======================================================================

@router.get("/settings")
def get_settings(
    _current_user: User = Depends(require_permission("RISK", "read")),
    db: Session = Depends(get_db),
):
    return _settings_dict(db)


@router.put("/settings")
def update_settings(
    updates: Dict[str, Any],
    current_user: User = Depends(require_permission("RISK", "write")),
    db: Session = Depends(get_db),
):
    """Partial update of risk settings. Factor weights must keep summing to 100."""
    if not updates:
        raise HTTPException(status_code=400, detail="No settings provided")

    rows = {
        row.setting_key: row
        for row in db.query(RiskSetting).all()
    }
    unknown = [key for key in updates if key not in rows]
    if unknown:
        raise HTTPException(
            status_code=400, detail=f"Unknown settings: {', '.join(sorted(unknown))}"
        )
    readonly = [key for key in updates if not rows[key].is_editable]
    if readonly:
        raise HTTPException(
            status_code=400,
            detail=f"Settings not editable: {', '.join(sorted(readonly))}",
        )

    # Validate numeric/bool values parse according to their declared type
    for key, value in updates.items():
        value_type = rows[key].value_type
        try:
            if value_type in ("int", "float"):
                float(value)
            elif value_type == "bool" and not isinstance(value, bool):
                if str(value).strip().lower() not in ("true", "false", "0", "1"):
                    raise ValueError
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid value for {key}: expected {value_type}",
            )

    # CRITICAL: the four factor weights must sum to 100 after the update
    if any(key in WEIGHT_KEYS for key in updates):
        merged = {}
        for key in WEIGHT_KEYS:
            merged[key] = float(updates.get(key, rows[key].setting_value))
        total = sum(merged.values())
        if abs(total - 100.0) > 0.001:
            raise HTTPException(
                status_code=400,
                detail=f"Factor weights must sum to 100 (got {total:g}): {merged}",
            )

    for key, value in updates.items():
        row = rows[key]
        row.setting_value = str(value).lower() if isinstance(value, bool) else str(value)
        row.updated_by = current_user.id
    db.commit()

    log_action(
        db, user_id=current_user.id, username=current_user.username,
        action="risk.settings.update", module="risk",
        detail=f"Updated risk settings: {sorted(updates.keys())}",
    )
    return _settings_dict(db)


# ======================================================================
# History
# ======================================================================

@router.get("/assets/{asset_id}/history")
def get_asset_history(
    asset_id: int,
    limit: int = Query(30, ge=1, le=500),
    _current_user: User = Depends(require_permission("RISK", "read")),
    db: Session = Depends(get_db),
):
    _get_asset_or_404(db, asset_id)
    history = (
        db.query(AssetRiskHistory)
        .filter(AssetRiskHistory.asset_id == asset_id)
        .order_by(AssetRiskHistory.calculated_at.desc())
        .limit(limit)
        .all()
    )
    return [_history_to_dict(h) for h in history]


# ======================================================================
# Exports
# ======================================================================

CSV_COLUMNS = [
    "Rank", "Asset Name", "IP Address", "Vendor", "Product", "Model", "Version",
    "Criticality", "Criticality Score", "Zone", "Zone Score", "Open Ports Count",
    "Open Port Score", "Critical Findings", "High Findings", "Medium Findings",
    "Low Findings", "Audit Risk Score", "Risk Score", "Risk Level",
    "Last Audit Date", "Last Calculation Date", "Incomplete Data",
]


@router.get("/export/csv")
def export_csv(
    search: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    criticality: Optional[str] = Query(None),
    zone_id: Optional[int] = Query(None),
    min_score: Optional[float] = Query(None, ge=0, le=100),
    max_score: Optional[float] = Query(None, ge=0, le=100),
    incomplete_data: Optional[bool] = Query(None),
    _current_user: User = Depends(require_permission("RISK", "read")),
    db: Session = Depends(get_db),
):
    """CSV of the (filtered) full risk ranking."""
    rows = (
        _build_scores_query(
            db, search, risk_level, criticality, zone_id,
            min_score, max_score, incomplete_data,
        )
        .order_by(AssetRiskScore.final_risk_score.desc(), AssetRiskScore.id)
        .all()
    )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_COLUMNS)
    for score, asset, rank in rows:
        writer.writerow([
            rank,
            asset.asset_name,
            asset.ip_address,
            asset.manufacturer,
            asset.os_name,
            asset.model,
            asset.os_version,
            score.criticality_level,
            _num(score.criticality_score),
            score.zone_name,
            _num(score.zone_score),
            score.open_ports_count,
            _num(score.open_port_score),
            score.critical_findings_count,
            score.high_findings_count,
            score.medium_findings_count,
            score.low_findings_count,
            _num(score.audit_risk_score),
            _num(score.final_risk_score),
            score.risk_level,
            _dt(asset.last_audit_date),
            _dt(score.calculated_at),
            score.incomplete_data,
        ])
    buffer.seek(0)

    filename = f"risk_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/assets/{asset_id}/export/json")
def export_asset_json(
    asset_id: int,
    _current_user: User = Depends(require_permission("RISK", "read")),
    db: Session = Depends(get_db),
):
    """Single-asset risk export (spec section 27 structure)."""
    asset = _get_asset_or_404(db, asset_id)
    score = (
        db.query(AssetRiskScore)
        .filter(AssetRiskScore.asset_id == asset_id)
        .first()
    )
    if score is None:
        raise HTTPException(
            status_code=404, detail="Risk score not calculated for this asset"
        )

    return {
        "asset": {
            "id": asset.id,
            "name": asset.asset_name,
            "ip_address": asset.ip_address,
            "vendor": asset.manufacturer,
            "product": asset.os_name,
        },
        "risk": {
            "score": _num(score.final_risk_score),
            "level": score.risk_level,
            "calculated_at": _dt(score.calculated_at),
            "incomplete_data": score.incomplete_data,
        },
        "components": {
            "criticality": {
                "level": score.criticality_level,
                "score": _num(score.criticality_score),
                "weight": _num(score.criticality_weight),
                "contribution": _num(score.criticality_contribution),
            },
            "zone": {
                "name": score.zone_name,
                "score": _num(score.zone_score),
                "weight": _num(score.zone_weight),
                "contribution": _num(score.zone_contribution),
            },
            "open_ports": {
                "count": score.open_ports_count,
                "raw_score": _num(score.open_port_raw_score),
                "score": _num(score.open_port_score),
                "weight": _num(score.open_port_weight),
                "contribution": _num(score.open_port_contribution),
            },
            "audit": {
                "applicable_weight": _num(score.audit_applicable_weight),
                "failed_weight": _num(score.audit_failed_weight),
                "score": _num(score.audit_risk_score),
                "weight": _num(score.audit_weight),
                "contribution": _num(score.audit_contribution),
            },
        },
    }
