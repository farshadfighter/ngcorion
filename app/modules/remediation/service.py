"""
Remediation tracking: keeps one RemediationItem per problem that any module
reports, and applies risk acceptances to them.

  sync()                 the heart of the module. Collects what CVE findings,
                         the latest completed audit of each asset and the
                         architecture findings report right now, then creates,
                         updates, resolves and reopens items to match. Run by
                         the background worker (engine.py) and right after an
                         acceptance is decided.
  request_acceptance()   create a pending risk acceptance for an item.
  decide_acceptance()    approve or reject; never by the requester.
  end_acceptance()       revoke an approved acceptance.

An item is only ever "resolved" here, by the sync, when its source stops
reporting the problem: marking it fixed by hand only moves it to
"pending_verification".
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Asset, User
from app.models.architecture_finding import ArchitectureFinding
from app.models.asset_owners import AssetOwner
from app.models.audit import AuditResult, AuditSession, CheckStatus
from app.models.hardening import HardeningAction
from app.models.remediation import (ACCEPT_APPROVED, ACCEPT_EXPIRED, ACCEPT_PENDING, ACCEPT_REJECTED,
                                    ACCEPT_REVOKED, ITEM_ACCEPTED, ITEM_ACTIVE, ITEM_IN_PROGRESS, ITEM_OPEN,
                                    ITEM_PENDING, ITEM_RESOLVED, SCOPE_ITEM, SCOPE_REF, SEVERITIES,
                                    RemediationEvent, RemediationItem, RiskAcceptance)
from app.models.system_config import SECTION_REMEDIATION, SystemConfigSetting
from app.models.user import UserRole

logger = logging.getLogger(__name__)

# Days to fix, from the first time a problem is seen (KEV = known exploited).
DEFAULT_SLA = {"kev": 7, "critical": 15, "high": 30, "medium": 90, "low": 180}
# Longest a risk acceptance may last.
DEFAULT_ACCEPT_MAX = {"kev": 30, "critical": 30, "high": 90, "medium": 180, "low": 365}
SLA_KEYS = ("kev",) + SEVERITIES


class RemediationError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ──────────────────────────────────────────────────────────────────────────
# Settings
# ──────────────────────────────────────────────────────────────────────────

def get_settings(db: Session) -> Dict[str, Dict[str, int]]:
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION_REMEDIATION).first()
    stored = (row.config_json or {}) if row else {}
    sla = {k: int((stored.get("sla") or {}).get(k, v)) for k, v in DEFAULT_SLA.items()}
    accept_max = {k: int((stored.get("accept_max") or {}).get(k, v)) for k, v in DEFAULT_ACCEPT_MAX.items()}
    return {"sla": sla, "accept_max": accept_max}


def save_settings(db: Session, payload: Dict[str, Dict[str, int]], user: User) -> Dict:
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION_REMEDIATION).first()
    if row is None:
        row = SystemConfigSetting(section=SECTION_REMEDIATION)
        db.add(row)
    row.config_json = {"sla": dict(payload["sla"]), "accept_max": dict(payload["accept_max"])}
    row.updated_by = user.id
    db.commit()
    return get_settings(db)


def _band(severity: str, kev: bool) -> str:
    return "kev" if kev else (severity if severity in SEVERITIES else "medium")


def sla_due(first_seen: datetime, severity: str, kev: bool, settings: Dict) -> datetime:
    return first_seen + timedelta(days=settings["sla"][_band(severity, kev)])


def accept_max_days(severity: str, kev: bool, settings: Dict) -> int:
    return settings["accept_max"][_band(severity, kev)]


# ──────────────────────────────────────────────────────────────────────────
# What the modules report right now
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class Found:
    key: str
    source: str
    ref: str
    asset: Asset
    title: str
    severity: str
    kev: bool = False
    detail: Dict = field(default_factory=dict)
    hardened: bool = False          # audit: a successful hardening ran for it
    source_accepted: bool = False   # arch: accepted or ignored on its own page


def _severity(value: Optional[str]) -> str:
    v = (value or "").strip().lower()
    if v in SEVERITIES:
        return v
    if v in ("very_high",):
        return "critical"
    if v in ("info", "informational", "none"):
        return "low"
    return "medium"


def _cve_found(db: Session) -> Optional[List[Found]]:
    """None when the CVE database is not loaded: CVE items are then left as they are."""
    from app.modules.cve import findings as cve_findings
    from app.modules.cve import settings as cve_settings
    if cve_settings.get(db, cve_settings.WATERMARK) is None:
        return None
    assets = {a.id: a for a in db.query(Asset)}
    out = []
    for f in cve_findings.compute(db)["findings"]:
        asset = assets.get(f["asset_id"])
        if asset is None:
            continue
        severity = _severity(f.get("severity"))
        if not f.get("severity") and f.get("cvss") is not None:
            cvss = f["cvss"]
            severity = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
        out.append(Found(
            key=f"cve:{asset.id}:{f['cve_id']}", source="cve", ref=f["cve_id"], asset=asset,
            title=(f.get("description") or f["cve_id"])[:500], severity=severity, kev=bool(f.get("kev")),
            detail={"product": f.get("product"), "installed": f.get("installed"), "fixed_in": f.get("fixed_in"),
                    "cvss": f.get("cvss"), "epss": f.get("epss"), "priority": f.get("priority")},
        ))
    return out


def _latest_completed_sessions(db: Session) -> Dict[int, AuditSession]:
    latest: Dict[int, AuditSession] = {}
    for s in (db.query(AuditSession)
              .filter(AuditSession.status == "completed", AuditSession.asset_id.isnot(None))
              .order_by(AuditSession.started_at.desc(), AuditSession.id.desc())):
        latest.setdefault(s.asset_id, s)
    return latest


def _audit_found(db: Session) -> Tuple[List[Found], Set[int]]:
    """Failed checks of each asset's latest completed audit, and the assets that have one."""
    sessions = _latest_completed_sessions(db)
    if not sessions:
        return [], set()
    assets = {a.id: a for a in db.query(Asset).filter(Asset.id.in_(list(sessions)))}
    by_session = {s.id: s for s in sessions.values()}
    hardened = {aid for (aid,) in db.query(HardeningAction.audit_result_id)
                .filter(HardeningAction.status == "success", HardeningAction.action_type != "preview",
                        HardeningAction.audit_session_id.in_(list(by_session)))}
    out = []
    for r in (db.query(AuditResult)
              .filter(AuditResult.session_id.in_(list(by_session)), AuditResult.status == CheckStatus.FAIL)):
        session = by_session[r.session_id]
        asset = assets.get(session.asset_id)
        if asset is None:
            continue
        check = r.check_number or str(r.check_id or r.id)
        vdom = (r.vdom or "").strip()
        key = f"audit:{asset.id}:{check}" + (f":{vdom}" if vdom and vdom.lower() != "global" else "")
        out.append(Found(
            key=key, source="audit", ref=check, asset=asset, title=(r.check_title or check)[:500],
            severity=_severity(r.severity), hardened=r.id in hardened,
            detail={"check_number": check, "vdom": r.vdom, "level": r.level, "device_type": session.device_type,
                    "session_id": session.id, "result_id": r.id,
                    "evidence": (r.evidence_snippet or "")[:400] or None},
        ))
    return out, set(sessions)


def _arch_found(db: Session) -> List[Found]:
    assets = {a.id: a for a in db.query(Asset)}
    out = []
    for f in db.query(ArchitectureFinding).filter(ArchitectureFinding.asset_id.isnot(None)):
        asset = assets.get(f.asset_id)
        if asset is None:
            continue
        out.append(Found(
            key=f"arch:{asset.id}:{f.rule_code}", source="arch", ref=f.rule_code, asset=asset,
            title=f.title, severity=_severity(f.severity), source_accepted=f.status in ("accepted", "ignored"),
            detail={"rule_code": f.rule_code, "category": f.category, "recommendation": f.recommendation,
                    "finding_id": f.id, "source_status": f.status},
        ))
    return out


# ──────────────────────────────────────────────────────────────────────────
# Sync
# ──────────────────────────────────────────────────────────────────────────

def _event(db: Session, item: RemediationItem, kind: str, user_id: Optional[int] = None,
           at: Optional[datetime] = None, **data) -> None:
    db.add(RemediationEvent(item_id=item.id, kind=kind, user_id=user_id, at=at or datetime.utcnow(),
                            data=data or None))


def _owner_map(db: Session) -> Dict[int, int]:
    """asset id -> user id, where the asset owner's email is a user's email."""
    users = {e.lower(): uid for uid, e in db.query(User.id, User.email).filter(User.email.isnot(None),
                                                                               User.is_active.is_(True))}
    out = {}
    for asset_id, email in (db.query(Asset.id, AssetOwner.email)
                            .join(AssetOwner, AssetOwner.id == Asset.owner_id)
                            .filter(AssetOwner.email.isnot(None))):
        uid = users.get(email.strip().lower())
        if uid:
            out[asset_id] = uid
    return out


def _active_acceptances(db: Session, now: datetime) -> Tuple[Dict[int, RiskAcceptance], Dict[Tuple[str, str], RiskAcceptance]]:
    by_item, by_ref = {}, {}
    for a in db.query(RiskAcceptance).filter(RiskAcceptance.status == ACCEPT_APPROVED):
        if a.expires_at <= now:
            continue
        if a.scope == SCOPE_ITEM and a.item_id:
            by_item[a.item_id] = a
        elif a.scope == SCOPE_REF:
            by_ref[(a.source, a.ref)] = a
    return by_item, by_ref


def _expire_acceptances(db: Session, now: datetime) -> List[RiskAcceptance]:
    expired = (db.query(RiskAcceptance)
               .filter(RiskAcceptance.status == ACCEPT_APPROVED, RiskAcceptance.expires_at <= now).all())
    for a in expired:
        a.status = ACCEPT_EXPIRED
        a.ended_at = now
    return expired


def sync(db: Session, now: Optional[datetime] = None) -> Dict[str, int]:
    """Bring remediation_items in line with what the modules report. Commits."""
    now = now or datetime.utcnow()
    settings = get_settings(db)
    stats = defaultdict(int)

    found: List[Found] = []
    checked: Set[str] = set()
    cve = _cve_found(db)
    if cve is not None:
        found += cve
        checked.add("cve")
    audit, audited_assets = _audit_found(db)
    found += audit
    checked.add("audit")
    found += _arch_found(db)
    checked.add("arch")

    expired = _expire_acceptances(db, now)
    by_item_acc, by_ref_acc = _active_acceptances(db, now)
    owners = _owner_map(db)
    existing = {i.key: i for i in db.query(RemediationItem)}
    touched_assets: Set[int] = set()
    seen_keys = set()

    for f in found:
        if f.key in seen_keys:
            continue
        seen_keys.add(f.key)
        item = existing.get(f.key)
        if item is None:
            item = RemediationItem(
                key=f.key, source=f.source, ref=f.ref, asset_id=f.asset.id, asset_name=f.asset.asset_name,
                ip_address=f.asset.ip_address, title=f.title, detail=f.detail, severity=f.severity, kev=f.kev,
                status=ITEM_OPEN, owner_id=owners.get(f.asset.id), first_seen_at=now, last_seen_at=now,
                due_at=sla_due(now, f.severity, f.kev, settings), updated_at=now,
            )
            db.add(item)
            db.flush()
            existing[f.key] = item
            _event(db, item, "created", at=now, due_at=item.due_at.isoformat())
            if item.owner_id:
                _event(db, item, "assigned", at=now, owner_id=item.owner_id, automatic=True)
            stats["created"] += 1
        else:
            if item.status == ITEM_RESOLVED:
                item.status = ITEM_OPEN
                item.resolved_at = None
                item.closed_reason = None
                item.reopened += 1
                if not item.due_custom:
                    item.due_at = sla_due(now, f.severity, f.kev, settings)
                _event(db, item, "reopened", at=now)
                stats["reopened"] += 1
            if (item.severity, item.kev) != (f.severity, f.kev) and not item.due_custom:
                item.due_at = sla_due(item.first_seen_at, f.severity, f.kev, settings)
            item.title, item.detail, item.severity, item.kev = f.title, f.detail, f.severity, f.kev
            item.asset_name, item.ip_address = f.asset.asset_name, f.asset.ip_address
            item.last_seen_at = now

        acc = by_item_acc.get(item.id) or by_ref_acc.get((item.source, item.ref))
        if acc is not None:
            if item.status != ITEM_ACCEPTED or item.acceptance_id != acc.id:
                item.status, item.acceptance_id = ITEM_ACCEPTED, acc.id
                _event(db, item, "accepted", at=now, acceptance_id=acc.id, expires_at=acc.expires_at.isoformat())
                touched_assets.add(item.asset_id)
                stats["accepted"] += 1
        elif f.source_accepted:
            if item.status != ITEM_ACCEPTED or item.acceptance_id is not None:
                item.status, item.acceptance_id = ITEM_ACCEPTED, None
                _event(db, item, "accepted_in_source", at=now, source_status=f.detail.get("source_status"))
        elif item.status == ITEM_ACCEPTED:
            ended = item.acceptance_id
            item.status, item.acceptance_id = ITEM_OPEN, None
            if not item.due_custom:
                item.due_at = max(sla_due(item.first_seen_at, item.severity, item.kev, settings), now)
            _event(db, item, "acceptance_ended", at=now, acceptance_id=ended)
            touched_assets.add(item.asset_id)
            stats["unaccepted"] += 1
        elif f.hardened and item.status in (ITEM_OPEN, ITEM_IN_PROGRESS):
            item.status = ITEM_PENDING
            _event(db, item, "hardened", at=now, result_id=f.detail.get("result_id"))

    asset_ids = {aid for (aid,) in db.query(Asset.id)}
    for item in existing.values():
        if item.key in seen_keys or item.status == ITEM_RESOLVED:
            continue
        if item.asset_id is None or item.asset_id not in asset_ids:
            reason = "asset_deleted"
        elif item.source not in checked:
            continue
        elif item.source == "audit" and item.asset_id not in audited_assets:
            reason = "no_data"
        else:
            reason = "fixed"
        was_accepted = item.status == ITEM_ACCEPTED
        item.status, item.resolved_at, item.closed_reason, item.acceptance_id = ITEM_RESOLVED, now, reason, None
        _event(db, item, "resolved", at=now, reason=reason)
        if was_accepted:
            touched_assets.add(item.asset_id)
        stats["resolved"] += 1

    for acc in expired:
        stats["expired"] += 1
    db.commit()
    _recalculate_risk(db, {a for a in touched_assets if a})
    return dict(stats)


def _recalculate_risk(db: Session, asset_ids: Iterable[int]) -> None:
    """Accepted findings leave the risk score: refresh the assets whose accepted set changed."""
    ids = list(asset_ids)
    if not ids:
        return
    from app.modules.risk.service import AssetRiskCalculationService
    service = AssetRiskCalculationService()
    for asset_id in ids:
        try:
            service.calculate(asset_id, db, trigger_type="risk_acceptance")
        except Exception:  # never fail the sync over a score
            logger.exception("[remediation] risk recalculation for asset %s failed", asset_id)
            db.rollback()


def accepted_refs(db: Session, asset_id: int, source: str) -> Set[str]:
    """Refs (CVE ids / check keys) of this asset currently covered by an approved risk acceptance.

    Audit refs are returned with their VDOM suffix the way item keys carry it
    (check number, or "check:vdom")."""
    out = set()
    prefix = f"{source}:{asset_id}:"
    for (key,) in db.query(RemediationItem.key).filter(
            RemediationItem.asset_id == asset_id, RemediationItem.source == source,
            RemediationItem.status == ITEM_ACCEPTED, RemediationItem.acceptance_id.isnot(None)):
        out.add(key[len(prefix):])
    return out


def audit_ref(check_number: Optional[str], vdom: Optional[str]) -> str:
    vdom = (vdom or "").strip()
    return (check_number or "") + (f":{vdom}" if vdom and vdom.lower() != "global" else "")


# ──────────────────────────────────────────────────────────────────────────
# Manual changes to an item
# ──────────────────────────────────────────────────────────────────────────

def update_item(db: Session, item: RemediationItem, user: User, *, owner_id=..., due_at=..., status=None,
                note: Optional[str] = None) -> RemediationItem:
    now = datetime.utcnow()
    if owner_id is not ...:
        if owner_id is not None and db.get(User, owner_id) is None:
            raise RemediationError("That user does not exist")
        if owner_id != item.owner_id:
            item.owner_id = owner_id
            _event(db, item, "assigned", user_id=user.id, owner_id=owner_id)
    if due_at is not ...:
        if due_at is None:
            item.due_custom = False
            item.due_at = sla_due(item.first_seen_at, item.severity, item.kev, get_settings(db))
        else:
            item.due_custom = True
            item.due_at = due_at
        _event(db, item, "due_changed", user_id=user.id, due_at=item.due_at.isoformat(), custom=item.due_custom)
    if status is not None and status != item.status:
        if item.status in (ITEM_RESOLVED, ITEM_ACCEPTED):
            raise RemediationError("This finding is closed; its status follows its source or its risk acceptance")
        if status not in (ITEM_OPEN, ITEM_IN_PROGRESS, ITEM_PENDING):
            raise RemediationError("A finding is resolved by the next audit or CVE check, not by hand")
        _event(db, item, "status", user_id=user.id, old=item.status, new=status)
        item.status = status
    if note:
        _event(db, item, "note", user_id=user.id, text=note.strip()[:2000])
    item.updated_at = now
    db.commit()
    return item


# ──────────────────────────────────────────────────────────────────────────
# Risk acceptance
# ──────────────────────────────────────────────────────────────────────────

def _covering_pending(db: Session, item: RemediationItem, scope: str) -> Optional[RiskAcceptance]:
    q = db.query(RiskAcceptance).filter(RiskAcceptance.status.in_((ACCEPT_PENDING, ACCEPT_APPROVED)))
    if scope == SCOPE_ITEM:
        q = q.filter(RiskAcceptance.scope == SCOPE_ITEM, RiskAcceptance.item_id == item.id)
    else:
        q = q.filter(RiskAcceptance.scope == SCOPE_REF, RiskAcceptance.source == item.source,
                     RiskAcceptance.ref == item.ref)
    return q.first()


def request_acceptance(db: Session, item: RemediationItem, user: User, *, scope: str, justification: str,
                       compensating_control: Optional[str], expires_at: datetime) -> RiskAcceptance:
    now = datetime.utcnow()
    if item.status == ITEM_RESOLVED:
        raise RemediationError("This finding is already resolved")
    if scope not in (SCOPE_ITEM, SCOPE_REF):
        raise RemediationError("Unknown scope")
    if not (justification or "").strip():
        raise RemediationError("A justification is required")
    settings = get_settings(db)
    max_days = accept_max_days(item.severity, item.kev, settings)
    if expires_at <= now:
        raise RemediationError("The end date must be in the future")
    if expires_at > now + timedelta(days=max_days, hours=12):
        raise RemediationError(f"This finding can be accepted for at most {max_days} days")
    if _covering_pending(db, item, scope) is not None:
        raise RemediationError("A risk acceptance for this is already pending or active", 409)
    acc = RiskAcceptance(
        scope=scope, source=item.source, ref=item.ref, item_id=item.id if scope == SCOPE_ITEM else None,
        asset_id=item.asset_id if scope == SCOPE_ITEM else None, title=item.title, severity=item.severity,
        kev=item.kev, justification=justification.strip()[:4000],
        compensating_control=(compensating_control or "").strip()[:4000] or None, expires_at=expires_at,
        status=ACCEPT_PENDING, requested_by=user.id, requested_at=now,
    )
    db.add(acc)
    db.flush()
    _event(db, item, "acceptance_requested", user_id=user.id, acceptance_id=acc.id, scope=scope,
           expires_at=expires_at.isoformat())
    db.commit()
    return acc


def can_decide(user: User, acc: RiskAcceptance) -> Optional[str]:
    """Why this user may not approve or reject the acceptance (None when they may)."""
    role = user.role.value if hasattr(user.role, "value") else str(user.role)
    if role not in (UserRole.ADMIN.value, UserRole.MANAGER.value):
        return "Only administrators and managers can decide on a risk acceptance"
    if acc.requested_by == user.id:
        return "You cannot decide on your own request"
    if (acc.kev or acc.severity == "critical") and role != UserRole.ADMIN.value:
        return "Only an administrator can accept a critical or known-exploited finding"
    return None


def decide_acceptance(db: Session, acc: RiskAcceptance, user: User, approve: bool,
                      note: Optional[str] = None) -> RiskAcceptance:
    if acc.status != ACCEPT_PENDING:
        raise RemediationError("This request has already been decided")
    reason = can_decide(user, acc)
    if reason:
        raise RemediationError(reason, 403)
    now = datetime.utcnow()
    if approve and acc.expires_at <= now:
        raise RemediationError("The requested end date has already passed; ask for a new request")
    acc.status = ACCEPT_APPROVED if approve else ACCEPT_REJECTED
    acc.decided_by, acc.decided_at = user.id, now
    acc.decision_note = (note or "").strip()[:2000] or None
    for item in _items_of(db, acc):
        _event(db, item, "acceptance_approved" if approve else "acceptance_rejected", user_id=user.id,
               acceptance_id=acc.id)
    db.commit()
    if approve:
        sync(db)
    return acc


def can_withdraw(user: User, acc: RiskAcceptance) -> bool:
    """A pending request is cancelled by its requester only (anyone else rejects it, with a
    reason); an active acceptance can also be withdrawn by an administrator or a manager."""
    if acc.requested_by == user.id:
        return acc.status in (ACCEPT_PENDING, ACCEPT_APPROVED)
    role = user.role.value if hasattr(user.role, "value") else str(user.role)
    return acc.status == ACCEPT_APPROVED and role in (UserRole.ADMIN.value, UserRole.MANAGER.value)


def end_acceptance(db: Session, acc: RiskAcceptance, user: User) -> RiskAcceptance:
    if acc.status not in (ACCEPT_APPROVED, ACCEPT_PENDING):
        raise RemediationError("Only a pending or active risk acceptance can be withdrawn")
    if not can_withdraw(user, acc):
        if acc.status == ACCEPT_PENDING:
            raise RemediationError("Only the requester can cancel a pending request; reject it instead", 403)
        raise RemediationError("Only the requester, an administrator or a manager can withdraw this", 403)
    was_active = acc.status == ACCEPT_APPROVED
    acc.status, acc.ended_by, acc.ended_at = ACCEPT_REVOKED, user.id, datetime.utcnow()
    db.commit()
    if was_active:
        sync(db)
    return acc


def _items_of(db: Session, acc: RiskAcceptance) -> List[RemediationItem]:
    if acc.scope == SCOPE_ITEM:
        item = db.get(RemediationItem, acc.item_id) if acc.item_id else None
        return [item] if item else []
    return (db.query(RemediationItem)
            .filter(RemediationItem.source == acc.source, RemediationItem.ref == acc.ref).all())


# ──────────────────────────────────────────────────────────────────────────
# Page figures
# ──────────────────────────────────────────────────────────────────────────

def summary(db: Session, now: Optional[datetime] = None) -> Dict:
    now = now or datetime.utcnow()
    q = db.query(RemediationItem)
    active = q.filter(RemediationItem.status.in_(ITEM_ACTIVE))
    open_count = active.count()
    overdue = active.filter(RemediationItem.due_at < now).count()
    due_soon = active.filter(RemediationItem.due_at >= now, RemediationItem.due_at < now + timedelta(days=7)).count()
    accepted = q.filter(RemediationItem.status == ITEM_ACCEPTED).count()

    since = now - timedelta(days=90)
    fixed = (q.filter(RemediationItem.status == ITEM_RESOLVED, RemediationItem.closed_reason == "fixed",
                      RemediationItem.resolved_at >= since).all())
    on_time = sum(1 for i in fixed if i.due_at is None or i.resolved_at <= i.due_at)
    mttr = (sum((i.resolved_at - i.first_seen_at).total_seconds() for i in fixed) / len(fixed) / 86400
            if fixed else None)

    acc_active = db.query(RiskAcceptance).filter(RiskAcceptance.status == ACCEPT_APPROVED,
                                                 RiskAcceptance.expires_at > now)
    return {
        "open": open_count, "overdue": overdue, "due_soon": due_soon, "accepted": accepted,
        "fixed_90d": len(fixed), "on_time_pct": round(on_time * 100 / len(fixed)) if fixed else None,
        "mttr_days": round(mttr, 1) if mttr is not None else None,
        "acceptances_active": acc_active.count(),
        "acceptances_expiring": acc_active.filter(RiskAcceptance.expires_at < now + timedelta(days=7)).count(),
        "acceptances_pending": db.query(RiskAcceptance).filter(RiskAcceptance.status == ACCEPT_PENDING).count(),
        "counts": {
            "status": dict(db.query(RemediationItem.status, func.count()).group_by(RemediationItem.status).all()),
            "source": dict(active.with_entities(RemediationItem.source, func.count())
                           .group_by(RemediationItem.source).all()),
            "unassigned": active.filter(RemediationItem.owner_id.is_(None)).count(),
        },
    }
