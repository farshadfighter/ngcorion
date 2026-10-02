"""
Figures the report templates share, each "as of" a point in time so a
report can compare a period with the one before it.

  risk_at          latest risk score per asset calculated before a time
                   (asset_risk_history)
  compliance_at    latest completed audit per asset before a time
  remediation      open / overdue / accepted findings at a time, and what
                   was fixed (on time or late) during a period
  accepted_at      risk acceptances active at a time

What has no history (current CVE matches, backup freshness) is reported as
it is when the report is built, and the report says so.
"""
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.audit import AuditSession
from app.models.remediation import (ACCEPT_APPROVED, ACCEPT_EXPIRED, ACCEPT_REVOKED, ITEM_ACCEPTED, ITEM_RESOLVED,
                                    SCOPE_ITEM, RemediationItem, RiskAcceptance)
from app.models.risk import AssetRiskHistory


# ── risk ─────────────────────────────────────────────────────────────────

def risk_at(db: Session, asset_ids: Iterable[int], when: datetime) -> Dict[int, float]:
    ids = list(asset_ids)
    if not ids:
        return {}
    latest = (db.query(AssetRiskHistory.asset_id, func.max(AssetRiskHistory.calculated_at).label("at"))
              .filter(AssetRiskHistory.asset_id.in_(ids), AssetRiskHistory.calculated_at < when)
              .group_by(AssetRiskHistory.asset_id).subquery())
    rows = (db.query(AssetRiskHistory.asset_id, AssetRiskHistory.risk_score)
            .join(latest, (AssetRiskHistory.asset_id == latest.c.asset_id)
                  & (AssetRiskHistory.calculated_at == latest.c.at)).all())
    return {a: float(s) for a, s in rows}


def average(values: Iterable[Optional[float]]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    return sum(vals) / len(vals) if vals else None


def risk_trend(db: Session, asset_ids: Iterable[int], end: datetime, points: int = 12,
               step: timedelta = timedelta(days=7)) -> List[Tuple[datetime, Optional[float]]]:
    """Average risk at the end of each step, oldest first."""
    ids = list(asset_ids)
    out = []
    for k in range(points - 1, -1, -1):
        at = end - step * k
        out.append((at, average(risk_at(db, ids, at).values())))
    return out


# ── audit compliance ─────────────────────────────────────────────────────

def compliance_at(db: Session, asset_ids: Iterable[int], when: datetime) -> Dict[int, AuditSession]:
    """Latest completed audit (with a compliance figure) per asset before `when`."""
    ids = list(asset_ids)
    if not ids:
        return {}
    latest = (db.query(AuditSession.asset_id, func.max(AuditSession.completed_at).label("at"))
              .filter(AuditSession.asset_id.in_(ids), AuditSession.status == "completed",
                      AuditSession.compliance_pct.isnot(None), AuditSession.completed_at < when)
              .group_by(AuditSession.asset_id).subquery())
    rows = (db.query(AuditSession)
            .join(latest, (AuditSession.asset_id == latest.c.asset_id) & (AuditSession.completed_at == latest.c.at))
            .order_by(AuditSession.id).all())
    return {s.asset_id: s for s in rows}


# ── remediation ──────────────────────────────────────────────────────────

def accepted_at(db: Session, when: datetime) -> List[RiskAcceptance]:
    """Acceptances that were in force at `when`."""
    rows = (db.query(RiskAcceptance)
            .filter(RiskAcceptance.status.in_((ACCEPT_APPROVED, ACCEPT_EXPIRED, ACCEPT_REVOKED)),
                    RiskAcceptance.decided_at.isnot(None), RiskAcceptance.decided_at < when,
                    RiskAcceptance.expires_at > when).all())
    return [a for a in rows if a.ended_at is None or a.ended_at > when]


@dataclass
class Remediation:
    open: List[RemediationItem] = field(default_factory=list)
    overdue: List[RemediationItem] = field(default_factory=list)
    accepted: List[RemediationItem] = field(default_factory=list)
    new: List[RemediationItem] = field(default_factory=list)
    fixed: List[RemediationItem] = field(default_factory=list)
    fixed_on_time: int = 0
    mttr_days: Optional[float] = None

    @property
    def on_time_pct(self) -> Optional[float]:
        return 100.0 * self.fixed_on_time / len(self.fixed) if self.fixed else None


def remediation(db: Session, asset_ids: Set[int], start: datetime, end: datetime,
                sources: Optional[Iterable[str]] = None) -> Remediation:
    """Findings open at `end`, and what happened to findings during [start, end)."""
    q = db.query(RemediationItem).filter(RemediationItem.asset_id.in_(list(asset_ids) or [-1]),
                                         RemediationItem.first_seen_at < end)
    if sources:
        q = q.filter(RemediationItem.source.in_(list(sources)))
    items = q.all()

    acc = accepted_at(db, end)
    acc_items = {a.item_id for a in acc if a.scope == SCOPE_ITEM and a.item_id}
    acc_refs = {(a.source, a.ref) for a in acc if a.scope != SCOPE_ITEM}

    out = Remediation()
    durations = []
    for i in items:
        closed_before_end = i.status == ITEM_RESOLVED and i.resolved_at is not None and i.resolved_at < end
        if i.first_seen_at >= start:
            out.new.append(i)
        if closed_before_end:
            if i.closed_reason == "fixed" and i.resolved_at >= start:
                out.fixed.append(i)
                durations.append((i.resolved_at - i.first_seen_at).total_seconds() / 86400)
                if i.due_at is None or i.resolved_at <= i.due_at:
                    out.fixed_on_time += 1
            continue
        accepted = (i.id in acc_items or (i.source, i.ref) in acc_refs
                    or (i.status == ITEM_ACCEPTED and i.acceptance_id is None))   # accepted on its own page
        if accepted:
            out.accepted.append(i)
            continue
        out.open.append(i)
        if i.due_at is not None and i.due_at < end:
            out.overdue.append(i)
    out.mttr_days = sum(durations) / len(durations) if durations else None
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out.open.sort(key=lambda i: (sev.get(i.severity, 9), not i.kev, i.due_at or datetime.max))
    out.overdue.sort(key=lambda i: (i.due_at or datetime.max))
    return out


def count_by(items: Iterable, key) -> Dict:
    out = defaultdict(int)
    for i in items:
        out[key(i)] += 1
    return out
