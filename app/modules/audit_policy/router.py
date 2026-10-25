"""
The organisation's benchmark policy (app/models/audit_policy.py): rules that make a check (or a whole
level) optional or excluded for every asset or an asset group, requested by one person and approved by
another; the checks to choose from (every family's catalog, audited or not); and what the policy changes
in the latest audits.
"""
import re
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, UserRole
from app.models.audit import AuditResult, AuditSession, CheckStatus, DeviceType
from app.models.audit_policy import (DECISIONS, STATUS_APPROVED, STATUS_PENDING, STATUS_REJECTED, STATUS_REVOKED,
                                     AuditPolicyRule)
from app.modules.audit_policy import catalog, service

router = APIRouter(prefix="/api/audit-policy", tags=["Audit policy"])

_BENCHMARKS = {d.value for d in DeviceType}
CHECKS_SHOWN = 1000         # the drawer's list; a search narrows it


class RuleIn(BaseModel):
    benchmark: str = Field(..., max_length=40)
    check_number: Optional[str] = Field(None, max_length=50)
    level: Optional[str] = Field(None, max_length=10)
    decision: str
    group_id: Optional[int] = None
    reason: str = Field(..., min_length=10, max_length=2000)
    expires_at: Optional[datetime] = None

    @model_validator(mode="after")
    def _one_target(self):
        if bool(self.check_number) == bool(self.level):
            raise ValueError("Choose one check or one level")
        if self.decision not in DECISIONS:
            raise ValueError("Choose optional or excluded")
        if self.benchmark not in _BENCHMARKS:
            raise ValueError("Unknown benchmark")
        return self


class DecideIn(BaseModel):
    approve: bool
    note: Optional[str] = Field(None, max_length=1000)


class RuleOut(BaseModel):
    id: int
    benchmark: str
    check_number: Optional[str] = None
    level: Optional[str] = None
    check_title: Optional[str] = None
    severity: Optional[str] = None
    decision: str
    group: Optional[Dict] = None
    reason: str
    expires_at: Optional[datetime] = None
    status: str
    in_force: bool
    requested_by: Optional[str] = None
    requested_at: datetime
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    decision_note: Optional[str] = None
    ended_by: Optional[str] = None
    ended_at: Optional[datetime] = None
    can_decide: Optional[str] = None       # why this user may not decide (None: may)
    can_end: bool = False
    results: int = 0                       # results in the latest audits it covers


def _role(user: User) -> str:
    return user.role.value if hasattr(user.role, "value") else str(user.role)


def why_not_decide(user: User, rule: AuditPolicyRule) -> Optional[str]:
    """Why this user may not approve or reject the rule (None when they may): an administrator or a
    manager, never the requester; a whole level, or excluding a high or critical check, needs an
    administrator."""
    role = _role(user)
    if rule.status != STATUS_PENDING:
        return "This rule is not waiting for a decision"
    if role not in (UserRole.ADMIN.value, UserRole.MANAGER.value):
        return "Only administrators and managers can decide on a policy rule"
    if rule.requested_by == user.id:
        return "You cannot decide on your own request"
    broad = rule.level is not None or (rule.decision == "excluded" and (rule.severity or "").lower() in
                                        ("high", "critical"))
    if broad and role != UserRole.ADMIN.value:
        return "Only an administrator can decide on a whole level or on excluding a high or critical check"
    return None


def _can_end(user: User, rule: AuditPolicyRule) -> bool:
    if rule.status == STATUS_PENDING:
        return rule.requested_by == user.id or _role(user) == UserRole.ADMIN.value
    return rule.status == STATUS_APPROVED and _role(user) in (UserRole.ADMIN.value, UserRole.MANAGER.value)


def _latest_session_ids(db: Session) -> List[int]:
    rows = (db.query(AuditSession.asset_id, func.max(AuditSession.id))
            .filter(AuditSession.status == "completed", AuditSession.asset_id.isnot(None))
            .group_by(AuditSession.asset_id, AuditSession.device_type).all())
    return [sid for _, sid in rows]


def _out(db: Session, r: AuditPolicyRule, user: User, users: Dict[int, str], groups: Dict[int, str],
         counts: Dict[int, int]) -> RuleOut:
    now = datetime.utcnow()
    return RuleOut(
        id=r.id, benchmark=r.benchmark, check_number=r.check_number, level=r.level, check_title=r.check_title,
        severity=r.severity, decision=r.decision,
        group={"id": r.group_id, "name": groups.get(r.group_id, f"#{r.group_id}")} if r.group_id else None,
        reason=r.reason, expires_at=r.expires_at, status=r.status,
        in_force=r.status == STATUS_APPROVED and (r.expires_at is None or r.expires_at > now),
        requested_by=users.get(r.requested_by), requested_at=r.requested_at, decided_by=users.get(r.decided_by),
        decided_at=r.decided_at, decision_note=r.decision_note, ended_by=users.get(r.ended_by), ended_at=r.ended_at,
        can_decide=why_not_decide(user, r), can_end=_can_end(user, r), results=counts.get(r.id, 0),
    )


def _covered_counts(db: Session, rules: List[AuditPolicyRule]) -> Dict[int, int]:
    """Results in each asset's latest audit that each rule in force covers."""
    live = [r for r in rules if r.status == STATUS_APPROVED]
    if not live:
        return {}
    policy = service.load(db)
    ids = _latest_session_ids(db)
    out: Dict[int, int] = {}
    if not ids:
        return out
    sessions = {s.id: s for s in db.query(AuditSession).filter(AuditSession.id.in_(ids))}
    for res in db.query(AuditResult).filter(AuditResult.session_id.in_(ids), AuditResult.policy.isnot(None)):
        s = sessions[res.session_id]
        bench = service._benchmark(s)
        for r in live:
            if r.benchmark != bench or (r.check_number and r.check_number != res.check_number) or \
                    (r.level and r.level.upper() != (res.level or "").upper()):
                continue
            if r.group_id is not None and s.asset_id not in policy.members.get(r.group_id, set()):
                continue
            out[r.id] = out.get(r.id, 0) + 1
    return out


@router.get("/rules", response_model=List[RuleOut])
def list_rules(status: str = Query("all", pattern="^(all|in_force|pending|ended)$"),
               benchmark: Optional[str] = Query(None, max_length=40),
               current_user: User = Depends(require_permission("auditing", "read")),
               db: Session = Depends(get_db)):
    """The policy's rules: in force, waiting for a decision, ended (rejected, withdrawn, expired), or all."""
    from app.models.asset_groups import AssetGroup
    q = db.query(AuditPolicyRule)
    if benchmark:
        q = q.filter(AuditPolicyRule.benchmark == benchmark)
    if status == "in_force":
        q = q.filter(AuditPolicyRule.status == STATUS_APPROVED)
    elif status == "pending":
        q = q.filter(AuditPolicyRule.status == STATUS_PENDING)
    elif status == "ended":
        q = q.filter(AuditPolicyRule.status.notin_([STATUS_APPROVED, STATUS_PENDING]))
    rules = q.order_by(AuditPolicyRule.requested_at.desc(), AuditPolicyRule.id.desc()).all()
    ids = {i for r in rules for i in (r.requested_by, r.decided_by, r.ended_by) if i}
    users = {u.id: u.username for u in db.query(User).filter(User.id.in_(ids))} if ids else {}
    gids = {r.group_id for r in rules if r.group_id}
    groups = {g.id: g.name for g in db.query(AssetGroup).filter(AssetGroup.id.in_(gids))} if gids else {}
    counts = _covered_counts(db, rules)
    return [_out(db, r, current_user, users, groups, counts) for r in rules]


@router.get("/checks")
def list_checks(benchmark: str = Query(..., max_length=40), q: Optional[str] = Query(None, max_length=100),
                current_user: User = Depends(require_permission("auditing", "read")),
                db: Session = Depends(get_db)):
    """The checks of a benchmark to choose a rule from: its module's whole catalog (app/modules/
    audit_policy/catalog.py), so any of the 17 families can have rules before its first audit, and any
    check an audit has reported that the catalog lacks; each with how many of the latest audits of this
    benchmark fail it. And the benchmark's levels."""
    if benchmark not in _BENCHMARKS:
        raise HTTPException(status_code=400, detail="Unknown benchmark")
    dt = DeviceType(benchmark)
    by_number = {c["check_number"]: c for c in catalog.checks(benchmark)}
    audited = (db.query(AuditResult.check_number, func.max(AuditResult.check_title), func.max(AuditResult.severity),
                        func.max(AuditResult.level))
               .join(AuditSession, AuditSession.id == AuditResult.session_id)
               .filter(AuditSession.device_type == dt, AuditResult.check_number.isnot(None))
               .group_by(AuditResult.check_number).all())
    for c, t, s, lv in audited:
        by_number.setdefault(c, {"check_number": c, "title": t, "severity": (s or "").lower() or None,
                                 "level": (lv or "").upper() or None})
    rows = sorted(by_number.values(), key=lambda c: _natural(c["check_number"]))
    levels = sorted({c["level"] for c in rows if c["level"] and c["level"] != "INFO"})
    if q:
        needle = q.strip().lower()
        rows = [c for c in rows if needle in c["check_number"].lower() or needle in (c["title"] or "").lower()]
    latest = [i for (i,) in db.query(AuditSession.id).filter(AuditSession.id.in_(_latest_session_ids(db)),
                                                               AuditSession.device_type == dt)]
    failed = dict(db.query(AuditResult.check_number, func.count()).filter(
        AuditResult.session_id.in_(latest), AuditResult.status == CheckStatus.FAIL).group_by(AuditResult.check_number)) \
        if latest else {}
    return {"benchmark": benchmark, "levels": levels, "total": len(rows),
            "checks": [{**c, "failed_now": failed.get(c["check_number"], 0)} for c in rows[:CHECKS_SHOWN]]}


def _natural(number: str):
    """1.2.10 after 1.2.9: digits compare as numbers."""
    return [(0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"(\d+)", number)]


@router.get("/benchmarks")
def list_benchmarks(current_user: User = Depends(require_permission("auditing", "read")),
                    db: Session = Depends(get_db)):
    """Every benchmark (the 17 families), with how many checks its catalog has and, for those audits have
    run, each one's latest audits: how many, the average score under the policy and without it, and how
    many results the policy covers."""
    ids = _latest_session_ids(db)
    out = []
    if ids:
        rows = (db.query(AuditSession.device_type, func.count(), func.avg(AuditSession.compliance_pct),
                         func.avg(func.coalesce(AuditSession.raw_compliance_pct, AuditSession.compliance_pct)),
                         func.sum(AuditSession.policy_optional), func.sum(AuditSession.policy_excluded))
                .filter(AuditSession.id.in_(ids)).group_by(AuditSession.device_type).all())
        for dt, n, score, raw, opt, exc in rows:
            out.append({"benchmark": getattr(dt, "value", dt), "assets": n,
                        "score": round(score, 1) if score is not None else None,
                        "raw_score": round(raw, 1) if raw is not None else None,
                        "optional": int(opt or 0), "excluded": int(exc or 0)})
    audited = {b["benchmark"] for b in out}
    for dt in DeviceType:
        if dt.value not in audited:
            out.append({"benchmark": dt.value, "assets": 0, "score": None, "raw_score": None,
                        "optional": 0, "excluded": 0})
    for b in out:
        b["checks"] = len(catalog.checks(b["benchmark"]))
    pending = db.query(AuditPolicyRule).filter(AuditPolicyRule.status == STATUS_PENDING).count()
    in_force = len(service.in_force(db))
    # audited ones first, then by name
    return {"benchmarks": sorted(out, key=lambda b: (b["assets"] == 0, b["benchmark"])), "pending": pending,
            "in_force": in_force}


@router.post("/rules", response_model=RuleOut, status_code=201)
def request_rule(body: RuleIn, request: Request, current_user: User = Depends(require_permission("auditing", "write")),
                 db: Session = Depends(get_db)):
    """Ask for a rule; it applies once someone else approves it."""
    from app.models.asset_groups import AssetGroup
    from app.models.security_audit_log import log_action
    group = None
    if body.group_id is not None:
        group = db.get(AssetGroup, body.group_id)
        if group is None:
            raise HTTPException(status_code=400, detail="Group not found")
    if body.expires_at is not None and body.expires_at <= datetime.utcnow():
        raise HTTPException(status_code=400, detail="The expiry must be in the future")
    title = severity = None
    if body.check_number:
        hit = (db.query(AuditResult.check_title, AuditResult.severity)
               .join(AuditSession, AuditSession.id == AuditResult.session_id)
               .filter(AuditSession.device_type == DeviceType(body.benchmark),
                       AuditResult.check_number == body.check_number)
               .order_by(AuditResult.id.desc()).first())
        if hit is not None:
            title, severity = hit
        else:
            # not audited yet: the module's catalog knows it
            known = catalog.find(body.benchmark, body.check_number)
            if known is None:
                raise HTTPException(status_code=400, detail="This benchmark has no such check")
            title, severity = known["title"], known["severity"]
    same = db.query(AuditPolicyRule).filter(
        AuditPolicyRule.benchmark == body.benchmark, AuditPolicyRule.status.in_([STATUS_PENDING, STATUS_APPROVED]),
        AuditPolicyRule.check_number == body.check_number if body.check_number else AuditPolicyRule.level == body.level.upper(),
        AuditPolicyRule.group_id == body.group_id if body.group_id else AuditPolicyRule.group_id.is_(None)).first()
    if same is not None:
        raise HTTPException(status_code=409, detail="A rule for this check and scope is already pending or in force")
    rule = AuditPolicyRule(benchmark=body.benchmark, check_number=body.check_number,
                           level=body.level.upper() if body.level else None, check_title=title, severity=severity,
                           decision=body.decision, group_id=body.group_id, reason=body.reason.strip(),
                           expires_at=body.expires_at, status=STATUS_PENDING, requested_by=current_user.id,
                           requested_at=datetime.utcnow())
    db.add(rule)
    db.commit()
    what, bench = rule.check_number or rule.level, rule.benchmark
    log_action(db, user_id=current_user.id, username=current_user.username, action="audit_policy.request",
               module="auditing", target_id=rule.id, ip_address=request.client.host if request.client else None,
               detail=(f"Asked to make {what} of the {bench} benchmark optional" if rule.decision == "optional"
                       else f"Asked to exclude {what} of the {bench} benchmark"))
    users = {current_user.id: current_user.username}
    return _out(db, rule, current_user, users, {group.id: group.name} if group else {}, {})


@router.post("/rules/{rule_id}/decide", response_model=RuleOut)
def decide(rule_id: int, body: DecideIn, request: Request,
           current_user: User = Depends(require_permission("auditing", "read")), db: Session = Depends(get_db)):
    """Approve or reject a rule waiting for a decision (see why_not_decide). An approval applies it to the
    audits at once."""
    from app.models.security_audit_log import log_action
    rule = db.get(AuditPolicyRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="No such rule")
    why = why_not_decide(current_user, rule)
    if why:
        raise HTTPException(status_code=403, detail=why)
    rule.status = STATUS_APPROVED if body.approve else STATUS_REJECTED
    rule.decided_by, rule.decided_at = current_user.id, datetime.utcnow()
    rule.decision_note = (body.note or "").strip() or None
    db.commit()
    what, bench, optional = rule.check_number or rule.level, rule.benchmark, rule.decision == "optional"
    log_action(db, user_id=current_user.id, username=current_user.username,
               action="audit_policy.approve" if body.approve else "audit_policy.reject", module="auditing",
               target_id=rule.id, ip_address=request.client.host if request.client else None,
               detail=(f"Approved making {what} of the {bench} benchmark optional" if body.approve and optional
                       else f"Approved excluding {what} of the {bench} benchmark" if body.approve
                       else f"Rejected making {what} of the {bench} benchmark optional" if optional
                       else f"Rejected excluding {what} of the {bench} benchmark"))
    if body.approve:
        service.apply_now(db, rule)
    return list_rules_one(db, rule, current_user)


@router.post("/rules/{rule_id}/end", response_model=RuleOut)
def end_rule(rule_id: int, request: Request, current_user: User = Depends(require_permission("auditing", "read")),
             db: Session = Depends(get_db)):
    """Withdraw a request (its requester or an administrator) or end a rule in force (an administrator or
    a manager): the checks count again from now on."""
    from app.models.security_audit_log import log_action
    rule = db.get(AuditPolicyRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="No such rule")
    if not _can_end(current_user, rule):
        raise HTTPException(status_code=403, detail="You cannot end this rule")
    was_in_force = rule.status == STATUS_APPROVED
    rule.status = STATUS_REVOKED
    rule.ended_by, rule.ended_at = current_user.id, datetime.utcnow()
    db.commit()
    what, bench = rule.check_number or rule.level, rule.benchmark
    log_action(db, user_id=current_user.id, username=current_user.username, action="audit_policy.end",
               module="auditing", target_id=rule.id, ip_address=request.client.host if request.client else None,
               detail=(f"Ended the rule making {what} of the {bench} benchmark optional"
                       if rule.decision == "optional" else f"Ended the rule excluding {what} of the {bench} benchmark"))
    if was_in_force:
        service.apply_now(db, rule)
    return list_rules_one(db, rule, current_user)


def list_rules_one(db: Session, rule: AuditPolicyRule, user: User) -> RuleOut:
    from app.models.asset_groups import AssetGroup
    ids = {i for i in (rule.requested_by, rule.decided_by, rule.ended_by) if i}
    users = {u.id: u.username for u in db.query(User).filter(User.id.in_(ids))} if ids else {}
    groups = {}
    if rule.group_id:
        g = db.get(AssetGroup, rule.group_id)
        groups = {g.id: g.name} if g else {}
    return _out(db, rule, user, users, groups, _covered_counts(db, [rule]))
