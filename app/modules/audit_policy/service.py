"""
The organisation's benchmark policy (app/models/audit_policy.py) applied to the audits.

Every completed audit session is (re)scored under the rules in force: each of its results gets the
policy's decision for that check on that asset (optional / excluded / none), the module's own scores
are kept in raw_*, and compliance_pct / weighted_compliance_pct become
    passed / (passed + failed)    over the scored checks the policy still requires,
weighted by severity for the weighted score (critical 4, high 3, medium 2, low 1, info 0). A session no
rule touches keeps the module's own scores unchanged.

Sessions are marked for rescoring (policy_checked_at = NULL) when they complete (new rows start so)
and when a rule starts or stops applying; the policy worker scores them in batches every few seconds,
and a decision on a rule scores the affected sessions at once. The remediation sync and the risk score
read the result's policy: neither keeps an excluded check, remediation also leaves out optional ones.
"""
import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy import or_, text
from sqlalchemy.orm import Session

from app.core.singleton import lock_key
from app.models.audit import AuditResult, AuditSession, CheckStatus, DeviceType
from app.models.audit_policy import STATUS_APPROVED, STATUS_EXPIRED, AuditPolicyRule

logger = logging.getLogger(__name__)

_DEVICE_VALUES = {d.value for d in DeviceType}
WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
BATCH = 200                       # sessions per pass
GROUP_REFRESH = timedelta(hours=1)   # dynamic groups change: recheck their assets' latest audits


def _benchmark(session: AuditSession) -> str:
    dt = session.device_type
    return getattr(dt, "value", dt) or ""


@dataclass
class Policy:
    """The rules in force, indexed for one look-up per result."""
    by_check: Dict[Tuple[str, str], List[AuditPolicyRule]]
    by_level: Dict[Tuple[str, str], List[AuditPolicyRule]]
    members: Dict[int, Set[int]]          # group id -> asset ids

    def decision(self, benchmark: str, asset_id: Optional[int], check_number: Optional[str],
                 level: Optional[str]) -> Optional[str]:
        """excluded wins over optional; a rule for a group applies to its assets only."""
        found = None
        rules = (self.by_check.get((benchmark, check_number or ""), [])
                 + self.by_level.get((benchmark, (level or "").upper()), []))
        for r in rules:
            if r.group_id is not None and asset_id not in self.members.get(r.group_id, set()):
                continue
            if r.decision == "excluded":
                return "excluded"
            found = "optional"
        return found

    @property
    def empty(self) -> bool:
        return not self.by_check and not self.by_level


def in_force(db: Session, now: Optional[datetime] = None) -> List[AuditPolicyRule]:
    now = now or datetime.utcnow()
    return [r for r in db.query(AuditPolicyRule).filter(AuditPolicyRule.status == STATUS_APPROVED)
            if r.expires_at is None or r.expires_at > now]


def load(db: Session, now: Optional[datetime] = None) -> Policy:
    from app.models.asset_groups import AssetGroup
    from app.modules.asset_groups.groups import member_ids

    by_check: Dict[Tuple[str, str], List[AuditPolicyRule]] = defaultdict(list)
    by_level: Dict[Tuple[str, str], List[AuditPolicyRule]] = defaultdict(list)
    groups: Set[int] = set()
    for r in in_force(db, now):
        if r.check_number:
            by_check[(r.benchmark, r.check_number)].append(r)
        elif r.level:
            by_level[(r.benchmark, r.level.upper())].append(r)
        if r.group_id is not None:
            groups.add(r.group_id)
    members = {g.id: set(member_ids(db, g)) for g in db.query(AssetGroup).filter(AssetGroup.id.in_(groups))} \
        if groups else {}
    return Policy(dict(by_check), dict(by_level), members)


def is_scored(r: AuditResult) -> bool:
    """Whether a result counts in the score: passed or failed, not informational (INFO level) and
    required by the policy (not optional or excluded). Not applicable checks and errors do not count."""
    return not r.policy and r.status in (CheckStatus.PASS, CheckStatus.FAIL) and (r.level or "").upper() != "INFO"


def _scores(results: Iterable[AuditResult]) -> Tuple[Optional[float], Optional[float]]:
    passed = failed = 0
    w_pass = w_total = 0
    for r in results:
        if not is_scored(r):
            continue
        weight = WEIGHTS.get((r.severity or "medium").lower(), 2)
        w_total += weight
        if r.status == CheckStatus.PASS:
            passed += 1
            w_pass += weight
        else:
            failed += 1
    pct = round(100.0 * passed / (passed + failed), 2) if passed + failed else 0.0
    wpct = round(100.0 * w_pass / w_total, 2) if w_total else 0.0
    return pct, wpct


def rescore(db: Session, session: AuditSession, policy: Policy, now: Optional[datetime] = None) -> bool:
    """Mark the session's results with the policy and set its scores. True when its score changed."""
    benchmark = _benchmark(session)
    results = db.query(AuditResult).filter(AuditResult.session_id == session.id).all()
    optional = excluded = 0
    for r in results:
        decision = policy.decision(benchmark, session.asset_id, r.check_number, r.level)
        if r.policy != decision:
            r.policy = decision
        optional += decision == "optional"
        excluded += decision == "excluded"
    if session.raw_compliance_pct is None and session.compliance_pct is not None:
        session.raw_compliance_pct = session.compliance_pct
        session.raw_weighted_compliance_pct = session.weighted_compliance_pct
    before = (session.compliance_pct, session.weighted_compliance_pct)
    if optional or excluded:
        pct, wpct = _scores(results)
        session.compliance_pct = pct
        session.weighted_compliance_pct = wpct if session.raw_weighted_compliance_pct is not None else None
    elif session.raw_compliance_pct is not None:
        session.compliance_pct = session.raw_compliance_pct
        session.weighted_compliance_pct = session.raw_weighted_compliance_pct
    session.policy_optional, session.policy_excluded = optional, excluded
    session.policy_checked_at = now or datetime.utcnow()
    return before != (session.compliance_pct, session.weighted_compliance_pct)


def mark(db: Session, benchmarks: Optional[Iterable[str]] = None, asset_ids: Optional[Iterable[int]] = None,
         latest_only: bool = False) -> int:
    """Mark completed sessions for rescoring: of these benchmarks (all when None), these assets
    (all when None), every audit or only each asset's latest. Returns how many."""
    q = db.query(AuditSession.id).filter(AuditSession.status == "completed")
    if benchmarks is not None:
        names = list(benchmarks)
        if not names:
            return 0
        types = [DeviceType(n) for n in names if n in _DEVICE_VALUES]
        if not types:
            return 0
        q = q.filter(AuditSession.device_type.in_(types))
    if asset_ids is not None:
        q = q.filter(AuditSession.asset_id.in_(list(asset_ids)))
    if latest_only:
        latest: Dict[int, int] = {}
        for sid, aid in q.add_columns(AuditSession.asset_id).order_by(AuditSession.started_at.desc(),
                                                                    AuditSession.id.desc()):
            latest.setdefault(aid, sid)
        ids = list(latest.values())
    else:
        ids = [sid for (sid,) in q]
    if ids:
        db.query(AuditSession).filter(AuditSession.id.in_(ids)).update(
            {AuditSession.policy_checked_at: None}, synchronize_session=False)
    return len(ids)


def run_pending(db: Session, limit: Optional[int] = BATCH, now: Optional[datetime] = None) -> Dict[str, int]:
    """Score the completed sessions waiting for it (all when limit is None). Commits; serialised across
    workers. Without any rule in force, a session the policy never changed is only stamped."""
    now = now or datetime.utcnow()
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_key("audit-policy-scoring")})
    expired = expire(db, now)
    policy = load(db, now)
    pending = db.query(AuditSession).filter(AuditSession.status == "completed",
                                            AuditSession.policy_checked_at.is_(None))
    if policy.empty:
        # Nothing to apply: only sessions the policy changed before need their own scores back.
        changed_before = pending.filter(or_(AuditSession.policy_optional > 0, AuditSession.policy_excluded > 0))
        sessions = changed_before.limit(limit).all() if limit else changed_before.all()
        changed = sum(rescore(db, s, policy, now) for s in sessions)
        stamped = pending.filter(AuditSession.policy_optional == 0, AuditSession.policy_excluded == 0).update(
            {AuditSession.policy_checked_at: now}, synchronize_session=False)
        db.commit()
        return {"scored": len(sessions) + stamped, "changed": changed, "expired": expired}
    sessions = pending.order_by(AuditSession.id.desc()).limit(limit).all() if limit else pending.all()
    changed = sum(rescore(db, s, policy, now) for s in sessions)
    db.commit()
    return {"scored": len(sessions), "changed": changed, "expired": expired}


def expire(db: Session, now: datetime) -> int:
    """Approved rules past their expiry stop applying: status expired, their sessions rescored."""
    rows = db.query(AuditPolicyRule).filter(AuditPolicyRule.status == STATUS_APPROVED,
                                            AuditPolicyRule.expires_at.isnot(None),
                                            AuditPolicyRule.expires_at <= now).all()
    for r in rows:
        r.status = STATUS_EXPIRED
        r.ended_at = now
    if rows:
        mark(db, {r.benchmark for r in rows})
    return len(rows)


def apply_now(db: Session, rule: AuditPolicyRule) -> Dict[str, int]:
    """A rule started or stopped applying: rescore its benchmark's audits now (each asset's latest
    first, the rest in the background)."""
    mark(db, [rule.benchmark])
    db.commit()
    return run_pending(db, limit=2000)


_last_group_refresh: Optional[datetime] = None


def refresh_groups(db: Session, now: datetime) -> int:
    """Members of dynamic groups change with the inventory: recheck the latest audit of every asset
    of the benchmarks that have group rules, once an hour."""
    global _last_group_refresh
    if _last_group_refresh and now - _last_group_refresh < GROUP_REFRESH:
        return 0
    _last_group_refresh = now
    benchmarks = {r.benchmark for r in in_force(db, now) if r.group_id is not None}
    n = mark(db, benchmarks, latest_only=True) if benchmarks else 0
    db.commit()
    return n
