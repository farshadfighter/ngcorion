"""
Compliance with standards (app/models/compliance.py): the built-in standards, the evidence of the latest
audits and the score of every requirement.

Evidence: the latest completed audit of every asset for every benchmark (an asset audited as a Linux
server and as a Docker host counts in both), optionally only the assets of one group; of each, the
checks that passed or failed, without the ones the benchmark policy makes optional or excludes
(app/modules/audit_policy) and without informational checks. The results are grouped by check in the
database, so the work here grows with the number of different checks (a few thousand), not with assets.

A requirement's evidence is every check its mapping names (domains.requirement_matches):
    score   passed / (passed + failed) of those results
    status  met (nothing failed), partial, not_met (nothing passed)
A requirement without evidence takes the assessment made by hand, while it is valid (met 100, partial 50,
not met 0); "not applicable" can be recorded for any requirement and takes it out of the score. The
standard's score is the mean of its scored requirements; coverage is the share that has a status.
"""
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import distinct, func, select, text
from sqlalchemy.orm import Session

from app.core.singleton import lock_key
from app.models.audit import AuditResult, AuditSession, CheckStatus
from app.models.compliance import (ComplianceAssessment, ComplianceCheckDomains, ComplianceRequirement,
                                   ComplianceSection, ComplianceStandard)
from app.modules.compliance import domains as D

logger = logging.getLogger(__name__)

STANDARDS_DIR = Path(__file__).parent / "standards"
MANUAL_SCORE = {"met": 100.0, "partial": 50.0, "not_met": 0.0}
SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ── built-in standards ───────────────────────────────────────────────────

@lru_cache(maxsize=1)
def builtin_files() -> List[dict]:
    """The definitions of the built-in standards (read once)."""
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(STANDARDS_DIR.glob("*.json"))]


def apply_definition(db: Session, std: ComplianceStandard, data: dict) -> None:
    """Make a standard's sections and requirements those of a definition (the format of standards/*.json):
    update by ref, add new ones, remove the ones the definition no longer has (with their assessments)."""
    sections = {s.ref: s for s in db.query(ComplianceSection).filter(ComplianceSection.standard_id == std.id)}
    seen = set()
    for i, s in enumerate(data.get("sections") or []):
        row = sections.get(s["ref"]) or ComplianceSection(standard_id=std.id, ref=s["ref"])
        row.title, row.title_fa, row.position = s["title"], s.get("title_fa"), i
        db.add(row)
        seen.add(s["ref"])
    for ref, row in sections.items():
        if ref not in seen:
            db.delete(row)
    reqs = {r.ref: r for r in db.query(ComplianceRequirement).filter(ComplianceRequirement.standard_id == std.id)}
    seen = set()
    for i, r in enumerate(data.get("requirements") or []):
        row = reqs.get(r["ref"]) or ComplianceRequirement(standard_id=std.id, ref=r["ref"])
        row.section, row.title, row.title_fa = r.get("section"), r["title"], r.get("title_fa")
        row.mapping, row.position = r.get("mapping") or {}, i
        db.add(row)
        seen.add(r["ref"])
    for ref, row in reqs.items():
        if ref not in seen:
            db.delete(row)


_synced = False


def sync_builtin(db: Session) -> None:
    """Keep the built-in standards in step with standards/*.json, once per process (the enabled flag
    is the organisation's and kept)."""
    global _synced
    files = builtin_files()
    if _synced and db.query(ComplianceStandard.id).filter(ComplianceStandard.builtin.is_(True)).count() == len(files):
        return
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_key("compliance-builtin-sync")})
    for data in files:
        std = db.query(ComplianceStandard).filter(ComplianceStandard.key == data["key"]).first()
        if std is None:
            std = ComplianceStandard(key=data["key"], builtin=True, enabled=True)
            db.add(std)
        for f in ("name", "name_fa", "version", "description", "description_fa"):
            setattr(std, f, data.get(f))
        std.builtin = True
        db.flush()
        apply_definition(db, std, data)
    db.commit()
    _synced = True


def export_definition(db: Session, std: ComplianceStandard) -> dict:
    """A standard in the format of standards/*.json (to keep, edit and import elsewhere)."""
    sections = db.query(ComplianceSection).filter(ComplianceSection.standard_id == std.id) \
        .order_by(ComplianceSection.position).all()
    reqs = db.query(ComplianceRequirement).filter(ComplianceRequirement.standard_id == std.id) \
        .order_by(ComplianceRequirement.position).all()
    return {"key": std.key, "name": std.name, "name_fa": std.name_fa, "version": std.version,
            "description": std.description, "description_fa": std.description_fa,
            "sections": [{"ref": s.ref, "title": s.title, "title_fa": s.title_fa} for s in sections],
            "requirements": [{"ref": r.ref, "section": r.section, "title": r.title, "title_fa": r.title_fa,
                              "mapping": r.mapping or {}} for r in reqs]}


# ── evidence ─────────────────────────────────────────────────────────────

@lru_cache(maxsize=8192)
def _auto(benchmark: str, check_number: str, title: str) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    return tuple(D.classify(title, benchmark, check_number)), tuple(D.topics(title))


@dataclass
class CheckStat:
    """One check over the latest audits in scope."""
    benchmark: str
    check_number: str
    title: str
    severity: str
    passed: int = 0
    failed: int = 0
    failing_assets: int = 0
    domains: List[str] = field(default_factory=list)
    topics: List[str] = field(default_factory=list)
    overridden: bool = False

    @property
    def key(self) -> Tuple[str, str]:
        return self.benchmark, self.check_number


def latest_sessions(asset_ids: Optional[Iterable[int]] = None):
    """The latest completed audit of every asset for every benchmark, as a select of session ids."""
    q = select(func.max(AuditSession.id)).where(AuditSession.status == "completed",
                                                 AuditSession.asset_id.isnot(None))
    if asset_ids is not None:
        q = q.where(AuditSession.asset_id.in_(list(asset_ids)))
    return q.group_by(AuditSession.asset_id, AuditSession.device_type)


def group_assets(db: Session, group_id: Optional[int]) -> Optional[List[int]]:
    if group_id is None:
        return None
    from app.models.asset_groups import AssetGroup
    from app.modules.asset_groups.groups import member_ids
    group = db.get(AssetGroup, group_id)
    return member_ids(db, group) if group else []


def overrides(db: Session) -> Dict[Tuple[str, str], List[str]]:
    return {(o.benchmark, o.check_number): list(o.domains or []) for o in db.query(ComplianceCheckDomains)}


def scope_assets(db: Session, group_id: Optional[int], asset_ids: Optional[Iterable[int]] = None) -> Optional[List[int]]:
    """The assets in scope: a group's, a given list (a report's asset filter), both, or None for all."""
    assets = group_assets(db, group_id)
    if asset_ids is not None:
        wanted = set(asset_ids)
        assets = sorted(wanted if assets is None else wanted.intersection(assets))
    return assets


def check_stats(db: Session, group_id: Optional[int] = None,
                asset_ids: Optional[Iterable[int]] = None) -> List[CheckStat]:
    """Every scored check of the latest audits in scope, with its results and domains."""
    assets = scope_assets(db, group_id, asset_ids)
    if assets is not None and not assets:
        return []
    rows = (db.query(AuditSession.device_type, AuditResult.check_number, func.max(AuditResult.check_title),
                     func.max(AuditResult.severity), AuditResult.status, func.count(),
                     func.count(distinct(AuditSession.asset_id)))
            .join(AuditSession, AuditSession.id == AuditResult.session_id)
            .filter(AuditResult.session_id.in_(latest_sessions(assets)),
                    AuditResult.status.in_([CheckStatus.PASS, CheckStatus.FAIL]),
                    AuditResult.policy.is_(None), AuditResult.check_number.isnot(None),
                    func.upper(func.coalesce(AuditResult.level, "")) != "INFO")
            .group_by(AuditSession.device_type, AuditResult.check_number, AuditResult.status).all())
    fixed = overrides(db)
    stats: Dict[Tuple[str, str], CheckStat] = {}
    for dt, number, title, severity, status, n, n_assets in rows:
        bench = getattr(dt, "value", dt)
        s = stats.get((bench, number))
        if s is None:
            s = stats[(bench, number)] = CheckStat(bench, number, title or number, (severity or "medium").lower())
        if status == CheckStatus.PASS:
            s.passed += n
        else:
            s.failed += n
            s.failing_assets += n_assets
    for s in stats.values():
        auto_domains, s.topics = _auto(s.benchmark, s.check_number, s.title)
        s.topics = list(s.topics)
        if s.key in fixed:
            s.domains, s.overridden = fixed[s.key], True
        else:
            s.domains = list(auto_domains)
    return sorted(stats.values(), key=lambda s: (s.benchmark, s.check_number))


def evidence(req_mapping: dict, stats: List[CheckStat]) -> List[CheckStat]:
    return [s for s in stats if D.requirement_matches(req_mapping, s.benchmark, s.check_number, s.domains,
                                                      s.topics)]


# ── scoring ──────────────────────────────────────────────────────────────

def assessments_for(db: Session, standard_id: int, group_id: Optional[int]) -> Dict[int, ComplianceAssessment]:
    q = (db.query(ComplianceAssessment).join(ComplianceRequirement,
                                             ComplianceRequirement.id == ComplianceAssessment.requirement_id)
         .filter(ComplianceRequirement.standard_id == standard_id))
    q = q.filter(ComplianceAssessment.group_id.is_(None) if group_id is None
                 else ComplianceAssessment.group_id == group_id)
    return {a.requirement_id: a for a in q}


def valid(a: Optional[ComplianceAssessment], now: datetime) -> bool:
    return a is not None and (a.valid_until is None or a.valid_until > now)


def score_requirement(req: ComplianceRequirement, stats: List[CheckStat],
                      assessment: Optional[ComplianceAssessment], now: datetime) -> dict:
    """status / score / source of one requirement, with its evidence counts."""
    ev = evidence(req.mapping or {}, stats)
    passed = sum(s.passed for s in ev)
    failed = sum(s.failed for s in ev)
    out = {"passed": passed, "failed": failed, "checks": len(ev),
           "failing_checks": sum(1 for s in ev if s.failed), "manual_only": not _mapped(req.mapping),
           "assessment_expired": assessment is not None and not valid(assessment, now)}
    if valid(assessment, now) and assessment.status == "not_applicable":
        out.update(status="not_applicable", score=None, source="manual")
    elif passed + failed:
        out.update(score=round(100.0 * passed / (passed + failed), 1), source="audit",
                   status="met" if not failed else "not_met" if not passed else "partial")
    elif valid(assessment, now):
        out.update(status=assessment.status, score=MANUAL_SCORE[assessment.status], source="manual")
    else:
        out.update(status="not_assessed", score=None, source=None)
    return out


def _mapped(mapping: Optional[dict]) -> bool:
    m = mapping or {}
    return bool(m.get("all") or m.get("domains") or m.get("topics") or m.get("checks"))


def summarise(results: List[dict]) -> dict:
    counts = defaultdict(int)
    for r in results:
        counts[r["status"]] += 1
    scored = [r["score"] for r in results if r["score"] is not None]
    total = len(results)
    with_status = total - counts["not_assessed"]
    return {"score": round(sum(scored) / len(scored), 1) if scored else None,
            "requirements": total, "counts": dict(counts),
            "coverage": round(100.0 * with_status / total, 1) if total else 0.0}


def evaluate(db: Session, std: ComplianceStandard, stats: List[CheckStat], group_id: Optional[int],
             now: Optional[datetime] = None) -> Tuple[List[Tuple[ComplianceRequirement, dict]], dict]:
    now = now or datetime.utcnow()
    reqs = db.query(ComplianceRequirement).filter(ComplianceRequirement.standard_id == std.id) \
        .order_by(ComplianceRequirement.position, ComplianceRequirement.id).all()
    assessed = assessments_for(db, std.id, group_id)
    scored = [(r, score_requirement(r, stats, assessed.get(r.id), now)) for r in reqs]
    return scored, summarise([s for _, s in scored])


def gaps(std_reqs: List[ComplianceRequirement], stats: List[CheckStat]) -> List[dict]:
    """The failing checks that are evidence for the standard, the most urgent first: with the
    requirements each one fails (the ones naming it specifically before the configuration-wide ones)."""
    out = []
    for s in stats:
        if not s.failed:
            continue
        refs = [r.ref for r in std_reqs
                if not (r.mapping or {}).get("all")
                and D.requirement_matches(r.mapping or {}, s.benchmark, s.check_number, s.domains, s.topics)]
        broad = [r.ref for r in std_reqs if (r.mapping or {}).get("all")]
        if not refs and not broad:
            continue
        out.append({"benchmark": s.benchmark, "check_number": s.check_number, "title": s.title,
                    "severity": s.severity, "failed": s.failed, "passed": s.passed,
                    "failing_assets": s.failing_assets, "requirements": refs + broad,
                    "specific": len(refs)})
    out.sort(key=lambda g: (-SEVERITY_WEIGHT.get(g["severity"], 2), -g["specific"], -g["failing_assets"],
                            g["benchmark"], g["check_number"]))
    return out


def failing_assets(db: Session, benchmark: str, check_number: str, group_id: Optional[int]) -> List[dict]:
    """The assets whose latest audit of the benchmark fails the check."""
    from app.models.asset import Asset
    from app.models.audit import DeviceType
    assets = group_assets(db, group_id)
    if assets is not None and not assets:
        return []
    rows = (db.query(Asset.id, Asset.asset_name, Asset.ip_address, AuditSession.id, AuditSession.completed_at)
            .join(AuditSession, AuditSession.asset_id == Asset.id)
            .join(AuditResult, AuditResult.session_id == AuditSession.id)
            .filter(AuditSession.id.in_(latest_sessions(assets)),
                    AuditSession.device_type == DeviceType(benchmark),
                    AuditResult.check_number == check_number, AuditResult.status == CheckStatus.FAIL,
                    AuditResult.policy.is_(None))
            .order_by(Asset.asset_name).limit(500).all())
    return [{"asset_id": a, "name": n, "ip": ip, "session_id": sid,
             "audited_at": at.isoformat() if at else None} for a, n, ip, sid, at in rows]


def failing_results(db: Session, group_id: Optional[int] = None,
                    asset_ids: Optional[Iterable[int]] = None) -> List[Tuple[int, str, str, str, str]]:
    """Every failed check of the latest audits in scope: (asset id, benchmark, check, title, severity)."""
    assets = scope_assets(db, group_id, asset_ids)
    if assets is not None and not assets:
        return []
    rows = (db.query(AuditSession.asset_id, AuditSession.device_type, AuditResult.check_number,
                     AuditResult.check_title, AuditResult.severity)
            .join(AuditSession, AuditSession.id == AuditResult.session_id)
            .filter(AuditResult.session_id.in_(latest_sessions(assets)), AuditResult.status == CheckStatus.FAIL,
                    AuditResult.policy.is_(None), AuditResult.check_number.isnot(None),
                    func.upper(func.coalesce(AuditResult.level, "")) != "INFO").all())
    return [(a, getattr(dt, "value", dt), n, t or n, (sev or "medium").lower()) for a, dt, n, t, sev in rows]
