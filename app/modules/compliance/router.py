"""
API of compliance with standards (app/modules/compliance/service.py), under /api/compliance.

Reading needs the auditing read permission; assessing a requirement by hand needs auditing write;
adding or changing a standard (the organisation's own, e.g. national requirements) needs auditing write
and the administrator or manager role; correcting the domains of a check changes every standard and is
for administrators only. Every change is in the audit trail.
"""
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, UserRole
from app.models.audit import DeviceType
from app.models.compliance import (ASSESSMENT_STATUSES, ComplianceAssessment, ComplianceCheckDomains,
                                   ComplianceRequirement, ComplianceSection, ComplianceStandard)
from app.modules.compliance import domains as D
from app.modules.compliance import service

router = APIRouter(prefix="/api/compliance", tags=["Compliance"])

_BENCHMARKS = {d.value for d in DeviceType}
MAX_REQUIREMENTS = 500
ASSESSMENT_DAYS = 365


def _role(user: User) -> str:
    return user.role.value if hasattr(user.role, "value") else str(user.role)


def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _need_role(user: User, *roles: UserRole) -> None:
    if _role(user) not in {r.value for r in roles}:
        names = " or ".join("administrators" if r == UserRole.ADMIN else "managers" for r in roles)
        raise HTTPException(status_code=403, detail=f"Only {names} can do this")


def _standard(db: Session, standard_id: int) -> ComplianceStandard:
    std = db.get(ComplianceStandard, standard_id)
    if std is None:
        raise HTTPException(status_code=404, detail="Standard not found")
    return std


def _custom(std: ComplianceStandard) -> None:
    if std.builtin:
        raise HTTPException(status_code=400, detail="A built-in standard cannot be changed; export it and import "
                                                    "a copy to adapt it")


def _group(db: Session, group_id: Optional[int]) -> Optional[Dict]:
    if group_id is None:
        return None
    from app.models.asset_groups import AssetGroup
    g = db.get(AssetGroup, group_id)
    if g is None:
        raise HTTPException(status_code=404, detail="Asset group not found")
    return {"id": g.id, "name": g.name}


def _std_out(s: ComplianceStandard) -> Dict:
    return {"id": s.id, "key": s.key, "name": s.name, "name_fa": s.name_fa, "version": s.version,
            "description": s.description, "description_fa": s.description_fa, "builtin": s.builtin,
            "enabled": s.enabled}


def _check_out(s: service.CheckStat) -> Dict:
    return {"benchmark": s.benchmark, "check_number": s.check_number, "title": s.title, "severity": s.severity,
            "passed": s.passed, "failed": s.failed, "failing_assets": s.failing_assets, "domains": s.domains,
            "topics": s.topics, "overridden": s.overridden}


def _assessment_out(a: Optional[ComplianceAssessment], users: Dict[int, str], now: datetime) -> Optional[Dict]:
    if a is None:
        return None
    return {"status": a.status, "note": a.note, "valid_until": a.valid_until.isoformat() if a.valid_until else None,
            "expired": not service.valid(a, now), "assessed_by": users.get(a.assessed_by),
            "assessed_at": a.assessed_at.isoformat() if a.assessed_at else None}


def _usernames(db: Session, ids) -> Dict[int, str]:
    ids = {i for i in ids if i}
    return {u.id: u.username for u in db.query(User).filter(User.id.in_(ids))} if ids else {}


# ── reading ──────────────────────────────────────────────────────────────

@router.get("/domains")
def list_domains(current_user: User = Depends(require_permission("auditing", "read"))):
    """The security domains and topics requirements are mapped to."""
    return {"domains": [{"key": k, "name": v} for k, v in D.DOMAINS.items()],
            "topics": [{"key": k, "name": v[0]} for k, v in D.TOPICS.items()]}


@router.get("/standards")
def list_standards(group_id: Optional[int] = None, include_disabled: bool = False,
                   current_user: User = Depends(require_permission("auditing", "read")),
                   db: Session = Depends(get_db)):
    """The standards with their score over the latest audits (all assets or one group)."""
    service.sync_builtin(db)
    group = _group(db, group_id)
    q = db.query(ComplianceStandard)
    if not include_disabled:
        q = q.filter(ComplianceStandard.enabled.is_(True))
    stds = q.order_by(ComplianceStandard.builtin.desc(), ComplianceStandard.name).all()
    stats = service.check_stats(db, group_id)
    now = datetime.utcnow()
    out = []
    for s in stds:
        _, summary = service.evaluate(db, s, stats, group_id, now) if s.enabled else (None, None)
        out.append({**_std_out(s), "summary": summary})
    return {"group": group, "standards": out, "audited_checks": len(stats),
            "audited_assets": _audited_assets(db, group_id)}


def _audited_assets(db: Session, group_id: Optional[int]) -> int:
    from sqlalchemy import distinct, func

    from app.models.audit import AuditSession
    assets = service.group_assets(db, group_id)
    if assets is not None and not assets:
        return 0
    return db.query(func.count(distinct(AuditSession.asset_id))).filter(
        AuditSession.id.in_(service.latest_sessions(assets))).scalar() or 0


@router.get("/standards/{standard_id}")
def get_standard(standard_id: int, group_id: Optional[int] = None,
                 current_user: User = Depends(require_permission("auditing", "read")),
                 db: Session = Depends(get_db)):
    """A standard's sections and requirements, each with its status, score, evidence and assessment."""
    service.sync_builtin(db)
    std = _standard(db, standard_id)
    group = _group(db, group_id)
    stats = service.check_stats(db, group_id)
    now = datetime.utcnow()
    scored, summary = service.evaluate(db, std, stats, group_id, now)
    assessed = service.assessments_for(db, std.id, group_id)
    users = _usernames(db, [a.assessed_by for a in assessed.values()])
    sections = db.query(ComplianceSection).filter(ComplianceSection.standard_id == std.id) \
        .order_by(ComplianceSection.position).all()
    return {**_std_out(std), "group": group, "summary": summary,
            "sections": [{"ref": s.ref, "title": s.title, "title_fa": s.title_fa} for s in sections],
            "requirements": [{"id": r.id, "ref": r.ref, "section": r.section, "title": r.title,
                              "title_fa": r.title_fa, "mapping": r.mapping or {}, **res,
                              "assessment": _assessment_out(assessed.get(r.id), users, now)}
                             for r, res in scored]}


@router.get("/requirements/{requirement_id}")
def get_requirement(requirement_id: int, group_id: Optional[int] = None,
                    current_user: User = Depends(require_permission("auditing", "read")),
                    db: Session = Depends(get_db)):
    """One requirement with the checks that are its evidence (failing ones first)."""
    req = db.get(ComplianceRequirement, requirement_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Requirement not found")
    std = _standard(db, req.standard_id)
    group = _group(db, group_id)
    stats = service.check_stats(db, group_id)
    now = datetime.utcnow()
    assessment = service.assessments_for(db, std.id, group_id).get(req.id)
    res = service.score_requirement(req, stats, assessment, now)
    ev = sorted(service.evidence(req.mapping or {}, stats),
                key=lambda s: (-s.failed, -service.SEVERITY_WEIGHT.get(s.severity, 2), s.benchmark, s.check_number))
    users = _usernames(db, [assessment.assessed_by] if assessment else [])
    return {"id": req.id, "ref": req.ref, "section": req.section, "title": req.title, "title_fa": req.title_fa,
            "mapping": req.mapping or {}, "standard": _std_out(std), "group": group, **res,
            "assessment": _assessment_out(assessment, users, now),
            "evidence": [_check_out(s) for s in ev[:1000]], "evidence_total": len(ev)}


@router.get("/standards/{standard_id}/gaps")
def list_gaps(standard_id: int, group_id: Optional[int] = None, limit: int = Query(200, ge=1, le=2000),
              current_user: User = Depends(require_permission("auditing", "read")),
              db: Session = Depends(get_db)):
    """The failing checks that hold the standard back, the most urgent first."""
    std = _standard(db, standard_id)
    _group(db, group_id)
    reqs = db.query(ComplianceRequirement).filter(ComplianceRequirement.standard_id == std.id) \
        .order_by(ComplianceRequirement.position).all()
    rows = service.gaps(reqs, service.check_stats(db, group_id))
    return {"total": len(rows), "gaps": rows[:limit]}


@router.get("/failing-assets")
def list_failing_assets(benchmark: str = Query(..., max_length=40), check_number: str = Query(..., max_length=50),
                        group_id: Optional[int] = None,
                        current_user: User = Depends(require_permission("auditing", "read")),
                        db: Session = Depends(get_db)):
    """The assets whose latest audit fails a check."""
    if benchmark not in _BENCHMARKS:
        raise HTTPException(status_code=400, detail="Unknown benchmark")
    _group(db, group_id)
    return {"assets": service.failing_assets(db, benchmark, check_number, group_id)}


@router.get("/standards/{standard_id}/export")
def export_standard(standard_id: int, current_user: User = Depends(require_permission("auditing", "read")),
                    db: Session = Depends(get_db)):
    """The standard as a definition file (JSON), to keep, adapt and import."""
    return service.export_definition(db, _standard(db, standard_id))


# ── assessing by hand ────────────────────────────────────────────────────

class AssessmentIn(BaseModel):
    group_id: Optional[int] = None
    status: str
    note: str = Field(..., min_length=5, max_length=4000)
    valid_until: Optional[datetime] = None

    @field_validator("status")
    @classmethod
    def _status(cls, v):
        if v not in ASSESSMENT_STATUSES:
            raise ValueError("Choose met, partial, not met or not applicable")
        return v


@router.put("/requirements/{requirement_id}/assessment")
def assess(requirement_id: int, body: AssessmentIn, request: Request,
           current_user: User = Depends(require_permission("auditing", "write")),
           db: Session = Depends(get_db)):
    """Assess a requirement by hand for all assets or one group. Met / partial / not met only for a
    requirement the audits give no evidence for; not applicable for any requirement."""
    from app.models.security_audit_log import log_action
    req = db.get(ComplianceRequirement, requirement_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Requirement not found")
    std = _standard(db, req.standard_id)
    _group(db, body.group_id)
    now = datetime.utcnow()
    if body.valid_until is not None and body.valid_until <= now:
        raise HTTPException(status_code=400, detail="The assessment must be valid until a future date")
    if body.status != "not_applicable":
        res = service.score_requirement(req, service.check_stats(db, body.group_id), None, now)
        if res["passed"] + res["failed"]:
            raise HTTPException(status_code=400, detail="The audits give evidence for this requirement; it can only "
                                                        "be marked not applicable by hand")
    a = (db.query(ComplianceAssessment)
         .filter(ComplianceAssessment.requirement_id == req.id,
                 ComplianceAssessment.group_id.is_(None) if body.group_id is None
                 else ComplianceAssessment.group_id == body.group_id).first())
    if a is None:
        a = ComplianceAssessment(requirement_id=req.id, group_id=body.group_id)
        db.add(a)
    a.status, a.note = body.status, body.note.strip()
    a.valid_until = body.valid_until or now + timedelta(days=ASSESSMENT_DAYS)
    a.assessed_by, a.assessed_at = current_user.id, now
    log_action(db, user_id=current_user.id, username=current_user.username, action="compliance.assess",
               module="auditing", target_id=req.id, ip_address=_ip(request),
               detail=f"Assessed requirement {req.ref} of {std.name} by hand")
    db.commit()
    return {"ok": True}


@router.delete("/requirements/{requirement_id}/assessment")
def remove_assessment(requirement_id: int, request: Request, group_id: Optional[int] = None,
                      current_user: User = Depends(require_permission("auditing", "write")),
                      db: Session = Depends(get_db)):
    from app.models.security_audit_log import log_action
    req = db.get(ComplianceRequirement, requirement_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Requirement not found")
    std = _standard(db, req.standard_id)
    q = db.query(ComplianceAssessment).filter(
        ComplianceAssessment.requirement_id == req.id,
        ComplianceAssessment.group_id.is_(None) if group_id is None else ComplianceAssessment.group_id == group_id)
    if not q.delete(synchronize_session=False):
        raise HTTPException(status_code=404, detail="No assessment to remove")
    log_action(db, user_id=current_user.id, username=current_user.username, action="compliance.unassess",
               module="auditing", target_id=req.id, ip_address=_ip(request),
               detail=f"Removed the assessment of requirement {req.ref} of {std.name}")
    db.commit()
    return {"ok": True}


# ── the organisation's own standards ─────────────────────────────────────

_REF = re.compile(r"^[\w.\-()/ ]{1,40}$")


class MappingIn(BaseModel):
    all: bool = False
    domains: List[str] = Field(default_factory=list, max_length=40)
    topics: List[str] = Field(default_factory=list, max_length=40)
    checks: List[str] = Field(default_factory=list, max_length=200)

    def as_dict(self) -> Dict:
        out: Dict = {}
        if self.all:
            out["all"] = True
        for f in ("domains", "topics", "checks"):
            vals = [v.strip() for v in getattr(self, f) if v and v.strip()]
            if vals:
                out[f] = vals
        why = D.validate_mapping(out)
        if why:
            raise HTTPException(status_code=400, detail=why)
        return out


class RequirementIn(BaseModel):
    ref: str = Field(..., min_length=1, max_length=40)
    section: Optional[str] = Field(None, max_length=40)
    title: str = Field(..., min_length=2, max_length=500)
    title_fa: Optional[str] = Field(None, max_length=500)
    mapping: MappingIn = Field(default_factory=MappingIn)

    @field_validator("ref")
    @classmethod
    def _ref(cls, v):
        v = v.strip()
        if not _REF.match(v):
            raise ValueError("A reference is letters, digits and . - ( ) /")
        return v


class SectionIn(BaseModel):
    ref: str = Field(..., min_length=1, max_length=40)
    title: str = Field(..., min_length=1, max_length=300)
    title_fa: Optional[str] = Field(None, max_length=300)


class StandardIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    name_fa: Optional[str] = Field(None, max_length=160)
    version: Optional[str] = Field(None, max_length=40)
    description: Optional[str] = Field(None, max_length=4000)
    description_fa: Optional[str] = Field(None, max_length=4000)


class StandardImport(StandardIn):
    key: Optional[str] = Field(None, max_length=60)
    sections: List[SectionIn] = Field(default_factory=list, max_length=200)
    requirements: List[RequirementIn] = Field(..., min_length=1, max_length=MAX_REQUIREMENTS)


class StandardPatch(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=120)
    name_fa: Optional[str] = Field(None, max_length=160)
    version: Optional[str] = Field(None, max_length=40)
    description: Optional[str] = Field(None, max_length=4000)
    description_fa: Optional[str] = Field(None, max_length=4000)
    enabled: Optional[bool] = None


def _new_key(db: Session) -> str:
    n = db.query(ComplianceStandard).count() + 1
    while db.query(ComplianceStandard).filter(ComplianceStandard.key == f"custom-{n}").first():
        n += 1
    return f"custom-{n}"


@router.post("/standards", status_code=201)
def create_standard(body: StandardIn, request: Request,
                    current_user: User = Depends(require_permission("auditing", "write")),
                    db: Session = Depends(get_db)):
    """A new, empty standard of the organisation's (requirements are added to it one by one)."""
    from app.models.security_audit_log import log_action
    _need_role(current_user, UserRole.ADMIN, UserRole.MANAGER)
    std = ComplianceStandard(key=_new_key(db), builtin=False, enabled=True, created_by=current_user.id,
                             **body.model_dump())
    db.add(std)
    db.flush()
    log_action(db, user_id=current_user.id, username=current_user.username, action="compliance.standard_create",
               module="auditing", target_id=std.id, ip_address=_ip(request),
               detail=f"Created the standard {std.name}")
    db.commit()
    return _std_out(std)


@router.post("/standards/import", status_code=201)
def import_standard(body: StandardImport, request: Request,
                    current_user: User = Depends(require_permission("auditing", "write")),
                    db: Session = Depends(get_db)):
    """A standard from a definition file (the export format): always a new standard of the organisation's."""
    from app.models.security_audit_log import log_action
    _need_role(current_user, UserRole.ADMIN, UserRole.MANAGER)
    refs = [r.ref for r in body.requirements]
    if len(refs) != len(set(refs)):
        raise HTTPException(status_code=400, detail="Two requirements have the same reference")
    sections = {s.ref for s in body.sections}
    if len(sections) != len(body.sections):
        raise HTTPException(status_code=400, detail="Two sections have the same reference")
    data = {"sections": [s.model_dump() for s in body.sections],
            "requirements": [{"ref": r.ref, "section": r.section if r.section in sections else None,
                              "title": r.title, "title_fa": r.title_fa, "mapping": r.mapping.as_dict()}
                             for r in body.requirements]}
    std = ComplianceStandard(key=_new_key(db), builtin=False, enabled=True, created_by=current_user.id,
                             **StandardIn(**body.model_dump(include=set(StandardIn.model_fields))).model_dump())
    db.add(std)
    db.flush()
    service.apply_definition(db, std, data)
    log_action(db, user_id=current_user.id, username=current_user.username, action="compliance.standard_import",
               module="auditing", target_id=std.id, ip_address=_ip(request),
               detail=f"Imported the standard {std.name} with {len(refs)} requirements")
    db.commit()
    return _std_out(std)


@router.patch("/standards/{standard_id}")
def update_standard(standard_id: int, body: StandardPatch, request: Request,
                    current_user: User = Depends(require_permission("auditing", "write")),
                    db: Session = Depends(get_db)):
    """Rename or describe the organisation's standard; turn any standard on or off."""
    from app.models.security_audit_log import log_action
    _need_role(current_user, UserRole.ADMIN, UserRole.MANAGER)
    std = _standard(db, standard_id)
    changes = body.model_dump(exclude_unset=True)
    toggle = changes.pop("enabled", None)
    if changes:
        _custom(std)
        for k, v in changes.items():
            setattr(std, k, v)
        log_action(db, user_id=current_user.id, username=current_user.username, action="compliance.standard_update",
                   module="auditing", target_id=std.id, ip_address=_ip(request),
                   detail=f"Changed the standard {std.name}")
    if toggle is not None and toggle != std.enabled:
        std.enabled = toggle
        log_action(db, user_id=current_user.id, username=current_user.username, action="compliance.standard_toggle",
                   module="auditing", target_id=std.id, ip_address=_ip(request),
                   detail=f"Turned on the standard {std.name}" if toggle else f"Turned off the standard {std.name}")
    db.commit()
    return _std_out(std)


@router.delete("/standards/{standard_id}")
def delete_standard(standard_id: int, request: Request,
                    current_user: User = Depends(require_permission("auditing", "write")),
                    db: Session = Depends(get_db)):
    from app.models.security_audit_log import log_action
    _need_role(current_user, UserRole.ADMIN, UserRole.MANAGER)
    std = _standard(db, standard_id)
    _custom(std)
    name = std.name
    db.delete(std)
    log_action(db, user_id=current_user.id, username=current_user.username, action="compliance.standard_delete",
               module="auditing", target_id=standard_id, ip_address=_ip(request),
               detail=f"Deleted the standard {name}")
    db.commit()
    return {"ok": True}


@router.post("/standards/{standard_id}/requirements", status_code=201)
def add_requirement(standard_id: int, body: RequirementIn, request: Request,
                    current_user: User = Depends(require_permission("auditing", "write")),
                    db: Session = Depends(get_db)):
    from app.models.security_audit_log import log_action
    _need_role(current_user, UserRole.ADMIN, UserRole.MANAGER)
    std = _standard(db, standard_id)
    _custom(std)
    q = db.query(ComplianceRequirement).filter(ComplianceRequirement.standard_id == std.id)
    if q.count() >= MAX_REQUIREMENTS:
        raise HTTPException(status_code=400, detail="A standard has at most 500 requirements")
    if q.filter(ComplianceRequirement.ref == body.ref).first():
        raise HTTPException(status_code=409, detail="A requirement with this reference already exists")
    mapping = body.mapping.as_dict()
    if body.section:
        _ensure_section(db, std, body.section)
    last = max([r.position for r in q] or [-1])
    req = ComplianceRequirement(standard_id=std.id, ref=body.ref, section=body.section or None, title=body.title,
                                title_fa=body.title_fa, mapping=mapping, position=last + 1)
    db.add(req)
    db.flush()
    log_action(db, user_id=current_user.id, username=current_user.username, action="compliance.requirement_add",
               module="auditing", target_id=req.id, ip_address=_ip(request),
               detail=f"Added requirement {req.ref} to the standard {std.name}")
    db.commit()
    return {"id": req.id}


def _ensure_section(db: Session, std: ComplianceStandard, ref: str) -> None:
    if not db.query(ComplianceSection).filter(ComplianceSection.standard_id == std.id,
                                              ComplianceSection.ref == ref).first():
        n = db.query(ComplianceSection).filter(ComplianceSection.standard_id == std.id).count()
        db.add(ComplianceSection(standard_id=std.id, ref=ref, title=ref, position=n))


@router.put("/requirements/{requirement_id}")
def update_requirement(requirement_id: int, body: RequirementIn, request: Request,
                       current_user: User = Depends(require_permission("auditing", "write")),
                       db: Session = Depends(get_db)):
    from app.models.security_audit_log import log_action
    _need_role(current_user, UserRole.ADMIN, UserRole.MANAGER)
    req = db.get(ComplianceRequirement, requirement_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Requirement not found")
    std = _standard(db, req.standard_id)
    _custom(std)
    if body.ref != req.ref and db.query(ComplianceRequirement).filter(
            ComplianceRequirement.standard_id == std.id, ComplianceRequirement.ref == body.ref).first():
        raise HTTPException(status_code=409, detail="A requirement with this reference already exists")
    if body.section:
        _ensure_section(db, std, body.section)
    req.ref, req.section, req.title, req.title_fa = body.ref, body.section or None, body.title, body.title_fa
    req.mapping = body.mapping.as_dict()
    log_action(db, user_id=current_user.id, username=current_user.username, action="compliance.requirement_update",
               module="auditing", target_id=req.id, ip_address=_ip(request),
               detail=f"Changed requirement {req.ref} of the standard {std.name}")
    db.commit()
    return {"ok": True}


@router.delete("/requirements/{requirement_id}")
def delete_requirement(requirement_id: int, request: Request,
                       current_user: User = Depends(require_permission("auditing", "write")),
                       db: Session = Depends(get_db)):
    from app.models.security_audit_log import log_action
    _need_role(current_user, UserRole.ADMIN, UserRole.MANAGER)
    req = db.get(ComplianceRequirement, requirement_id)
    if req is None:
        raise HTTPException(status_code=404, detail="Requirement not found")
    std = _standard(db, req.standard_id)
    _custom(std)
    ref = req.ref
    db.delete(req)
    log_action(db, user_id=current_user.id, username=current_user.username, action="compliance.requirement_delete",
               module="auditing", target_id=requirement_id, ip_address=_ip(request),
               detail=f"Deleted requirement {ref} of the standard {std.name}")
    db.commit()
    return {"ok": True}


# ── domains of the checks ────────────────────────────────────────────────

@router.get("/checks")
def list_checks(benchmark: Optional[str] = Query(None, max_length=40), q: Optional[str] = Query(None, max_length=100),
                domain: Optional[str] = Query(None, max_length=40), unclassified: bool = False,
                offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
                current_user: User = Depends(require_permission("auditing", "read")),
                db: Session = Depends(get_db)):
    """The checks of the latest audits with their domains (automatic or corrected), to review the mapping."""
    rows = service.check_stats(db)
    if benchmark:
        rows = [s for s in rows if s.benchmark == benchmark]
    if q:
        needle = q.strip().lower()
        rows = [s for s in rows if needle in s.check_number.lower() or needle in s.title.lower()]
    if domain:
        rows = [s for s in rows if domain in s.domains]
    if unclassified:
        rows = [s for s in rows if not s.domains]
    return {"total": len(rows), "checks": [_check_out(s) for s in rows[offset:offset + limit]],
            "benchmarks": sorted({s.benchmark for s in service.check_stats(db)})}


class DomainsIn(BaseModel):
    benchmark: str = Field(..., max_length=40)
    check_number: str = Field(..., min_length=1, max_length=50)
    domains: Optional[List[str]] = Field(None, max_length=len(D.DOMAINS))   # None: back to automatic


@router.put("/checks/domains")
def set_check_domains(body: DomainsIn, request: Request,
                      current_user: User = Depends(require_permission("auditing", "write")),
                      db: Session = Depends(get_db)):
    """Correct the domains of one check (administrators); None puts it back to the automatic ones."""
    from app.models.security_audit_log import log_action
    _need_role(current_user, UserRole.ADMIN)
    if body.benchmark not in _BENCHMARKS:
        raise HTTPException(status_code=400, detail="Unknown benchmark")
    row = db.query(ComplianceCheckDomains).filter(ComplianceCheckDomains.benchmark == body.benchmark,
                                                  ComplianceCheckDomains.check_number == body.check_number).first()
    check, bench = body.check_number, body.benchmark
    if body.domains is None:
        if row is not None:
            db.delete(row)
        log_action(db, user_id=current_user.id, username=current_user.username, action="compliance.check_domains",
                   module="auditing", ip_address=_ip(request),
                   detail=f"Put the domains of check {check} ({bench}) back to automatic")
    else:
        unknown = [d for d in body.domains if d not in D.DOMAINS]
        if unknown:
            raise HTTPException(status_code=400, detail=f"Unknown domain: {unknown[0]}")
        if row is None:
            row = ComplianceCheckDomains(benchmark=bench, check_number=check)
            db.add(row)
        row.domains = [d for d in D.DOMAINS if d in body.domains]
        row.updated_by, row.updated_at = current_user.id, datetime.utcnow()
        log_action(db, user_id=current_user.id, username=current_user.username, action="compliance.check_domains",
                   module="auditing", ip_address=_ip(request),
                   detail=f"Set the domains of check {check} ({bench})")
    db.commit()
    return {"ok": True}
