"""
The main dashboard: what needs action now, how much of the estate each module covers, where risk and
compliance have been heading, and the riskiest assets.

Every part is read with the permission of the module it comes from, so a user with only some modules
still gets a dashboard of those. Nothing here writes; it only counts what the modules already keep.

  attention   counts of things someone has to act on, only those above zero, each with the page that
              lists them: assets with actively exploited vulnerabilities (KEV), critical alerts nobody
              acknowledged, overdue remediation, monitored devices that stopped answering,
              configuration changes made outside NGCorion this week, expired or expiring certificates,
              assets on software past its end of life, requests waiting for this user's approval,
              scheduled jobs whose last run failed, and a failed backup of NGCorion itself.
  coverage    assets audited in the last 90 days, devices with a recent configuration backup, assets
              monitored over SNMP.
  trend       the average risk score and the average compliance over 90 days, one point every 5 days,
              each point the latest known value of every asset at that moment (not the average of the
              runs in between, which would count an asset audited ten times ten times).
  top_assets  the ten riskiest assets with the factor that adds most to their score.
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.models import Asset, User
from app.models.audit import AuditSession
from app.models.audit_policy import STATUS_PENDING, AuditPolicyRule
from app.models.backup import DeviceBackup
from app.models.noc import AssetSnmpCredential, AssetSnmpStatus
from app.models.notification import ALERT_ACTIVE, Alert
from app.models.remediation import ACCEPT_PENDING, ITEM_ACTIVE, RemediationItem, RiskAcceptance
from app.models.risk import AssetRiskScore
from app.models.scheduling import ScheduledJob
from app.models.system_backup import BK_PENDING, SystemBackup
from app.modules.alerts.router import visible_modules
from app.modules.reports.service import _role, can_read

TREND_DAYS = 90
TREND_STEP_DAYS = 5
CHANGE_DAYS = 30
AUDIT_FRESH_DAYS = 90
EXTERNAL_CHANGE_DAYS = 7
CERT_WARN_DAYS = 30
TOP_ASSETS = 10

# Risk factors, in the order the risk page shows them: response key -> AssetRiskScore column.
FACTORS = (
    ("criticality", "criticality_contribution"),
    ("asset_risk", "asset_risk_contribution"),
    ("zone", "zone_contribution"),
    ("open_ports", "open_port_contribution"),
    ("audit", "audit_contribution"),
    ("hardening", "hardening_contribution"),
    ("vulnerability", "vulnerability_contribution"),
)

# Scheduled job type -> (permission module, page of its schedules).
JOB_PAGES = {
    "discovery": ("asset_auto_discovery", "/assets/schedule-discovery"),
    "audit": ("auditing", "/audit/schedule-auditing"),
    "backup": ("backup", "/backup/schedules"),
}


def _item(key: str, count: int, severity: str, link: str) -> Optional[Dict]:
    return {"key": key, "count": int(count), "severity": severity, "link": link} if count else None


def attention(db: Session, user: User, now: datetime) -> List[Dict]:
    """What needs action now, for this user's modules: [{key, count, severity, link}], counts above zero."""
    out = []
    role = _role(user)
    approver = role in ("admin", "manager")

    if can_read(db, user, "cve"):
        kev = db.query(func.count(AssetRiskScore.id)).filter(AssetRiskScore.cve_kev_count > 0).scalar()
        out.append(_item("kev_assets", kev, "critical", "/cve"))

    modules = visible_modules(db, user)
    critical = (db.query(func.count(Alert.id))
                .filter(Alert.module.in_(modules), Alert.status == ALERT_ACTIVE, Alert.severity == "critical")
                .scalar()) if modules else 0
    out.append(_item("critical_alerts", critical, "critical", "/alerts?severity=critical"))

    if can_read(db, user, "noc"):
        down = (db.query(func.count(AssetSnmpStatus.id))
                .join(AssetSnmpCredential, AssetSnmpCredential.asset_id == AssetSnmpStatus.asset_id)
                .filter(AssetSnmpStatus.reachable.is_(False)).scalar())
        out.append(_item("devices_down", down, "critical", "/noc/hosts"))

    if role == "admin":
        last = (db.query(SystemBackup.status).filter(SystemBackup.status.notin_(BK_PENDING))
                .order_by(SystemBackup.created_at.desc(), SystemBackup.id.desc()).first())
        out.append(_item("system_backup_failed", 1 if last and last[0] == "failed" else 0, "critical",
                         "/settings/system-backup"))

    if can_read(db, user, "remediation"):
        overdue = (db.query(func.count(RemediationItem.id))
                   .filter(RemediationItem.status.in_(ITEM_ACTIVE), RemediationItem.due_at < now).scalar())
        out.append(_item("overdue_remediation", overdue, "high", "/remediation?view=overdue"))

    if can_read(db, user, "cve"):
        from app.modules.tls import service as tls
        rows = [r for r in tls.evaluate(db, now=now) if r["endpoint"].enabled]
        expired = sum(1 for r in rows if any(p["code"] == "expired" for p in r["problems"]))
        soon = sum(1 for r in rows if r["endpoint"].not_after
                   and now < r["endpoint"].not_after <= now + timedelta(days=CERT_WARN_DAYS))
        out.append(_item("certificates_expired", expired, "high", "/cve/certificates"))
        out.append(_item("certificates_expiring", soon, "medium", "/cve/certificates"))

    if can_read(db, user, "asset_list"):
        from app.modules.eol import service as eol
        existing = {i for (i,) in db.query(Asset.id)}
        comps = [c for c in eol.components(db, today=now.date()) if c.asset_id in existing]
        unsupported = eol.summary(comps)["assets"].get("unsupported", 0)
        out.append(_item("eol_unsupported", unsupported, "high", "/assets/software/lifecycle"))

    if can_read(db, user, "backup"):
        changed = (db.query(func.count(func.distinct(DeviceBackup.asset_id)))
                   .filter(DeviceBackup.change_origin == "external",
                           DeviceBackup.created_at >= now - timedelta(days=EXTERNAL_CHANGE_DAYS)).scalar())
        out.append(_item("external_changes", changed, "medium", "/backup"))

    failed_jobs = {}
    for job_type, (module, link) in JOB_PAGES.items():
        if can_read(db, user, module):
            failed_jobs[job_type] = link
    if failed_jobs:
        counts = dict(db.query(ScheduledJob.job_type, func.count(ScheduledJob.id))
                      .filter(ScheduledJob.enabled.is_(True), ScheduledJob.last_run_status == "failed",
                              ScheduledJob.job_type.in_(tuple(failed_jobs)))
                      .group_by(ScheduledJob.job_type).all())
        for job_type, link in failed_jobs.items():
            out.append(_item(f"failed_jobs_{job_type}", counts.get(job_type, 0), "medium", link))

    if approver and can_read(db, user, "remediation"):
        waiting = (db.query(func.count(RiskAcceptance.id))
                   .filter(RiskAcceptance.status == ACCEPT_PENDING,
                           (RiskAcceptance.requested_by.is_(None)) | (RiskAcceptance.requested_by != user.id))
                   .scalar())
        out.append(_item("acceptances_pending", waiting, "info", "/remediation/acceptances"))
    if approver and can_read(db, user, "auditing"):
        waiting = (db.query(func.count(AuditPolicyRule.id))
                   .filter(AuditPolicyRule.status == STATUS_PENDING,
                           (AuditPolicyRule.requested_by.is_(None)) | (AuditPolicyRule.requested_by != user.id))
                   .scalar())
        out.append(_item("policy_pending", waiting, "info", "/remediation/policy"))

    return [i for i in out if i]


def coverage(db: Session, user: User, now: datetime, total_assets: int) -> List[Dict]:
    """How much of the estate each module covers: [{key, covered, total, link}]."""
    out = []
    if can_read(db, user, "auditing"):
        audited = (db.query(func.count(func.distinct(AuditSession.asset_id)))
                   .join(Asset, Asset.id == AuditSession.asset_id)
                   .filter(AuditSession.status != "running",
                           AuditSession.started_at >= now - timedelta(days=AUDIT_FRESH_DAYS)).scalar())
        out.append({"key": "audited", "covered": int(audited), "total": total_assets, "link": "/audit/sessions"})
    if can_read(db, user, "backup"):
        from app.modules.backup.overview import compute_overview
        b = compute_overview(db, now=now)
        out.append({"key": "backed_up", "covered": b["fresh"], "total": b["supported"], "link": "/backup/overview"})
    if can_read(db, user, "noc"):
        monitored = db.query(func.count(AssetSnmpCredential.id)).scalar()
        out.append({"key": "monitored", "covered": int(monitored), "total": total_assets, "link": "/noc/hosts"})
    return out


def _points(now: datetime) -> List[datetime]:
    steps = TREND_DAYS // TREND_STEP_DAYS
    return [now - timedelta(days=TREND_STEP_DAYS * k) for k in range(steps, -1, -1)]


_RISK_TREND = text("""
    SELECT p.t AS at, ROUND(AVG(h.risk_score)::numeric, 1) AS value, COUNT(*) AS assets
    FROM unnest(CAST(:points AS timestamp[])) AS p(t)
    JOIN LATERAL (
        SELECT DISTINCT ON (asset_id) risk_score
        FROM asset_risk_history
        WHERE calculated_at <= p.t
        ORDER BY asset_id, calculated_at DESC, id DESC
    ) h ON TRUE
    GROUP BY p.t
""")

_COMPLIANCE_TREND = text("""
    SELECT p.t AS at, ROUND(AVG(s.compliance_pct)::numeric, 1) AS value, COUNT(*) AS assets
    FROM unnest(CAST(:points AS timestamp[])) AS p(t)
    JOIN LATERAL (
        SELECT DISTINCT ON (a.asset_id) a.compliance_pct
        FROM audit_sessions a
        WHERE a.asset_id IS NOT NULL AND a.status <> 'running' AND a.compliance_pct IS NOT NULL
          AND a.started_at <= p.t
        ORDER BY a.asset_id, a.started_at DESC, a.id DESC
    ) s ON TRUE
    GROUP BY p.t
""")


def _series(db: Session, query, points: List[datetime]) -> Dict:
    """{points: [{at, value, assets}], change: the change over the last 30 days or None}. A moment before
    the first value counts as no data, not as zero."""
    found = {r["at"]: r for r in db.execute(query, {"points": points}).mappings()}
    series = [{"at": p.isoformat() + "Z", "value": float(found[p]["value"]), "assets": int(found[p]["assets"])}
              for p in points if p in found]
    back = CHANGE_DAYS // TREND_STEP_DAYS
    change = None
    if points[-1] in found and points[-1 - back] in found:
        change = round(float(found[points[-1]]["value"]) - float(found[points[-1 - back]]["value"]), 1)
    return {"points": series, "change": change}


def trend(db: Session, user: User, now: datetime) -> Dict:
    points = _points(now)
    out = {}
    if can_read(db, user, "risk"):
        out["risk"] = _series(db, _RISK_TREND, points)
    if can_read(db, user, "auditing"):
        out["compliance"] = _series(db, _COMPLIANCE_TREND, points)
    return out


def top_assets(db: Session, user: User) -> Optional[List[Dict]]:
    """The riskiest assets, each with the factor that adds most to its score (None without risk access)."""
    if not can_read(db, user, "risk"):
        return None
    rows = (db.query(AssetRiskScore, Asset).join(Asset, Asset.id == AssetRiskScore.asset_id)
            .order_by(AssetRiskScore.final_risk_score.desc(), AssetRiskScore.id).limit(TOP_ASSETS).all())
    out = []
    for score, asset in rows:
        parts = {key: float(getattr(score, col) or 0) for key, col in FACTORS}
        total = sum(parts.values())
        main = max(parts, key=parts.get) if total > 0 else None
        out.append({
            "asset_id": asset.id, "asset_name": asset.asset_name, "ip_address": asset.ip_address,
            "score": float(score.final_risk_score or 0), "level": score.risk_level,
            "main_factor": main, "main_factor_share": round(100 * parts[main] / total) if main else None,
            "kev": int(score.cve_kev_count or 0), "incomplete": bool(score.incomplete_data),
        })
    return out


def overview(db: Session, user: User, now: Optional[datetime] = None) -> Dict:
    now = now or datetime.utcnow()
    total = db.query(func.count(Asset.id)).scalar() or 0
    return {
        "generated_at": now.isoformat() + "Z",
        "assets": {"total": int(total)} if can_read(db, user, "asset_list") else None,
        "attention": attention(db, user, now),
        "coverage": coverage(db, user, now, int(total)),
        "trend": trend(db, user, now),
        "top_assets": top_assets(db, user),
    }
