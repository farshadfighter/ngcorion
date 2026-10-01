"""
The events a notification rule can watch, and how each one is checked.

Every event type has an evaluator that looks at the current state of the
database and returns the problems it sees right now. Two kinds:

  state   a condition that holds or not (device unreachable, disk low). The
          alert stays open while the evaluator keeps reporting it and resolves
          by itself when it stops.
  event   something that happened once (a restore failed). Each occurrence is
          raised once, from rows newer than `since`, and is resolved by a person.

Evaluators only read; app/modules/alerts/engine.py turns problems into alerts.
"""
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings


@dataclass
class Problem:
    key: str                          # identifies the problem within its rule
    title: str
    detail: Optional[str] = None
    asset_id: Optional[int] = None
    source_label: Optional[str] = None
    link: Optional[str] = None
    owner_user_id: Optional[int] = None


@dataclass
class Param:
    key: str
    label: str
    default: float
    unit: str = ""
    min: float = 0
    max: float = 100000


@dataclass
class EventType:
    code: str
    module: str                       # noc | cve | audit | backup | system
    name: str
    summary: str                      # "{polls}" style placeholders from params
    kind: str                         # state | event
    every: int                        # seconds between checks
    evaluate: Callable
    params: List[Param] = field(default_factory=list)
    uses_assets: bool = False
    has_owner: bool = False           # problems carry the user behind them
    # Defaults for the rule seeded at install.
    severity: str = "warning"
    channels: List[str] = field(default_factory=lambda: ["email"])
    roles: List[str] = field(default_factory=lambda: ["admin"])
    repeat_minutes: int = 0
    enabled: bool = True

    def describe(self, params: Dict) -> str:
        values = {p.key: _fmt(params.get(p.key, p.default)) for p in self.params}
        return self.summary.format(**values)


def _fmt(value) -> str:
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _label(asset) -> str:
    if asset is None:
        return ""
    return f"{asset.asset_name} · {asset.ip_address}" if asset.ip_address else asset.asset_name


# ---------------------------------------------------------------------------
# NOC
# ---------------------------------------------------------------------------

def _device_unreachable(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models.noc import AssetSnmpStatus
    polls = int(params.get("polls", 3))
    rows = (db.query(AssetSnmpStatus).options(joinedload(AssetSnmpStatus.asset))
            .filter(AssetSnmpStatus.consecutive_poll_failures >= polls).all())
    out = []
    for s in rows:
        minutes = s.consecutive_poll_failures * settings.NOC_POLL_INTERVAL_SECONDS // 60
        detail = f"No answer to SNMP for {s.consecutive_poll_failures} polls in a row (about {minutes} min)"
        if s.error_message:
            detail += f" - {s.error_message[:200]}"
        out.append(Problem(key=f"asset:{s.asset_id}", title="Device unreachable", detail=detail,
                           asset_id=s.asset_id, source_label=_label(s.asset), link=f"/noc/hosts/{s.asset_id}"))
    return out


_IF_PREFIXES = (("tengigabitethernet", "te"), ("gigabitethernet", "gi"), ("fastethernet", "fa"),
                ("ethernet", "eth"), ("port-channel", "po"), ("vlan", "vl"))


def normalize_interface(name: Optional[str]) -> str:
    """'GigabitEthernet0/1', 'Gi0/1' and 'gi 0/1' are the same port."""
    value = re.sub(r"\s+", "", (name or "").lower())
    for long, short in _IF_PREFIXES:
        if value.startswith(long):
            return short + value[len(long):]
    return value


def _interface_name(iface) -> str:
    return iface.if_name or iface.if_descr or f"ifIndex {iface.if_index}"


def _linked_interfaces(db: Session) -> Dict[int, set]:
    """asset_id -> normalized interface names used by a Topology link."""
    from app.models.topology import TopologyLink
    out: Dict[int, set] = {}
    for link in db.query(TopologyLink).all():
        for asset_id, name in ((link.source_asset_id, link.source_interface),
                               (link.destination_asset_id, link.destination_interface)):
            if name:
                out.setdefault(asset_id, set()).add(normalize_interface(name))
    return out


def _interface_down(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models.noc import AssetSnmpInterface, AssetSnmpStatus
    linked_only = int(params.get("linked_only", 1)) == 1
    fresh_after = now - timedelta(seconds=settings.NOC_POLL_INTERVAL_SECONDS * 3)
    reachable = {s.asset_id for s in db.query(AssetSnmpStatus).filter(AssetSnmpStatus.reachable.is_(True))}
    linked = _linked_interfaces(db) if linked_only else {}
    rows = (db.query(AssetSnmpInterface).options(joinedload(AssetSnmpInterface.asset))
            .filter(AssetSnmpInterface.if_admin_status == "up", AssetSnmpInterface.if_oper_status == "down",
                    AssetSnmpInterface.last_polled_at >= fresh_after).all())
    out = []
    for iface in rows:
        if iface.asset_id not in reachable:
            continue                  # the device itself is the problem; "unreachable" covers it
        if linked_only:
            names = {normalize_interface(iface.if_name), normalize_interface(iface.if_descr)}
            if not names & linked.get(iface.asset_id, set()):
                continue
        name = _interface_name(iface)
        detail = f"{name} is down while enabled" + (f" ({iface.if_alias})" if iface.if_alias else "")
        out.append(Problem(key=f"if:{iface.id}", title="Interface down", detail=detail, asset_id=iface.asset_id,
                           source_label=_label(iface.asset), link=f"/noc/hosts/{iface.asset_id}"))
    return out


def _interface_utilization(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    """Average utilization of each interface over the last `minutes`, from the
    first and last octet counters in that window (no per-sample scan)."""
    from app.models.noc import AssetSnmpInterface
    percent = float(params.get("percent", 90))
    minutes = int(params.get("minutes", 10))
    start = now - timedelta(minutes=minutes)
    rows = db.execute(text("""
        SELECT interface_id, metric_type,
               (array_agg(value ORDER BY sampled_at ASC))[1]  AS first_value,
               (array_agg(value ORDER BY sampled_at DESC))[1] AS last_value,
               min(sampled_at) AS first_at, max(sampled_at) AS last_at
        FROM asset_metric_samples
        WHERE sampled_at >= :start AND interface_id IS NOT NULL
          AND metric_type IN ('if_in_octets', 'if_out_octets')
        GROUP BY interface_id, metric_type
    """), {"start": start}).all()
    rates: Dict[int, Dict[str, float]] = {}
    for r in rows:
        seconds = (r.last_at - r.first_at).total_seconds()
        # Need most of the window covered, and a counter that did not wrap or reset.
        if seconds < minutes * 60 * 0.7 or r.last_value < r.first_value:
            continue
        rates.setdefault(r.interface_id, {})[r.metric_type] = (r.last_value - r.first_value) * 8 / seconds
    if not rates:
        return []
    out = []
    for iface in (db.query(AssetSnmpInterface).options(joinedload(AssetSnmpInterface.asset))
                  .filter(AssetSnmpInterface.id.in_(list(rates)), AssetSnmpInterface.if_speed > 0)):
        r = rates[iface.id]
        used = {k: v / iface.if_speed * 100 for k, v in r.items()}
        direction, value = max(used.items(), key=lambda kv: kv[1])
        if value < percent:
            continue
        way = "in" if direction == "if_in_octets" else "out"
        out.append(Problem(key=f"util:{iface.id}", title="Interface utilization high",
                           detail=f"{_interface_name(iface)} at {value:.0f}% ({way}) on average over {minutes} min",
                           asset_id=iface.asset_id, source_label=_label(iface.asset),
                           link=f"/noc/hosts/{iface.asset_id}"))
    return out


# ---------------------------------------------------------------------------
# CVE
# ---------------------------------------------------------------------------

def _cve_loaded(db: Session) -> bool:
    from app.modules.cve import settings as cve_settings
    return bool(cve_settings.get(db, cve_settings.WATERMARK))


def _per_asset(findings: List[dict], title: str, key: str) -> List[Problem]:
    by_asset: Dict[int, List[dict]] = {}
    for f in findings:
        by_asset.setdefault(f["asset_id"], []).append(f)
    out = []
    for asset_id, items in by_asset.items():
        ids = [f["cve_id"] for f in items]
        shown = ", ".join(ids[:4]) + (f" and {len(ids) - 4} more" if len(ids) > 4 else "")
        first = items[0]
        product = first.get("product") or ""
        label = f"{first['asset_name']} · {first['ip_address']}" if first.get("ip_address") else first["asset_name"]
        detail = f"{shown}" + (f" ({product})" if product and len({f.get('product') for f in items}) == 1 else "")
        out.append(Problem(key=f"{key}:{asset_id}", title=title, detail=detail, asset_id=asset_id,
                           source_label=label, link="/cve"))
    return out


def _cve_kev(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    if not _cve_loaded(db):
        return []
    from app.modules.cve import findings
    rows = [f for f in findings.compute(db)["findings"] if f["kev"]]
    return _per_asset(rows, "Exploited vulnerability on an asset", "kev")


def _cve_critical(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    if not _cve_loaded(db):
        return []
    from app.modules.cve import findings
    floor = float(params.get("cvss", 9))
    rows = [f for f in findings.compute(db)["findings"] if (f["cvss"] or 0) >= floor]
    return _per_asset(rows, f"Vulnerability with CVSS {_fmt(floor)} or higher", "crit")


def _cve_outdated(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.modules.cve import settings as cve_settings
    from app.modules.cve.feeds import iso_to_dt
    days = int(params.get("days", 7))
    watermark = iso_to_dt(cve_settings.get(db, cve_settings.WATERMARK))
    if watermark is None or now - watermark < timedelta(days=days):
        return []
    age = (now - watermark).days
    return [Problem(key="cve-db", title="CVE database outdated",
                    detail=f"Last update {watermark:%Y-%m-%d} - {age} days ago. Findings may miss new vulnerabilities.",
                    source_label="NGCorion", link="/cve/database")]


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def _scheduled_failed(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models.scheduling import ScheduledJob, ScheduledJobRun
    rows = (db.query(ScheduledJobRun, ScheduledJob).join(ScheduledJob, ScheduledJob.id == ScheduledJobRun.job_id)
            .options(joinedload(ScheduledJob.asset))
            .filter(ScheduledJobRun.status == "failed", ScheduledJobRun.finished_at >= since).all())
    out = []
    for run, job in rows:
        kind = "audit" if job.job_type == "audit" else "discovery"
        asset = job.asset
        out.append(Problem(
            key=f"run:{run.id}", title=f"Scheduled {kind} failed",
            detail=f"{job.job_name}: {(run.message or 'no reason given')[:300]}",
            asset_id=job.asset_id, source_label=_label(asset) if asset else job.job_name,
            link="/audit/schedule-auditing" if kind == "audit" else "/assets/schedule-discovery",
            owner_user_id=job.created_by))
    return out


def _compliance_drop(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models import Asset
    from app.models.audit import AuditSession
    points = float(params.get("points", 10))
    recent = (db.query(AuditSession)
              .filter(AuditSession.status == "completed", AuditSession.completed_at >= since,
                      AuditSession.asset_id.isnot(None), AuditSession.compliance_pct.isnot(None)).all())
    out = []
    for s in recent:
        before = (db.query(AuditSession)
                  .filter(AuditSession.asset_id == s.asset_id, AuditSession.device_type == s.device_type,
                          AuditSession.status == "completed", AuditSession.compliance_pct.isnot(None),
                          AuditSession.completed_at < s.completed_at)
                  .order_by(AuditSession.completed_at.desc()).first())
        if before is None or before.compliance_pct - s.compliance_pct < points:
            continue
        asset = db.get(Asset, s.asset_id)
        out.append(Problem(
            key=f"audit:{s.id}", title="Compliance dropped",
            detail=f"{before.compliance_pct:.0f}% -> {s.compliance_pct:.0f}% since the audit of "
                   f"{before.completed_at:%Y-%m-%d}",
            asset_id=s.asset_id, source_label=_label(asset) if asset else s.target_ip,
            link=f"/audit/sessions/{s.id}", owner_user_id=s.user_id))
    return out


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------

def _restore_failed(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models.backup_restore import BackupRestore
    rows = (db.query(BackupRestore)
            .filter(BackupRestore.status.in_(("failed", "reverted")), BackupRestore.finished_at >= since).all())
    out = []
    for r in rows:
        title = "Restore reverted automatically" if r.status == "reverted" else "Restore failed"
        label = f"{r.asset_name} · {r.device_ip}" if r.device_ip else (r.asset_name or f"Restore #{r.id}")
        out.append(Problem(key=f"restore:{r.id}", title=title, detail=(r.error or "")[:400] or None,
                           asset_id=r.asset_id, source_label=label, link=f"/backup/restores?restore={r.id}",
                           owner_user_id=r.requested_by))
    return out


def _backup_stale(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.modules.backup.overview import compute_overview
    days = int(params.get("days", 30))
    overview = compute_overview(db, now, stale_days=days)
    late = [d for d in overview["attention"] if d["state"] in ("stale", "never")]
    if not late:
        return []
    dated = [d["last_backup_at"] for d in late if d["last_backup_at"]]
    never = sum(1 for d in late if d["last_backup_at"] is None)
    parts = []
    if dated:
        parts.append(f"oldest {(now - min(dated)).days} days")
    if never:
        parts.append(f"{never} never backed up")
    total = overview["attention_total"]
    return [Problem(key="stale", title=f"No backup for {days} days",
                    detail=f"{total} device{'s' if total != 1 else ''} - " + ", ".join(parts),
                    source_label=f"{total} device{'s' if total != 1 else ''}", link="/backup/overview")]


# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------

def _license_problem(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.core.license_state import get_license_state
    state = get_license_state()
    if state.valid and not state.offline:
        return []
    if state.valid:
        title, detail = "License server unreachable", "Running on the last validated license. " + state.message
    else:
        title, detail = "License is not valid", state.message
    return [Problem(key="license", title=title, detail=detail, source_label="NGCorion", link="/settings/license")]


BACKGROUND_TASKS = (("job-scheduler", "Job scheduler"), ("noc-poller", "NOC poller"),
                    ("noc-metrics-retention", "NOC metrics rollup"), ("cve-auto-update", "CVE automatic update"))


def _task_stopped(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.modules.system_health import _lock_held
    return [Problem(key=f"task:{name}", title="Background task stopped",
                    detail=f"{label} is not running in any worker", source_label="NGCorion",
                    link="/settings/system")
            for name, label in BACKGROUND_TASKS if not _lock_held(db, name)]


def disk_paths() -> List[str]:
    return [os.getenv("CVE_DATA_DIR") or tempfile.gettempdir(),
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))]


def _disk_low(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    floor = float(params.get("gb", 2))
    out, seen = [], set()
    for path in disk_paths():
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            continue
        if usage.total in seen:
            continue
        seen.add(usage.total)
        free = usage.free / 1024 ** 3
        if free < floor:
            out.append(Problem(key=f"disk:{path}", title="Disk space low",
                               detail=f"{free:.1f} GB free of {usage.total / 1024 ** 3:.0f} GB ({path})",
                               source_label="NGCorion", link="/settings/system"))
    return out


EVENTS: Dict[str, EventType] = {e.code: e for e in (
    EventType("noc.device_unreachable", "noc", "Device unreachable",
              "No SNMP answer for {polls} polls in a row", "state", 60, _device_unreachable,
              params=[Param("polls", "Polls in a row", 3, "polls", 1, 60)], uses_assets=True,
              severity="critical", channels=["email", "sms"], repeat_minutes=60),
    EventType("noc.interface_down", "noc", "Interface down",
              "An enabled interface goes down", "state", 60, _interface_down,
              params=[Param("linked_only", "Only interfaces used by a Topology link (1 = yes, 0 = every port)",
                            1, "", 0, 1)], uses_assets=True),
    EventType("noc.interface_utilization", "noc", "Interface utilization high",
              "Above {percent}% for {minutes} minutes", "state", 300, _interface_utilization,
              params=[Param("percent", "Utilization", 90, "%", 1, 100),
                      Param("minutes", "For", 10, "minutes", 5, 240)], uses_assets=True, channels=[]),
    EventType("cve.kev_finding", "cve", "Exploited vulnerability on an asset",
              "A finding in CISA KEV appears on an asset", "state", 900, _cve_kev, uses_assets=True,
              severity="critical", channels=["email", "syslog"]),
    EventType("cve.critical_finding", "cve", "Critical vulnerability",
              "A finding with CVSS {cvss} or higher", "state", 900, _cve_critical,
              params=[Param("cvss", "CVSS at least", 9, "", 0, 10)], uses_assets=True),
    EventType("cve.database_outdated", "cve", "CVE database outdated",
              "No successful update for {days} days", "state", 3600, _cve_outdated,
              params=[Param("days", "Days without update", 7, "days", 1, 365)],
              severity="info", channels=[]),
    EventType("audit.scheduled_failed", "audit", "Scheduled job failed",
              "A scheduled audit or discovery could not run or finish", "event", 60, _scheduled_failed,
              uses_assets=True, has_owner=True),
    EventType("audit.compliance_drop", "audit", "Compliance dropped",
              "An asset falls {points} points or more below its previous audit", "event", 300, _compliance_drop,
              params=[Param("points", "Drop of at least", 10, "points", 1, 100)], uses_assets=True,
              has_owner=True, channels=[], enabled=False),
    EventType("backup.restore_failed", "backup", "Restore failed or reverted",
              "A restore ends failed or is reverted automatically", "event", 60, _restore_failed,
              uses_assets=True, has_owner=True),
    EventType("backup.stale", "backup", "Device without a recent backup",
              "Devices with no backup for {days} days", "state", 3600, _backup_stale,
              params=[Param("days", "Days without backup", 30, "days", 1, 365)], repeat_minutes=1440),
    EventType("system.license", "system", "License problem",
              "The license is not valid, or its server cannot be reached", "state", 300, _license_problem,
              severity="critical", channels=["email", "sms"], repeat_minutes=1440),
    EventType("system.task_stopped", "system", "Background task stopped",
              "Scheduler, NOC poller or CVE update not running for {minutes} minutes", "state", 60, _task_stopped,
              params=[Param("minutes", "Not running for", 5, "minutes", 2, 120)],
              severity="critical", channels=["email", "syslog"]),
    EventType("system.disk_low", "system", "Disk space low",
              "Less than {gb} GB free", "state", 600, _disk_low,
              params=[Param("gb", "Free space below", 2, "GB", 1, 1000)]),
)}

MODULE_LABELS = {"noc": "NOC", "cve": "CVE", "audit": "Audit & Hardening", "backup": "Backup & Restore",
                 "system": "System"}
MODULE_ORDER = ("noc", "cve", "audit", "backup", "system")
