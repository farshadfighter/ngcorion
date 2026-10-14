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
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings


@dataclass
class Problem:
    """One problem an event check found: its identity within the rule (for one alert per problem), the
    texts and the asset it concerns.
    """
    key: str                          # identifies the problem within its rule
    title: str
    detail: Optional[str] = None
    asset_id: Optional[int] = None
    source_label: Optional[str] = None
    link: Optional[str] = None
    owner_user_id: Optional[int] = None


@dataclass
class Param:
    """A threshold of an event type that a rule can set (with unit and range)."""
    key: str
    label: str
    default: float
    unit: str = ""
    min: float = 0
    max: float = 100000


@dataclass
class EventType:
    """A kind of alert: its module, texts, whether it is a lasting state or a one-off event, how often
    it is checked, its thresholds, and the check function that returns the current problems.
    """
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
# Syslog received from the assets (app/modules/syslog)
# ---------------------------------------------------------------------------

def _syslog_severe(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    """Messages at the chosen severity or worse since the last check, one alert per asset and check."""
    from sqlalchemy import func
    from app.models import Asset
    from app.models.syslog import SyslogMessage
    level = int(params.get("severity", 2))
    since = since.replace(tzinfo=None) if since.tzinfo else since
    rows = (db.query(SyslogMessage.asset_id, func.count(SyslogMessage.id), func.max(SyslogMessage.id))
            .filter(SyslogMessage.received_at >= since, SyslogMessage.severity <= level)
            .group_by(SyslogMessage.asset_id).all())
    out = []
    for asset_id, n, last_id in rows:
        last = db.get(SyslogMessage, last_id)
        asset = db.get(Asset, asset_id)
        latest = f"{last.app_name}: {last.message}" if last.app_name else last.message
        latest = latest[:300]
        out.append(Problem(key=f"syslog:{asset_id}:{last_id}", title="Severe syslog message",
                           detail=f"{n} message(s), latest: {latest}",
                           asset_id=asset_id, source_label=_label(asset),
                           link=f"/noc/syslog?asset={asset_id}&severity={level}"))
    return out


def _syslog_silent(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    """Assets that used to send syslog and have been quiet for the chosen number of hours."""
    from app.models.syslog import SyslogSource
    from app.modules.syslog import settings as syslog_settings
    if not syslog_settings.get_settings(db)["enabled"]:
        return []
    hours = int(params.get("hours", 24))
    now = now.replace(tzinfo=None) if now.tzinfo else now
    rows = (db.query(SyslogSource).options(joinedload(SyslogSource.asset))
            .filter(SyslogSource.asset_id.isnot(None), SyslogSource.received > 0,
                    SyslogSource.last_seen < now - timedelta(hours=hours)).all())
    out = []
    for s in rows:
        last = s.last_seen
        out.append(Problem(key=f"asset:{s.asset_id}", title="Asset stopped sending syslog",
                           detail=f"No syslog message for {hours} hours or more (last one at {last:%Y-%m-%d %H:%M} UTC)",
                           asset_id=s.asset_id, source_label=_label(s.asset), link=f"/noc/syslog?asset={s.asset_id}"))
    return out


def _syslog_unknown(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    """Addresses outside the inventory that sent syslog in the last day (their messages are dropped)."""
    from app.models.syslog import SyslogSource
    now = now.replace(tzinfo=None) if now.tzinfo else now
    rows = (db.query(SyslogSource).filter(SyslogSource.asset_id.is_(None),
                                          SyslogSource.last_seen >= now - timedelta(hours=24))
            .order_by(SyslogSource.last_seen.desc()).limit(100).all())
    out = []
    for s in rows:
        dropped = s.dropped
        out.append(Problem(key=f"source:{s.source_ip}", title="Syslog from an address outside the inventory",
                           detail=f"{dropped} message(s) dropped; add the device to the inventory to keep them",
                           source_label=s.source_ip, link="/noc/syslog?tab=sources"))
    return out


def _syslog_not_listening(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    """The intake is turned on but the listener is not receiving (port taken, task stopped)."""
    from app.modules.syslog.router import listener_status
    now = now.replace(tzinfo=None) if now.tzinfo else now
    st = listener_status(db, now)
    if not st.enabled or st.listening and not st.error:
        return []
    reason = st.error or "the listener is not running"
    return [Problem(key="syslog:listener", title="Syslog intake not listening",
                    detail=f"Syslog intake is turned on but not receiving: {reason}", source_label="NGCorion",
                    link="/noc/syslog?tab=settings")]


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
    links = {"audit": "/audit/schedule-auditing", "discovery": "/assets/schedule-discovery",
             "backup": "/backup/schedules"}
    for run, job in rows:
        kind = job.job_type if job.job_type in links else "discovery"
        asset = job.asset
        out.append(Problem(
            key=f"run:{run.id}", title=f"Scheduled {kind} failed",
            detail=f"{job.job_name}: {(run.message or 'no reason given')[:300]}",
            asset_id=job.asset_id, source_label=_label(asset) if asset else job.job_name,
            link=links[kind], owner_user_id=job.created_by))
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


def _group_runs_failed(db: Session, kind: str, since: datetime) -> List[Problem]:
    from sqlalchemy import func
    from app.models.asset_groups import GroupRun, GroupRunItem
    rows = (db.query(GroupRun, func.count(GroupRunItem.id))
            .join(GroupRunItem, GroupRunItem.run_id == GroupRun.id)
            .filter(GroupRun.kind == kind, GroupRun.status.in_(("done", "stopped")), GroupRun.finished_at >= since,
                    GroupRunItem.status == "failed")
            .group_by(GroupRun.id).all())
    out = []
    for run, failed in rows:
        if kind == "backup":
            out.append(Problem(key=f"group_run:{run.id}", title="Group backup finished with failures",
                               detail=f"{run.group_name} ({run.technology}): {failed} asset(s) could not be backed up",
                               source_label=run.group_name, link=f"/backup/runs/{run.id}",
                               owner_user_id=run.started_by))
        else:
            out.append(Problem(key=f"group_run:{run.id}", title="Group audit finished with failures",
                               detail=f"{run.group_name} ({run.technology}): {failed} asset(s) could not be audited",
                               source_label=run.group_name, link=f"/audit/group-runs/{run.id}",
                               owner_user_id=run.started_by))
    return out


def _group_run_failed(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    return _group_runs_failed(db, "audit", since)


def _group_backup_failed(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    return _group_runs_failed(db, "backup", since)


def _config_changes(db: Session, origin: str, since: datetime) -> List[Problem]:
    from app.models import Asset
    from app.models.backup import DeviceBackup
    since = since.replace(tzinfo=None) if since.tzinfo else since     # backup times are naive UTC
    rows = (db.query(DeviceBackup)
            .filter(DeviceBackup.changed.is_(True), DeviceBackup.change_origin == origin,
                    DeviceBackup.created_at >= since)
            .order_by(DeviceBackup.id).all())
    from app.modules.syslog.config_changes import reports_for
    reports = reports_for(db, [b.id for b in rows if b.source == "on_change"])
    out = []
    for b in rows:
        asset = db.get(Asset, b.asset_id)
        label = _label(asset) if asset else (b.asset_name or b.device_ip or f"#{b.asset_id}")
        r = reports.get(b.id)
        if origin == "external" and r:
            out.append(Problem(key=f"backup:{b.id}", title="Configuration changed outside NGCorion",
                               detail=f"{b.added_lines or 0} line(s) added and {b.removed_lines or 0} removed; "
                                      f"changed by {r['reported_by'] or 'unknown user'} from "
                                      f"{r['reported_from'] or 'unknown address'} (reported over syslog)",
                               asset_id=b.asset_id, source_label=label, link=f"/backup?asset={b.asset_id}&compare={b.id}"))
        elif origin == "external":
            out.append(Problem(key=f"backup:{b.id}", title="Configuration changed outside NGCorion",
                               detail=f"{b.added_lines or 0} line(s) added and {b.removed_lines or 0} removed "
                                      f"since the previous backup",
                               asset_id=b.asset_id, source_label=label, link=f"/backup?asset={b.asset_id}&compare={b.id}"))
        else:
            out.append(Problem(key=f"backup:{b.id}", title="Configuration changed by NGCorion",
                               detail=f"{b.added_lines or 0} line(s) added and {b.removed_lines or 0} removed "
                                      f"({b.change_ref or 'hardening or restore'})",
                               asset_id=b.asset_id, source_label=label, link=f"/backup?asset={b.asset_id}&compare={b.id}"))
    return out


def _config_reported(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    """Changes devices reported over syslog that no scheduled backup covers (config_changes.py)."""
    from app.models import Asset
    from app.models.syslog import ConfigChangeEvent
    since = since.replace(tzinfo=None) if since.tzinfo else since
    rows = (db.query(ConfigChangeEvent)
            .filter(ConfigChangeEvent.status == "no_schedule", ConfigChangeEvent.processed_at >= since)
            .order_by(ConfigChangeEvent.id).all())
    per_asset: Dict[int, List] = {}
    for e in rows:
        per_asset.setdefault(e.asset_id, []).append(e)
    out = []
    for aid, events in per_asset.items():
        asset = db.get(Asset, aid)
        who = ", ".join(dict.fromkeys(e.changed_by for e in events if e.changed_by)) or "unknown user"
        where = ", ".join(dict.fromkeys(e.changed_from for e in events if e.changed_from)) or "unknown address"
        out.append(Problem(key=f"config_report:{events[-1].id}",
                           title="Configuration change reported, no backup taken",
                           detail=f"Changed by {who} from {where}; no scheduled backup covers this device",
                           asset_id=aid, source_label=_label(asset) if asset else f"#{aid}",
                           link=f"/noc/syslog?asset={aid}"))
    return out


def _config_changed_external(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    return _config_changes(db, "external", since)


def _config_changed_ngcorion(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    return _config_changes(db, "ngcorion", since)


def _credential_rotation(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.modules.asset_groups.profiles import rotation_due
    return [Problem(key=f"credential_profile:{p.id}", title="Credential profile due for a password change",
                    detail=f"{p.name}: password not changed for {p.rotation_days} days or more",
                    source_label=p.name, link="/settings/system") for p in rotation_due(db)]


# ---------------------------------------------------------------------------
# Sign-in through the directory (app/modules/directory)
# ---------------------------------------------------------------------------

def _directory_unreachable(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.modules.directory import service as directory
    status = directory.last_status(db) or {}
    if not directory.enabled(db) or status.get("ok", True):
        return []
    return [Problem(key="directory", title="Directory not reachable", detail=(status.get("error") or "")[:400] or None,
                    source_label="Active Directory / LDAP", link="/settings/system")]


def _emergency_login(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models.security_audit_log import AuditLog
    rows = (db.query(AuditLog).filter(AuditLog.action == "auth.emergency_login", AuditLog.timestamp >= since)
            .order_by(AuditLog.id).all())
    return [Problem(key=f"emergency:{r.id}", title="Local administrator signed in",
                    detail=f"{r.username} from {r.ip_address or 'unknown address'} while directory sign-in is on",
                    source_label=r.username, link="/settings/audit-trail", owner_user_id=r.user_id) for r in rows]


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
                    ("noc-metrics-retention", "NOC metrics rollup"), ("cve-auto-update", "CVE automatic update"),
                    ("system-backup", "NGCorion backup"), ("directory-check", "Directory account check"),
                    ("group-runs", "Group audits"), ("syslog-intake", "Syslog intake"))


def _task_stopped(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.modules.system_health import _lock_held
    return [Problem(key=f"task:{name}", title="Background task stopped",
                    detail=f"{label} is not running in any worker", source_label="NGCorion",
                    link="/settings/system")
            for name, label in BACKGROUND_TASKS if not _lock_held(db, name)]


def _disk_low(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.core.storage_guard import disk_paths
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


# ---------------------------------------------------------------------------
# Remediation (app/modules/remediation)
# ---------------------------------------------------------------------------

def _item_label(item) -> str:
    return f"{item.asset_name} · {item.ip_address}" if item.ip_address else (item.asset_name or "NGCorion")


def _remediation_overdue(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models.remediation import ITEM_ACTIVE, RemediationItem
    grace = timedelta(days=float(params.get("days", 0)))
    rows = (db.query(RemediationItem)
            .filter(RemediationItem.status.in_(ITEM_ACTIVE), RemediationItem.due_at.isnot(None),
                    RemediationItem.due_at < now - grace)
            .order_by(RemediationItem.due_at).all())
    return [Problem(key=f"item:{i.id}", title="Remediation overdue",
                    detail=f"{i.ref} - due {i.due_at:%Y-%m-%d}", asset_id=i.asset_id,
                    source_label=_item_label(i), link=f"/remediation?item={i.id}", owner_user_id=i.owner_id)
            for i in rows]


def _acceptance_pending(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models.remediation import ACCEPT_PENDING, RiskAcceptance
    rows = db.query(RiskAcceptance).filter(RiskAcceptance.status == ACCEPT_PENDING).all()
    return [Problem(key=f"acceptance:{a.id}", title="Risk acceptance waiting for approval",
                    detail=f"{a.ref} - until {a.expires_at:%Y-%m-%d}", asset_id=a.asset_id,
                    source_label="NGCorion", link="/remediation/acceptances")
            for a in rows]


def _acceptance_expiring(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models.remediation import ACCEPT_APPROVED, RiskAcceptance
    horizon = now + timedelta(days=float(params.get("days", 7)))
    rows = (db.query(RiskAcceptance)
            .filter(RiskAcceptance.status == ACCEPT_APPROVED, RiskAcceptance.expires_at > now,
                    RiskAcceptance.expires_at <= horizon).all())
    return [Problem(key=f"acceptance:{a.id}", title="Risk acceptance ending soon",
                    detail=f"{a.ref} - ends {a.expires_at:%Y-%m-%d}", asset_id=a.asset_id,
                    source_label="NGCorion", link="/remediation/acceptances", owner_user_id=a.requested_by)
            for a in rows]


def _report_schedule_failed(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models.report import ReportSchedule
    rows = (db.query(ReportSchedule)
            .filter(ReportSchedule.enabled.is_(True), ReportSchedule.last_status == "failed").all())
    return [Problem(key=f"schedule:{s.id}", title="Scheduled report failed",
                    detail=f"{s.name} - {(s.last_error or '')[:160]}", source_label="NGCorion",
                    link="/reports/schedules", owner_user_id=s.owner_id)
            for s in rows]


# ---------------------------------------------------------------------------
# NGCorion self-backup (app/modules/sysbackup)
# ---------------------------------------------------------------------------

BACKUP_LINK = "/settings/system-backup"


def _backup_failed(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models.system_backup import SystemBackup
    last = (db.query(SystemBackup).filter(SystemBackup.kind.in_(("scheduled", "manual")),
                                          SystemBackup.status.in_(("ready", "failed")))
            .order_by(SystemBackup.created_at.desc()).first())
    if last is None or last.status != "failed":
        return []
    return [Problem(key=f"backup:{last.id}", title="NGCorion backup failed",
                    detail=(last.error or "")[:200], source_label="NGCorion", link=BACKUP_LINK)]


def _backup_missing(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models.system_backup import SystemBackup
    from app.modules.sysbackup.service import get_settings
    cfg = get_settings(db)
    if not cfg["enabled"]:
        return []
    if not cfg["passphrase_set"]:
        return [Problem(key="backup:setup", title="NGCorion backups are not set up",
                        detail="Set the backup passphrase so daily backups can run", source_label="NGCorion",
                        link=BACKUP_LINK)]
    hours = float(params.get("hours", 48))
    recent = (db.query(SystemBackup.id).filter(SystemBackup.status == "ready",
                                               SystemBackup.kind != "uploaded",
                                               SystemBackup.finished_at >= now - timedelta(hours=hours)).first())
    if recent is not None:
        return []
    return [Problem(key="backup:stale", title="No recent NGCorion backup",
                    detail=f"No successful backup in the last {_fmt(hours)} hours", source_label="NGCorion",
                    link=BACKUP_LINK)]


def _backup_destination(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models.system_backup import BackupDestination
    rows = (db.query(BackupDestination).filter(BackupDestination.enabled.is_(True),
                                               BackupDestination.last_status == "failed").all())
    return [Problem(key=f"destination:{d.id}", title="Backup destination unreachable",
                    detail=f"{d.name}: {(d.last_error or '')[:160]}", source_label="NGCorion", link=BACKUP_LINK)
            for d in rows]


def _restore_test_failed(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    from app.models.system_backup import SystemRestore
    last = (db.query(SystemRestore).filter(SystemRestore.kind == "test",
                                           SystemRestore.status.in_(("succeeded", "failed")))
            .order_by(SystemRestore.created_at.desc()).first())
    if last is None or last.status != "failed":
        return []
    return [Problem(key=f"test:{last.id}", title="Backup restore test failed",
                    detail=f"{last.backup_label or ''}: {(last.error or '')[:160]}", source_label="NGCorion",
                    link=BACKUP_LINK)]


# ---------------------------------------------------------------------------
# Software inventory (app/modules/software)
# ---------------------------------------------------------------------------

def _software_unexpected(db: Session, params: Dict, now: datetime, since: datetime) -> List[Problem]:
    """Software that appeared on an asset from outside the repositories it
    already used: installed by hand, or from a repository new to the asset."""
    from app.models import Asset
    from app.models.software import SoftwareChange, SoftwareCollection, SoftwareItem
    rows = (db.query(SoftwareChange)
            .filter(SoftwareChange.change == "added", SoftwareChange.at >= since,
                    SoftwareChange.source.in_(("manual", "third_party"))).all())
    by_collection: Dict[int, List] = {}
    known_origins: Dict[tuple, set] = {}
    for ch in rows:
        if ch.source == "third_party":
            seen = (ch.asset_id, ch.at)
            if seen not in known_origins:
                known_origins[seen] = {o for (o,) in db.query(SoftwareItem.origin).filter(
                    SoftwareItem.asset_id == ch.asset_id, SoftwareItem.first_seen < ch.at,
                    SoftwareItem.origin.isnot(None)).distinct()}
            if ch.origin in known_origins[seen]:
                continue
        by_collection.setdefault(ch.collection_id, []).append(ch)
    out = []
    for cid, changes in by_collection.items():
        col = db.get(SoftwareCollection, cid)
        asset = db.get(Asset, changes[0].asset_id)
        names = sorted({c.name for c in changes})
        origins = sorted({c.origin for c in changes if c.source == "third_party" and c.origin})
        detail = ", ".join(names[:8]) + (f" +{len(names) - 8}" if len(names) > 8 else "")
        if origins:
            detail += " - from " + ", ".join(origins[:3])
        out.append(Problem(key=f"software:{cid}", title="New software outside known repositories",
                           detail=detail, asset_id=changes[0].asset_id,
                           source_label=_label(asset) if asset else None,
                           link=f"/assets/software?asset={changes[0].asset_id}",
                           owner_user_id=col.collected_by if col else None))
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
    EventType("noc.syslog_severe", "noc", "Severe syslog message",
              "An asset sends a syslog message at severity {severity} or worse (0 emergency ... 7 debug)",
              "event", 60, _syslog_severe,
              params=[Param("severity", "Severity (0 emergency, 1 alert, 2 critical, 3 error, 4 warning)", 2, "",
                            0, 7)], uses_assets=True),
    EventType("noc.syslog_silent", "noc", "Asset stopped sending syslog",
              "An asset that sends syslog has sent nothing for {hours} hours", "state", 600, _syslog_silent,
              params=[Param("hours", "Quiet for", 24, "hours", 1, 720)], uses_assets=True),
    EventType("noc.syslog_unknown", "noc", "Syslog from an address outside the inventory",
              "An address that is not an asset sends syslog (its messages are dropped)", "state", 600,
              _syslog_unknown, severity="info", channels=[], enabled=False),
    EventType("system.syslog_not_listening", "system", "Syslog intake not listening",
              "Syslog intake is turned on but the port cannot be opened or the listener stopped", "state", 120,
              _syslog_not_listening, severity="critical"),
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
    EventType("audit.group_run_failed", "audit", "Group audit finished with failures",
              "A group audit ends with assets that could not be audited", "event", 60, _group_run_failed,
              has_owner=True, roles=["admin", "manager"]),
    EventType("audit.compliance_drop", "audit", "Compliance dropped",
              "An asset falls {points} points or more below its previous audit", "event", 300, _compliance_drop,
              params=[Param("points", "Drop of at least", 10, "points", 1, 100)], uses_assets=True,
              has_owner=True, channels=[], enabled=False),
    EventType("backup.restore_failed", "backup", "Restore failed or reverted",
              "A restore ends failed or is reverted automatically", "event", 60, _restore_failed,
              uses_assets=True, has_owner=True),
    EventType("backup.group_run_failed", "backup", "Group backup finished with failures",
              "A group backup ends with devices that could not be backed up", "event", 60, _group_backup_failed,
              has_owner=True, roles=["admin", "manager"]),
    EventType("backup.config_changed", "backup", "Configuration changed outside NGCorion",
              "A device's configuration differs from its previous backup and NGCorion did not change it",
              "event", 60, _config_changed_external, uses_assets=True, severity="warning"),
    EventType("backup.config_changed_ngcorion", "backup", "Configuration changed by NGCorion",
              "A device's configuration changed through a hardening or restore run by NGCorion",
              "event", 60, _config_changed_ngcorion, uses_assets=True, severity="info", channels=[],
              enabled=False),
    EventType("backup.config_reported", "backup", "Configuration change reported, no backup taken",
              "A device reports a configuration change over syslog and no scheduled backup covers it",
              "event", 60, _config_reported, uses_assets=True, severity="info"),
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
    EventType("remediation.overdue", "remediation", "Remediation overdue",
              "A finding is not fixed {days} days after its deadline", "state", 900, _remediation_overdue,
              params=[Param("days", "Days after the deadline", 0, "days", 0, 365)], uses_assets=True,
              has_owner=True, roles=["admin", "manager"], repeat_minutes=1440),
    EventType("remediation.acceptance_pending", "remediation", "Risk acceptance requested",
              "A risk acceptance is waiting for approval", "state", 300, _acceptance_pending,
              severity="info", roles=["admin", "manager"]),
    EventType("remediation.acceptance_expiring", "remediation", "Risk acceptance ending",
              "An accepted risk ends within {days} days", "state", 3600, _acceptance_expiring,
              params=[Param("days", "Days before the end", 7, "days", 1, 60)], has_owner=True,
              roles=["admin", "manager"]),
    EventType("system.backup_failed", "system", "NGCorion backup failed",
              "The last backup of NGCorion itself failed", "state", 300, _backup_failed,
              severity="critical", channels=["email", "sms"]),
    EventType("system.backup_missing", "system", "No recent NGCorion backup",
              "No successful backup for {hours} hours", "state", 1800, _backup_missing,
              params=[Param("hours", "No backup for", 48, "hours", 24, 720)], severity="critical"),
    EventType("system.backup_destination", "system", "Backup destination unreachable",
              "A copy could not be sent to an SFTP server or Windows share", "state", 600, _backup_destination),
    EventType("system.restore_test_failed", "system", "Backup restore test failed",
              "The weekly test restore of a backup failed", "state", 600, _restore_test_failed,
              severity="critical"),
    EventType("reports.schedule_failed", "reports", "Scheduled report failed",
              "A scheduled report could not be built or emailed", "state", 300, _report_schedule_failed,
              has_owner=True, roles=["admin"]),
    EventType("system.directory_unreachable", "system", "Directory not reachable",
              "Sign-in with Active Directory / LDAP cannot reach any directory server", "state", 300,
              _directory_unreachable, severity="critical", channels=["email", "sms"], repeat_minutes=240),
    EventType("system.credential_rotation", "system", "Credential profile due for a password change",
              "A credential profile's password is older than its change period", "state", 3600,
              _credential_rotation, severity="info", channels=["email"], repeat_minutes=10080),
    EventType("system.emergency_login", "system", "Local administrator signed in",
              "A local administrator account signs in while sign-in goes through the directory", "event", 60,
              _emergency_login, has_owner=True, severity="warning", channels=["email"]),
    EventType("software.unexpected", "software", "New software outside known repositories",
              "Software installed by hand or from a repository new to the asset", "event", 300,
              _software_unexpected, uses_assets=True, has_owner=True, severity="warning", channels=[],
              enabled=False),
)}

MODULE_LABELS = {"noc": "NOC", "cve": "CVE", "audit": "Audit & Hardening", "backup": "Backup & Restore",
                 "remediation": "Remediation", "reports": "Reports",
                 "software": "Software", "system": "System"}
MODULE_ORDER = ("noc", "cve", "audit", "backup", "remediation", "reports", "software", "system")
