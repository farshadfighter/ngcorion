"""
Configuration changes a device reports over syslog, and the backup they start.

detect(text) recognises the message a device sends when its configuration is changed, with who
changed it and from where when the message says so:

  Cisco IOS / IOS-XE   %SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.0.0.9)
  Cisco NX-OS          %VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by admin on 10.0.0.9@pts/0
  FortiGate            logdesc="Object attribute configured" user="admin" ui="GUI(10.0.0.9)"
                       (log ids 0100044544-0100044547 and 0100032102 "Configuration changed")

The intake (app/modules/syslog/intake.py) records one ConfigChangeEvent per message, and process(),
called by the listener loop every few seconds, acts on them per asset:

1. It waits until the device has been quiet for DEBOUNCE_SECONDS (an engineer's session sends many
   messages; one backup after the last is enough), and at least MIN_GAP_SECONDS after the previous
   backup it started for the asset.
2. It looks for an enabled scheduled configuration backup (job_type "backup") whose asset group
   contains the asset and starts a one-asset group run with that schedule's device family and
   credential profile (app/modules/asset_groups/runs.start_run, trigger "syslog"). The backup is
   compared with the previous one as usual (app/modules/backup/changes.py), so the change, its diff
   and its alert follow, now with who made it and from where.
3. Without such a schedule the events are marked "no_schedule" and the alert
   "backup.config_reported" says the device reported a change that was not backed up.

Turned off with the syslog setting backup_on_change; events then end "off".
"""
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.syslog import ConfigChangeEvent

logger = logging.getLogger(__name__)

DEBOUNCE_SECONDS = 60
MIN_GAP_SECONDS = 300
MAX_RUNS_PER_PASS = 20
MAX_EVENTS_PER_DRAIN = 500          # a device flooding change messages cannot flood the table

_CISCO = re.compile(r"%(?:SYS-5-CONFIG_I|VSHD-5-VSHD_SYSLOG_CONFIG_I):\s*(.*)")
_CISCO_WHO = re.compile(r"Configured from (\S+)(?: by (\S+?))?(?: on (\S+?))?(?: \(([0-9A-Fa-f.:]+)\))?\s*$")
_FORTI_IDS = ("0100044544", "0100044545", "0100044546", "0100044547", "0100032102")
_FORTI_DESC = re.compile(r"(?i)attribute (?:configured|added|deleted)|configuration changed")
_KV = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|(\S+))')
_PAREN_IP = re.compile(r"\(([0-9A-Fa-f.:]+)\)")
_IP_AT = re.compile(r"^([0-9A-Fa-f.:]+)@")


class Change:
    __slots__ = ("by", "source", "message")

    def __init__(self, by: Optional[str], source: Optional[str], message: str):
        self.by, self.source, self.message = by, source, message


def _clip(value: Optional[str], n: int = 128) -> Optional[str]:
    value = (value or "").strip()
    return value[:n] or None


def detect(text: str) -> Optional[Change]:
    """The configuration change `text` (one syslog message) reports, or None."""
    if not text:
        return None
    if "CONFIG_I" in text:
        m = _CISCO.search(text)
        if m:
            body = m.group(1).strip()
            w = _CISCO_WHO.search(body)
            if not w:
                return Change(None, None, body[:1000])
            how, by, line, ip = w.groups()
            if how.lower() == "memory":          # the start-up configuration loaded at boot
                return None
            at = _IP_AT.match(line or "")
            source = ip or (at.group(1) if at else None) or line or how
            return Change(_clip(by), _clip(source), body[:1000])
    if "logid=" in text and ("logdesc=" in text or "ui=" in text):
        kv = {k: (a if a is not None else b) for k, a, b in _KV.findall(text)}
        if kv.get("logid") in _FORTI_IDS or _FORTI_DESC.search(kv.get("logdesc", "")):
            ui = kv.get("ui") or ""
            ip = _PAREN_IP.search(ui)
            message = kv.get("msg") or kv.get("logdesc") or "Configuration changed"
            if kv.get("cfgpath"):
                message = f"{message} ({kv['cfgpath']})"
            return Change(_clip(kv.get("user")), _clip(ip.group(1) if ip else ui), message[:1000])
    return None


# ── acting on the events ─────────────────────────────────────────────────────

def _backup_job_for(db: Session, asset_id: int, members: Dict[int, set]):
    """The first enabled scheduled group backup that covers the asset (lowest id), or None."""
    from app.models.asset_groups import AssetGroup
    from app.models.scheduling import ScheduledJob
    from app.modules.asset_groups import groups
    jobs = (db.query(ScheduledJob)
            .filter(ScheduledJob.job_type == "backup", ScheduledJob.enabled.is_(True),
                    ScheduledJob.group_id.isnot(None), ScheduledJob.credential_profile_id.isnot(None))
            .order_by(ScheduledJob.id).all())
    for job in jobs:
        if job.group_id not in members:
            group = db.get(AssetGroup, job.group_id)
            members[job.group_id] = set(groups.member_ids(db, group)) if group else set()
        if asset_id in members[job.group_id]:
            return job
    return None


def _finalize(db: Session) -> int:
    """Copy the outcome of finished on-change backups onto their events."""
    from app.models.asset_groups import GroupRunItem
    done = 0
    rows = (db.query(ConfigChangeEvent, GroupRunItem)
            .outerjoin(GroupRunItem, (GroupRunItem.run_id == ConfigChangeEvent.group_run_id)
                       & (GroupRunItem.asset_id == ConfigChangeEvent.asset_id))
            .filter(ConfigChangeEvent.status == "queued").all())
    now = datetime.utcnow()
    for event, item in rows:
        if item is None:                         # the run was removed
            event.status, event.processed_at = "failed", now
        elif item.status == "done":
            event.backup_id = item.backup_id
            event.status = "unchanged" if item.outcome == "unchanged" else "done"
            event.processed_at = now
        elif item.status in ("failed", "skipped", "cancelled"):
            event.status, event.processed_at = "failed", now
        else:
            continue
        done += 1
    return done


def process(db: Session, backup_on_change: bool = True, now: Optional[datetime] = None) -> Dict[str, int]:
    """One pass over the change events: finish those whose backup ended, start backups for assets
    whose device has been quiet long enough. Returns counts for the log."""
    from app.models import Asset
    from app.models.asset_groups import AssetGroup, CredentialProfile, GroupRun, GroupRunItem
    from app.models.security_audit_log import log_action
    from app.modules.asset_groups.runs import ACTIVE, RunError, start_run
    now = now or datetime.utcnow()
    out = {"finished": _finalize(db), "started": 0, "no_schedule": 0, "off": 0}
    db.commit()
    pending = ConfigChangeEvent.status == "pending"
    if not backup_on_change:
        out["off"] = (db.query(ConfigChangeEvent).filter(pending)
                      .update({"status": "off", "processed_at": now}, synchronize_session=False))
        db.commit()
        return out
    quiet_before = now - timedelta(seconds=DEBOUNCE_SECONDS)
    ready = [aid for aid, last in db.query(ConfigChangeEvent.asset_id, func.max(ConfigChangeEvent.received_at))
             .filter(pending).group_by(ConfigChangeEvent.asset_id)
             .order_by(func.max(ConfigChangeEvent.received_at)) if last <= quiet_before]
    members: Dict[int, set] = {}
    gap_since = now - timedelta(seconds=MIN_GAP_SECONDS)
    for aid in ready:
        if out["started"] >= MAX_RUNS_PER_PASS:
            break
        recent = (db.query(GroupRun.id, GroupRun.status, GroupRun.created_at)
                  .join(GroupRunItem, GroupRunItem.run_id == GroupRun.id)
                  .filter(GroupRun.trigger == "syslog", GroupRunItem.asset_id == aid)
                  .order_by(GroupRun.id.desc()).first())
        if recent is not None and (recent.status in ACTIVE
                                   or recent.created_at.astimezone(timezone.utc).replace(tzinfo=None) > gap_since):
            continue                            # the next pass after the run / gap takes these
        events = db.query(ConfigChangeEvent).filter(pending, ConfigChangeEvent.asset_id == aid) \
            .order_by(ConfigChangeEvent.id).all()
        asset = db.get(Asset, aid)
        job = _backup_job_for(db, aid, members) if asset is not None and (asset.ip_address or "").strip() else None
        if job is None:
            for e in events:
                e.status, e.processed_at = "no_schedule", now
            out["no_schedule"] += len(events)
            db.commit()
            continue
        group = db.get(AssetGroup, job.group_id)
        profile = db.get(CredentialProfile, job.credential_profile_id)
        try:
            run = start_run(db, group, job.technology, profile, None, 1, None, scheduled_job_id=job.id,
                            started_by_id=job.created_by, kind="backup", asset_ids=[aid], trigger="syslog")
            db.flush()
        except RunError as exc:
            db.rollback()
            logger.warning("[Syslog] on-change backup of asset %s not started: %s", aid, exc)
            events = db.query(ConfigChangeEvent).filter(pending, ConfigChangeEvent.asset_id == aid).all()
            for e in events:
                e.status, e.processed_at = "failed", now
            db.commit()
            continue
        last = events[-1]
        who = ", ".join(dict.fromkeys(e.changed_by for e in events if e.changed_by)) or "unknown user"
        where = ", ".join(dict.fromkeys(e.changed_from for e in events if e.changed_from)) or "unknown address"
        for e in events:
            e.status, e.group_run_id = "queued", run.id
        log_action(db, user_id=job.created_by, action="group_run.start", module="backup", target_id=run.id,
                   detail=f"Configuration change on '{asset.asset_name}' reported over syslog by {who} from "
                          f"{where}; schedule '{job.job_name}' started a backup")
        db.commit()
        out["started"] += 1
        logger.info("[Syslog] backup of asset %s started after a reported configuration change (%s)", aid,
                    last.message[:120])
    return out


def reports_for(db: Session, backup_ids: List[int]) -> Dict[int, Dict]:
    """Who and from where reported the change each backup captured (only backups an on-change run
    stored as changed)."""
    out: Dict[int, Dict] = {}
    if not backup_ids:
        return out
    rows = (db.query(ConfigChangeEvent)
            .filter(ConfigChangeEvent.backup_id.in_(backup_ids), ConfigChangeEvent.status == "done")
            .order_by(ConfigChangeEvent.received_at).all())
    for e in rows:
        r = out.setdefault(e.backup_id, {"by": [], "from": [], "at": None})
        if e.changed_by and e.changed_by not in r["by"]:
            r["by"].append(e.changed_by)
        if e.changed_from and e.changed_from not in r["from"]:
            r["from"].append(e.changed_from)
        r["at"] = e.received_at
    return {k: {"reported_by": ", ".join(v["by"]) or None, "reported_from": ", ".join(v["from"]) or None,
                "reported_at": v["at"]} for k, v in out.items()}
