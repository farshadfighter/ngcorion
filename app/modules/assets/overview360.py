"""
Everything NGCorion knows about one asset, on one page (GET /api/assets/{asset_id}/360).

The page itself needs the asset list read permission; every other section is filled only when the
user may read the module it comes from (otherwise it is None and the page leaves it out), and audit
sessions and hardening actions follow the same ownership rule as their own pages (a non-admin sees
their own). Each section is a short summary that links to the module's page for the rest.

Sections: identity (type, owner, location, tags, groups, hosting, license coverage), risk, audits
(latest per technology), hardening, vulnerabilities, remediation, configuration backups,
monitoring (SNMP and syslog), open alerts, topology neighbours, software, and a timeline of what
happened to the asset across all of them.
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.models import Asset, User, UserPermission

TIMELINE_MAX = 40


def _readable(db: Session, user: User) -> set:
    if user.role.value == "admin":
        return {"*"}
    return {(p.module.value if hasattr(p.module, "value") else str(p.module)).lower()
            for p in db.query(UserPermission).filter(UserPermission.user_id == user.id,
                                                     UserPermission.can_read.is_(True))}


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _num(v):
    return float(v) if v is not None else None


def _identity(db: Session, a: Asset) -> Dict:
    from app.core.asset_entitlement import is_asset_licensed
    from app.models.asset_groups import AssetGroup, AssetGroupMember
    from app.modules.asset_groups.groups import rule_member_ids, tags_of
    groups = []
    static = {g for (g,) in db.query(AssetGroupMember.group_id).filter(AssetGroupMember.asset_id == a.id)}
    for g in db.query(AssetGroup).order_by(AssetGroup.name):
        if g.kind == "static":
            inside = g.id in static
        else:
            try:
                inside = a.id in set(rule_member_ids(db, g.rules or []))
            except Exception:  # noqa: BLE001 - a group whose rules no longer apply is just not shown
                inside = False
        if inside:
            groups.append({"id": g.id, "name": g.name, "kind": g.kind})
    hosted = [{"id": h.id, "name": h.asset_name} for h in
              db.query(Asset).filter(Asset.hosted_on_asset_id == a.id).order_by(Asset.asset_name).limit(50)]
    return {
        "id": a.id, "name": a.asset_name, "hostname": a.hostname, "icon": a.resolved_icon,
        "type": a.asset_type.type_name if a.asset_type else None,
        "category": a.asset_type.category if a.asset_type else None,
        "role": a.asset_role, "status": a.status.value if a.status else None,
        "ip_address": a.ip_address, "mac_address": a.mac_address,
        "manufacturer": a.manufacturer, "model": a.model, "serial_number": a.serial_number,
        "os_name": a.os_name, "os_version": a.os_version,
        "owner": a.owner.full_name if a.owner else None,
        "location": a.location.site_name if a.location else None,
        "confidentiality": a.confidentiality_level.value if a.confidentiality_level else None,
        "description": a.description,
        "hosted_on": {"id": a.hosted_on.id, "name": a.hosted_on.asset_name} if a.hosted_on else None,
        "hosts": hosted,
        "tags": tags_of(db, [a.id]).get(a.id, []),
        "groups": groups,
        "licensed": is_asset_licensed(db, a.id),
        "created_at": _iso(a.created_at), "updated_at": _iso(a.updated_at),
    }


def _risk(db: Session, a: Asset) -> Optional[Dict]:
    from app.models.risk import AssetRiskScore
    s = db.query(AssetRiskScore).filter(AssetRiskScore.asset_id == a.id).first()
    if s is None:
        return {"score": None}
    return {"score": _num(s.final_risk_score), "level": s.risk_level, "calculated_at": _iso(s.calculated_at),
            "zone": s.zone_name, "criticality": s.criticality_level,
            "audit_findings": s.active_audit_findings_count, "risky_ports": s.risky_ports_count,
            "open_ports": s.open_ports_count, "cve_findings": s.cve_findings_count, "cve_kev": s.cve_kev_count,
            "incomplete": bool(s.incomplete_data)}


def _audits(db: Session, a: Asset, owner: Optional[int]) -> Dict:
    from app.core.dependencies import owned_sessions
    from app.models.audit import AuditSession
    q = owned_sessions(db.query(AuditSession).filter(AuditSession.asset_id == a.id), owner)
    total = q.count()
    latest: Dict[str, AuditSession] = {}
    for s in q.order_by(AuditSession.started_at.desc()).limit(200):
        key = s.device_type.value if hasattr(s.device_type, "value") else str(s.device_type)
        if key not in latest and s.status == "completed":
            latest[key] = s
    last = q.order_by(AuditSession.started_at.desc()).first()
    return {
        "total": total,
        "last_at": _iso(last.completed_at or last.started_at) if last else None,
        "latest": [{"id": s.id, "technology": t, "variant": s.sub_device_type, "completed_at": _iso(s.completed_at),
                    "compliance": _num(s.weighted_compliance_pct if s.weighted_compliance_pct is not None
                                       else s.compliance_pct),
                    "passed": s.passed_checks, "failed": s.failed_checks, "total": s.total_checks}
                   for t, s in sorted(latest.items(), key=lambda kv: kv[1].completed_at or datetime.min, reverse=True)],
    }


def _hardening(db: Session, a: Asset, owner: Optional[int]) -> Dict:
    from app.models.hardening import HardeningAction
    q = db.query(HardeningAction).filter(HardeningAction.asset_id == a.id, HardeningAction.action_type != "preview")
    if owner is not None:
        q = q.filter(HardeningAction.user_id == owner)
    rows = q.order_by(HardeningAction.created_at.desc()).limit(5).all()
    return {"total": q.count(), "succeeded": q.filter(HardeningAction.status == "success").count(),
            "recent": [{"id": h.id, "check": h.check_number, "title": h.check_title, "status": h.status,
                        "verified": h.verification_passed, "at": _iso(h.completed_at or h.created_at)} for h in rows]}


def _cves(db: Session, a: Asset) -> Dict:
    from app.modules.cve import findings
    data = findings.compute(db, a.id)
    rows = data["findings"]
    return {"total": len(rows), "fix_now": sum(1 for f in rows if f["priority"] == 1),
            "kev": sum(1 for f in rows if f["kev"]),
            "by_severity": {s: sum(1 for f in rows if f["severity"] == s) for s in ("critical", "high", "medium", "low")},
            "top": [{"cve_id": f["cve_id"], "severity": f["severity"], "cvss": f["cvss"], "kev": f["kev"],
                     "priority": f["priority"], "product": f["product"], "installed": f["installed"],
                     "fixed_in": f["fixed_in"]} for f in rows[:6]]}


def _remediation(db: Session, a: Asset, now: datetime) -> Dict:
    from app.models.remediation import ITEM_ACTIVE, RemediationItem
    q = db.query(RemediationItem).filter(RemediationItem.asset_id == a.id, RemediationItem.status.in_(ITEM_ACTIVE))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    items = sorted(q.all(), key=lambda i: (order.get(i.severity, 4), i.due_at or datetime.max))
    return {"open": len(items), "overdue": sum(1 for i in items if i.due_at and i.due_at < now),
            "accepted": db.query(RemediationItem).filter(RemediationItem.asset_id == a.id,
                                                         RemediationItem.status == "accepted").count(),
            "top": [{"id": i.id, "title": i.title, "severity": i.severity, "source": i.source, "ref": i.ref,
                     "status": i.status, "due_at": _iso(i.due_at), "kev": i.kev} for i in items[:6]]}


def _backups(db: Session, a: Asset, now: datetime) -> Dict:
    from app.models.backup import DeviceBackup
    q = db.query(DeviceBackup).filter(DeviceBackup.asset_id == a.id)
    recent = q.order_by(DeviceBackup.created_at.desc(), DeviceBackup.id.desc()).limit(4).all()
    last_change = q.filter(DeviceBackup.changed.is_(True)).order_by(DeviceBackup.created_at.desc()).first()
    last_seen = max([b.confirmed_at or b.created_at for b in recent[:1]] or [None]) if recent else None
    return {"total": q.count(), "last_at": _iso(last_seen),
            "last_change_at": _iso(last_change.created_at) if last_change else None,
            "last_change_origin": last_change.change_origin if last_change else None,
            "external_changes_30d": q.filter(DeviceBackup.change_origin == "external",
                                             DeviceBackup.created_at >= now - timedelta(days=30)).count(),
            "recent": [{"id": b.id, "created_at": _iso(b.created_at), "source": b.source,
                        "change_origin": b.change_origin, "added": b.added_lines, "removed": b.removed_lines}
                       for b in recent]}


def _monitoring(db: Session, a: Asset, now: datetime) -> Dict:
    from app.models.noc import AssetSnmpCredential, AssetSnmpInterface, AssetSnmpStatus
    from app.models.syslog import SyslogMessage, SyslogSource
    st = db.query(AssetSnmpStatus).filter(AssetSnmpStatus.asset_id == a.id).first()
    ifaces = db.query(AssetSnmpInterface).filter(AssetSnmpInterface.asset_id == a.id).all()
    day = now - timedelta(hours=24)
    sq = db.query(SyslogMessage).filter(SyslogMessage.asset_id == a.id)
    source = db.query(func.max(SyslogSource.last_seen)).filter(SyslogSource.asset_id == a.id).scalar()
    return {
        "snmp": {
            "configured": db.query(AssetSnmpCredential.id).filter(AssetSnmpCredential.asset_id == a.id).first()
            is not None,
            "reachable": st.reachable if st else None, "last_polled_at": _iso(st.last_polled_at) if st else None,
            "uptime_seconds": (st.sys_uptime_ticks // 100) if st and st.sys_uptime_ticks else None,
            "error": st.error_message if st and not st.reachable else None,
            "interfaces": len(ifaces),
            "interfaces_down": sum(1 for i in ifaces if i.if_admin_status == "up" and i.if_oper_status == "down"),
        },
        "syslog": {
            "last_at": _iso(source), "last_24h": sq.filter(SyslogMessage.received_at >= day).count(),
            "severe_24h": sq.filter(SyslogMessage.received_at >= day, SyslogMessage.severity <= 3).count(),
            "recent": [{"id": m.id, "received_at": _iso(m.received_at), "severity": m.severity, "app": m.app_name,
                        "message": m.message[:300]}
                       for m in sq.order_by(SyslogMessage.id.desc()).limit(5)],
        },
    }


def _alerts(db: Session, a: Asset, modules: List[str]) -> List[Dict]:
    from app.models.notification import ALERT_OPEN_STATUSES, Alert
    rows = (db.query(Alert).filter(Alert.asset_id == a.id, Alert.status.in_(ALERT_OPEN_STATUSES),
                                   Alert.module.in_(modules))
            .order_by(Alert.first_seen_at.desc()).limit(20).all())
    return [{"id": x.id, "title": x.title, "detail": x.detail, "severity": x.severity, "module": x.module,
             "status": x.status, "since": _iso(x.first_seen_at), "link": x.link} for x in rows]


def _neighbours(db: Session, a: Asset) -> List[Dict]:
    from app.models.topology import TopologyLink
    out = []
    links = db.query(TopologyLink).filter(or_(TopologyLink.source_asset_id == a.id,
                                              TopologyLink.destination_asset_id == a.id)).limit(100).all()
    other_ids = {lk.destination_asset_id if lk.source_asset_id == a.id else lk.source_asset_id for lk in links}
    names = {x.id: x for x in db.query(Asset).filter(Asset.id.in_(other_ids))} if other_ids else {}
    for lk in links:
        mine = lk.source_asset_id == a.id
        other = names.get(lk.destination_asset_id if mine else lk.source_asset_id)
        if other is None:
            continue
        out.append({"asset_id": other.id, "name": other.asset_name, "icon": other.resolved_icon,
                    "ip_address": other.ip_address,
                    "local_interface": lk.source_interface if mine else lk.destination_interface,
                    "remote_interface": lk.destination_interface if mine else lk.source_interface,
                    "link_type": lk.link_type, "status": lk.status, "vlan": lk.vlan})
    return out


def _software(db: Session, a: Asset) -> Dict:
    from app.models.software import SoftwareCollection, SoftwareItem
    kinds = dict(db.query(SoftwareItem.kind, func.count(SoftwareItem.id)).filter(SoftwareItem.asset_id == a.id)
                 .group_by(SoftwareItem.kind).all())
    last = (db.query(SoftwareCollection).filter(SoftwareCollection.asset_id == a.id)
            .order_by(SoftwareCollection.collected_at.desc()).first())
    return {"packages": int(kinds.get("package", 0) + kinds.get("program", 0)),
            "services": int(kinds.get("service", 0)), "hotfixes": int(kinds.get("hotfix", 0)),
            "last_collected_at": _iso(last.collected_at) if last else None,
            "last_status": last.status if last else None}


def _timeline(db: Session, a: Asset, can, owner: Optional[int]) -> List[Dict]:
    ev: List[Dict] = []
    if can("asset_list"):
        from app.models.asset_log import AssetLog
        for lg in (db.query(AssetLog).filter(AssetLog.asset_id == a.id)
                   .order_by(AssetLog.timestamp.desc()).limit(TIMELINE_MAX)):
            ev.append({"at": _iso(lg.timestamp), "kind": "asset", "action": lg.action,
                       "text": None, "status": lg.status, "link": None})
    if can("auditing"):
        from app.core.dependencies import owned_sessions
        from app.models.audit import AuditSession
        for s in (owned_sessions(db.query(AuditSession).filter(AuditSession.asset_id == a.id), owner)
                  .order_by(AuditSession.started_at.desc()).limit(TIMELINE_MAX)):
            dt = s.device_type.value if hasattr(s.device_type, "value") else str(s.device_type)
            ev.append({"at": _iso(s.completed_at or s.started_at), "kind": "audit", "action": s.status,
                       "text": dt, "value": _num(s.weighted_compliance_pct if s.weighted_compliance_pct is not None
                                                 else s.compliance_pct),
                       "status": s.status, "link": f"/audit/sessions/{s.id}"})
    if can("hardening"):
        from app.models.hardening import HardeningAction
        q = db.query(HardeningAction).filter(HardeningAction.asset_id == a.id, HardeningAction.action_type != "preview")
        if owner is not None:
            q = q.filter(HardeningAction.user_id == owner)
        for h in q.order_by(HardeningAction.created_at.desc()).limit(TIMELINE_MAX):
            ev.append({"at": _iso(h.completed_at or h.created_at), "kind": "hardening", "action": h.status,
                       "text": f"{h.check_number} {h.check_title}"[:200], "status": h.status, "link": None})
    if can("backup"):
        from app.models.backup import DeviceBackup
        from app.models.backup_restore import BackupRestore
        for b in (db.query(DeviceBackup).filter(DeviceBackup.asset_id == a.id)
                  .order_by(DeviceBackup.created_at.desc()).limit(TIMELINE_MAX)):
            ev.append({"at": _iso(b.created_at), "kind": "backup", "action": b.change_origin or b.source,
                       "text": b.source, "added": b.added_lines, "removed": b.removed_lines, "status": None,
                       "link": f"/backup?asset={a.id}" + (f"&compare={b.id}" if b.changed else "")})
        for r in (db.query(BackupRestore).filter(BackupRestore.asset_id == a.id)
                  .order_by(BackupRestore.created_at.desc()).limit(TIMELINE_MAX)):
            ev.append({"at": _iso(r.finished_at or r.created_at), "kind": "restore", "action": r.status,
                       "text": (r.reason or "")[:200], "status": r.status, "link": "/backup/restores"})
    from app.modules.alerts.router import MODULE_PERMISSION
    alert_modules = [m for m, perm in MODULE_PERMISSION.items() if can(perm)]
    if alert_modules:
        from app.models.notification import Alert
        for x in (db.query(Alert).filter(Alert.asset_id == a.id, Alert.module.in_(alert_modules))
                  .order_by(Alert.first_seen_at.desc()).limit(TIMELINE_MAX)):
            ev.append({"at": _iso(x.first_seen_at), "kind": "alert", "action": x.severity, "text": x.title,
                       "status": x.status, "link": x.link})
    ev = [e for e in ev if e["at"]]
    ev.sort(key=lambda e: e["at"], reverse=True)
    return ev[:TIMELINE_MAX]


def build(db: Session, asset: Asset, user: User, now: Optional[datetime] = None) -> Dict:
    now = now or datetime.utcnow()
    readable = _readable(db, user)

    def can(module: str) -> bool:
        return "*" in readable or module.lower() in readable

    owner = None if user.role.value == "admin" else user.id
    from app.modules.alerts.router import MODULE_PERMISSION
    alert_modules = [m for m, perm in MODULE_PERMISSION.items() if can(perm)]
    return {
        "asset": _identity(db, asset),
        "risk": _risk(db, asset) if can("risk") else None,
        "audits": _audits(db, asset, owner) if can("auditing") else None,
        "hardening": _hardening(db, asset, owner) if can("hardening") else None,
        "cve": _cves(db, asset) if can("cve") else None,
        "remediation": _remediation(db, asset, now) if can("remediation") else None,
        "backups": _backups(db, asset, now) if can("backup") else None,
        "monitoring": _monitoring(db, asset, now) if can("noc") else None,
        "alerts": _alerts(db, asset, alert_modules) if alert_modules else None,
        "topology": _neighbours(db, asset) if can("topology") else None,
        "software": _software(db, asset),
        "timeline": _timeline(db, asset, can, owner),
    }
