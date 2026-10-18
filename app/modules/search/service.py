"""
Global search: one query over what NGCorion knows, for the search box in the page header.

Each kind of result is searched only when the user may read its module (the same rule as its page), and
reports only among those the user may see in the archive:

  assets        name, host name, address, MAC (any notation), serial number, model, OS    asset_list
  groups        asset group names                                                       asset_list
  software      installed software names, with the number of assets                     asset_list
  devices       unknown devices on the network: address, MAC, vendor                    noc
  cves          CVE ids (the query starts with "CVE")                                   cve
  certificates  TLS services: address, server name, certificate subject                 cve
  findings      remediation items: title or reference (CVE id, check number)            remediation
  users         user name and email                                                     user_management
  reports       report title and code (RPT-...)                                         reports

The query is normalised first: Persian and Arabic digits become ASCII, Arabic ي/ك become Persian ی/ک.
Each kind returns at most `limit` results, exact matches first; a result names the page that shows it.
"""
import re
from typing import Callable, Dict, List, Optional, Tuple

from urllib.parse import quote

from sqlalchemy import String, cast, func, or_
from sqlalchemy.orm import Session

from app.models import User

MIN_LENGTH = 2
DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")
LETTERS = str.maketrans({"ي": "ی", "ك": "ک"})
HEX = re.compile(r"^[0-9a-f]+$")
# aa:bb:cc, aa-bb-cc, aabb.cc.., or bare hex digits (six or more: "3cef8c")
MAC_LIKE = re.compile(r"^[0-9a-f]{2}([:\-.][0-9a-f]{1,4})+[:\-.]?$|^[0-9a-f]{4}\.[0-9a-f]{1,4}|^[0-9a-f]{6,12}$", re.I)
CVE_LIKE = re.compile(r"^cve-?\d{0,4}(-\d*)?$", re.I)


def normalise(q: str) -> str:
    return " ".join((q or "").translate(DIGITS).translate(LETTERS).split())[:100]


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _mac_digits(q: str) -> Optional[str]:
    """The hex digits of a query that looks like (part of) a MAC address, else None."""
    if not MAC_LIKE.match(q):
        return None
    digits = re.sub(r"[^0-9a-f]", "", q.lower())
    return digits if len(digits) >= 4 and HEX.match(digits) else None


def _mac_column(col):
    return func.regexp_replace(func.lower(col), "[^0-9a-f]", "", "g")


def _rank(text: Optional[str], q: str) -> int:
    t = (text or "").lower()
    return 0 if t == q.lower() else 1 if t.startswith(q.lower()) else 2


# ── the kinds ────────────────────────────────────────────────────────────

def _assets(db: Session, q: str, limit: int, user: User) -> List[Dict]:
    from app.models.asset import Asset
    like = _like(q)
    conds = [Asset.asset_name.ilike(like), Asset.hostname.ilike(like), Asset.ip_address.ilike(like),
             Asset.serial_number.ilike(like), Asset.model.ilike(like), Asset.os_name.ilike(like)]
    mac = _mac_digits(q)
    if mac:
        conds.append(_mac_column(Asset.mac_address).like(f"%{mac}%"))
    rows = db.query(Asset).filter(or_(*conds)).limit(limit * 4).all()
    rows.sort(key=lambda a: (min(_rank(a.asset_name, q), _rank(a.ip_address, q), _rank(a.hostname, q)),
                             (a.asset_name or "").lower()))
    out = []
    for a in rows[:limit]:
        detail = [x for x in (a.ip_address, a.hostname if a.hostname != a.asset_name else None,
                              " ".join(x for x in (a.os_name, a.os_version) if x) or None) if x]
        if mac and a.mac_address:
            detail.append(a.mac_address)
        out.append({"id": a.id, "title": a.asset_name, "detail": " · ".join(detail),
                    "link": f"/assets/inventory/{a.id}"})
    return out


def _groups(db: Session, q: str, limit: int, user: User) -> List[Dict]:
    from app.models.asset_groups import AssetGroup
    rows = db.query(AssetGroup).filter(AssetGroup.name.ilike(_like(q))).limit(limit * 3).all()
    rows.sort(key=lambda g: (_rank(g.name, q), g.name.lower()))
    return [{"id": g.id, "title": g.name, "detail": g.description or "", "link": f"/assets/groups?q={quote(g.name)}"}
            for g in rows[:limit]]


def _software(db: Session, q: str, limit: int, user: User) -> List[Dict]:
    from app.models.software import SoftwareItem
    rows = (db.query(SoftwareItem.name, func.count(func.distinct(SoftwareItem.asset_id)))
            .filter(SoftwareItem.name.ilike(_like(q))).group_by(SoftwareItem.name)
            .order_by(func.count(func.distinct(SoftwareItem.asset_id)).desc()).limit(limit * 3).all())
    rows.sort(key=lambda r: (_rank(r[0], q), -r[1]))
    return [{"title": name, "count": n, "link": f"/assets/software?q={quote(name)}"} for name, n in rows[:limit]]


def _devices(db: Session, q: str, limit: int, user: User) -> List[Dict]:
    from app.models.noc import NetworkEndpoint
    conds = [NetworkEndpoint.ip.ilike(_like(q)), NetworkEndpoint.vendor.ilike(_like(q)),
             cast(NetworkEndpoint.other_ips, String).ilike(_like(q))]
    mac = _mac_digits(q)
    if mac:
        conds.append(_mac_column(NetworkEndpoint.mac).like(f"%{mac}%"))
    rows = (db.query(NetworkEndpoint).filter(NetworkEndpoint.matched_asset_id.is_(None), or_(*conds))
            .order_by(NetworkEndpoint.last_seen_at.desc()).limit(limit).all())
    return [{"id": e.id, "title": e.ip or e.mac, "detail": " · ".join(x for x in (e.mac, e.vendor) if x),
             "state": e.state, "link": f"/noc/unknown-devices?focus={e.id}"} for e in rows]


def _cves(db: Session, q: str, limit: int, user: User) -> List[Dict]:
    if not CVE_LIKE.match(q) or len(q) < 8:        # "CVE-2024" at least
        return []
    from app.models.cve import CveEntry
    ident = q.upper() if q.upper().startswith("CVE-") else "CVE-" + q[3:].lstrip("-").upper()
    rows = (db.query(CveEntry).filter(CveEntry.cve_id.like(ident.replace("_", "\\_") + "%"))
            .order_by(func.length(CveEntry.cve_id), CveEntry.cve_id.desc()).limit(limit).all())
    return [{"id": c.cve_id, "title": c.cve_id, "severity": c.severity, "cvss": c.cvss_score, "kev": bool(c.kev),
             "detail": (c.description or "")[:140], "link": f"/cve?cve={c.cve_id}"} for c in rows]


def _certificates(db: Session, q: str, limit: int, user: User) -> List[Dict]:
    from app.models.asset import Asset
    from app.models.tls import TlsEndpoint
    like = _like(q)
    rows = (db.query(TlsEndpoint, Asset.asset_name).join(Asset, Asset.id == TlsEndpoint.asset_id)
            .filter(or_(TlsEndpoint.host.ilike(like), TlsEndpoint.server_name.ilike(like),
                        TlsEndpoint.subject.ilike(like), cast(TlsEndpoint.names, String).ilike(like)))
            .order_by(TlsEndpoint.not_after).limit(limit).all())
    return [{"id": e.id, "title": f"{e.server_name or e.host}:{e.port}", "detail": asset_name,
             "subject": e.subject, "not_after": e.not_after.isoformat() if e.not_after else None,
             "link": f"/cve/certificates?service={e.id}"} for e, asset_name in rows]


def _findings(db: Session, q: str, limit: int, user: User) -> List[Dict]:
    from app.models.remediation import ITEM_ACTIVE, RemediationItem
    like = _like(q)
    rows = (db.query(RemediationItem)
            .filter(or_(RemediationItem.title.ilike(like), RemediationItem.ref.ilike(like),
                        RemediationItem.asset_name.ilike(like)))
            .order_by(RemediationItem.status.in_(ITEM_ACTIVE).desc(), RemediationItem.updated_at.desc())
            .limit(limit).all())
    return [{"id": i.id, "title": i.title, "source": i.source, "ref": i.ref, "severity": i.severity,
             "status": i.status, "detail": i.asset_name, "link": f"/remediation?item={i.id}"} for i in rows]


def _users(db: Session, q: str, limit: int, user: User) -> List[Dict]:
    like = _like(q)
    rows = db.query(User).filter(or_(User.username.ilike(like), User.email.ilike(like))).limit(limit * 3).all()
    rows.sort(key=lambda u: (_rank(u.username, q), u.username.lower()))
    return [{"id": u.id, "title": u.username, "detail": u.email or "",
             "role": u.role.value if hasattr(u.role, "value") else str(u.role), "active": bool(u.is_active),
             "link": f"/settings/users?q={quote(u.username)}"} for u in rows[:limit]]


def _reports(db: Session, q: str, limit: int, user: User) -> List[Dict]:
    from app.models.report import Report
    from app.modules.reports import service as reports
    like = _like(q)
    rows = (reports.visible_reports(db, user).filter(or_(Report.title.ilike(like), Report.code.ilike(like)))
            .order_by(Report.created_at.desc()).limit(limit).all())
    return [{"id": r.id, "title": r.title, "detail": r.code or "", "status": r.status,
             "created_at": r.created_at.isoformat() if r.created_at else None,
             "link": f"/reports/archive?q={quote(r.code or r.title)}"} for r in rows]


# (key, permission module, search)
KINDS: List[Tuple[str, str, Callable]] = [
    ("assets", "asset_list", _assets),
    ("cves", "cve", _cves),
    ("devices", "noc", _devices),
    ("findings", "remediation", _findings),
    ("certificates", "cve", _certificates),
    ("software", "asset_list", _software),
    ("groups", "asset_list", _groups),
    ("users", "user_management", _users),
    ("reports", "reports", _reports),
]


def search(db: Session, user: User, query: str, limit: int = 5, kinds: Optional[List[str]] = None) -> Dict:
    from app.modules.reports.service import can_read
    q = normalise(query)
    groups = []
    if len(q) >= MIN_LENGTH:
        allowed = {}
        for key, module, fn in KINDS:
            if kinds and key not in kinds:
                continue
            if module not in allowed:
                allowed[module] = can_read(db, user, module)
            if not allowed[module]:
                continue
            items = fn(db, q, limit, user)
            if items:
                groups.append({"kind": key, "items": items})
    return {"query": q, "groups": groups}
