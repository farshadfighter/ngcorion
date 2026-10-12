"""
Asset groups: who is in a group, tags, and checking rules.

A dynamic group's rules all have to hold (AND); they are evaluated every time the group is used,
so membership is never stale. Fields:

  type      eq / neq    asset type id
  zone      eq / neq    Risk Intelligence zone id (the zone alert rules filter by)
  owner     eq / neq    owner id
  location  eq / neq    location id
  status    eq / neq    active | standby | decommissioned | unknown | inactive
  os        contains / eq        operating system name and version
  vendor    contains / eq        manufacturer
  name      contains             asset name or host name
  tag       has / not_has        a tag
  ip        in / not_in          an IP range in CIDR notation (10.0.0.0/8, 172.16.10.0/24)
"""
import ipaddress
from typing import Dict, Iterable, List, Optional, Set

from sqlalchemy import and_, exists, func, not_, or_
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_groups import AssetGroup, AssetGroupMember, AssetTag
from app.models.enums import StatusEnum
from app.models.risk import AssetRiskProfile

FIELDS = {
    "type": ("eq", "neq"), "zone": ("eq", "neq"), "owner": ("eq", "neq"), "location": ("eq", "neq"),
    "status": ("eq", "neq"), "os": ("contains", "eq"), "vendor": ("contains", "eq"), "name": ("contains",),
    "tag": ("has", "not_has"), "ip": ("in", "not_in"),
}
ID_FIELDS = {"type": Asset.asset_type_id, "owner": Asset.owner_id, "location": Asset.location_id}
MAX_RULES = 20


class RuleError(ValueError):
    pass


def normalize_tag(tag: str) -> str:
    t = " ".join((tag or "").split()).lower()
    if not t or len(t) > 64:
        raise RuleError("A tag is 1 to 64 characters")
    return t


def check_rules(rules: List[Dict]) -> List[Dict]:
    """Rules in their stored form; RuleError for anything that cannot be evaluated."""
    if len(rules) > MAX_RULES:
        raise RuleError(f"At most {MAX_RULES} conditions")
    out = []
    for r in rules:
        field, op, value = r.get("field"), r.get("op"), r.get("value")
        if field not in FIELDS or op not in FIELDS[field]:
            raise RuleError(f"Unknown condition: {field} {op}")
        if field in ID_FIELDS or field == "zone":
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise RuleError(f"Choose a value for {field}")
        elif field == "status":
            if value not in {s.value for s in StatusEnum}:
                raise RuleError(f"Unknown status: {value}")
        elif field == "tag":
            value = normalize_tag(str(value or ""))
        elif field == "ip":
            try:
                value = str(ipaddress.ip_network(str(value).strip(), strict=False))
            except ValueError:
                raise RuleError(f"Not an IP range: {value}")
        else:
            value = str(value or "").strip()
            if not value or len(value) > 200:
                raise RuleError(f"Enter a value for {field}")
        out.append({"field": field, "op": op, "value": value})
    return out


def _condition(rule: Dict):
    field, op, value = rule["field"], rule["op"], rule["value"]
    if field in ID_FIELDS:
        col = ID_FIELDS[field]
        return col == value if op == "eq" else or_(col.is_(None), col != value)
    if field == "zone":
        has = exists().where(and_(AssetRiskProfile.asset_id == Asset.id, AssetRiskProfile.zone_id == value))
        return has if op == "eq" else not_(has)
    if field == "status":
        cond = Asset.status == StatusEnum(value)
        return cond if op == "eq" else not_(cond)
    if field == "tag":
        has = exists().where(and_(AssetTag.asset_id == Asset.id, AssetTag.tag == value))
        return has if op == "has" else not_(has)
    if field == "name":
        like = f"%{value.lower()}%"
        return or_(func.lower(Asset.asset_name).like(like), func.lower(func.coalesce(Asset.hostname, "")).like(like))
    text = {"os": func.lower(func.concat(func.coalesce(Asset.os_name, ""), " ", func.coalesce(Asset.os_version, ""))),
            "vendor": func.lower(func.coalesce(Asset.manufacturer, ""))}[field]
    if op == "eq":
        return func.trim(text) == value.lower()
    return text.like(f"%{value.lower()}%")


def _in_ranges(ip: Optional[str], rules: List[Dict]) -> bool:
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        addr = None
    for r in rules:
        inside = addr is not None and addr in ipaddress.ip_network(r["value"], strict=False)
        if inside != (r["op"] == "in"):
            return False
    return True


def member_ids(db: Session, group: AssetGroup) -> List[int]:
    """The group's assets, by id (ascending)."""
    if group.kind == "static":
        return [r[0] for r in db.query(AssetGroupMember.asset_id).filter(AssetGroupMember.group_id == group.id)
                .order_by(AssetGroupMember.asset_id)]
    return rule_member_ids(db, group.rules or [])


def rule_member_ids(db: Session, rules: List[Dict]) -> List[int]:
    sql_rules = [r for r in rules if r["field"] != "ip"]
    ip_rules = [r for r in rules if r["field"] == "ip"]
    q = db.query(Asset.id, Asset.ip_address)
    for r in sql_rules:
        q = q.filter(_condition(r))
    return [aid for aid, ip in q.order_by(Asset.id) if not ip_rules or _in_ranges(ip, ip_rules)]


def tags_of(db: Session, asset_ids: Iterable[int]) -> Dict[int, List[str]]:
    ids = list(asset_ids)
    out: Dict[int, List[str]] = {i: [] for i in ids}
    if ids:
        for aid, tag in db.query(AssetTag.asset_id, AssetTag.tag).filter(AssetTag.asset_id.in_(ids)).order_by(AssetTag.tag):
            out[aid].append(tag)
    return out


def all_tags(db: Session) -> List[Dict]:
    return [{"tag": t, "count": c} for t, c in
            db.query(AssetTag.tag, func.count()).group_by(AssetTag.tag).order_by(AssetTag.tag)]


def add_tags(db: Session, asset_ids: Iterable[int], tags: Iterable[str]) -> int:
    """Tag the assets; returns how many assets got a tag they did not have."""
    ids, wanted = list(asset_ids), [normalize_tag(t) for t in tags]
    have: Set = {(a, t) for a, t in db.query(AssetTag.asset_id, AssetTag.tag)
                 .filter(AssetTag.asset_id.in_(ids), AssetTag.tag.in_(wanted))}
    changed = set()
    for aid in ids:
        for tag in wanted:
            if (aid, tag) not in have:
                db.add(AssetTag(asset_id=aid, tag=tag))
                changed.add(aid)
    return len(changed)


def remove_tags(db: Session, asset_ids: Iterable[int], tags: Iterable[str]) -> int:
    """Remove the tags; returns how many assets lost one."""
    wanted = [normalize_tag(t) for t in tags]
    q = db.query(AssetTag).filter(AssetTag.asset_id.in_(list(asset_ids)), AssetTag.tag.in_(wanted))
    changed = {r.asset_id for r in q}
    q.delete(synchronize_session=False)
    return len(changed)
