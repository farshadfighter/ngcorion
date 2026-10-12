"""
Asset groups, tags, bulk edit, credential profiles and group audit runs.

  /api/asset-groups                 groups (asset_list read / write)
      GET  ""  POST ""  GET|PUT|DELETE /{id}  POST /preview  POST /{id}/members
      GET  /tags                    every tag with its asset count
      GET  /tags/assets             asset id -> its tags
  /api/assets/bulk                  one change to many assets (asset_list write; delete: asset_list
                                    delete; zone: risk write)
  /api/credential-profiles          list (credential_profiles read); create, edit, delete and test
                                    sign-in: system administrators only
  /api/group-runs                   group audits (auditing read / write; starting one also needs
                                    credential_profiles read)
"""
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_admin, require_permission
from app.models import Asset, User
from app.models.asset_groups import (AssetGroup, AssetGroupMember, AssetTag, CredentialProfile, GroupRun,
                                     GroupRunItem)
from app.models.enums import StatusEnum
from app.models.scheduling import ScheduledJob
from app.models.security_audit_log import log_action

from . import groups as G
from . import profiles as P
from . import runs as R

groups_router = APIRouter(prefix="/api/asset-groups", tags=["Asset groups"])
bulk_router = APIRouter(prefix="/api/assets", tags=["Assets"])
profiles_router = APIRouter(prefix="/api/credential-profiles", tags=["Credential profiles"])
runs_router = APIRouter(prefix="/api/group-runs", tags=["Group audits"])

MAX_BULK = 5000


def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _who(user: User, request: Request, action: str, module: str, target_id: Optional[int] = None) -> Dict:
    return {"user_id": user.id, "username": user.username, "action": action, "module": module,
            "target_id": target_id, "ip_address": _ip(request)}


# ── groups ───────────────────────────────────────────────────────────────────

class Rule(BaseModel):
    field: str
    op: str
    value: Any = None


class GroupBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field(None, max_length=2000)
    kind: Literal["dynamic", "static"] = "dynamic"
    rules: List[Rule] = Field(default_factory=list, max_length=G.MAX_RULES)
    asset_ids: List[int] = Field(default_factory=list, max_length=MAX_BULK)


class PreviewBody(BaseModel):
    rules: List[Rule] = Field(default_factory=list, max_length=G.MAX_RULES)


class MembersBody(BaseModel):
    asset_ids: List[int] = Field(..., min_length=1, max_length=MAX_BULK)
    action: Literal["add", "remove"] = "add"


def _rules(rules: List[Rule]) -> List[Dict]:
    try:
        return G.check_rules([r.model_dump() for r in rules])
    except G.RuleError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _existing_ids(db: Session, ids: List[int]) -> List[int]:
    return [r[0] for r in db.query(Asset.id).filter(Asset.id.in_(set(ids)))] if ids else []


def _group_out(db: Session, g: AssetGroup, count: Optional[int] = None) -> Dict:
    used = db.query(func.count(ScheduledJob.id)).filter(ScheduledJob.group_id == g.id).scalar() or 0
    return {"id": g.id, "name": g.name, "description": g.description, "kind": g.kind, "rules": g.rules or [],
            "asset_count": len(G.member_ids(db, g)) if count is None else count, "schedules": used,
            "created_at": g.created_at, "updated_at": g.updated_at}


def _assets_out(db: Session, ids: List[int], limit: Optional[int] = None) -> List[Dict]:
    from app.models import AssetType
    ids = ids[:limit] if limit else ids
    if not ids:
        return []
    tags = G.tags_of(db, ids)
    rows = (db.query(Asset.id, Asset.asset_name, Asset.ip_address, Asset.status, AssetType.type_name)
            .outerjoin(AssetType, AssetType.id == Asset.asset_type_id).filter(Asset.id.in_(ids))
            .order_by(Asset.asset_name))
    return [{"id": i, "asset_name": n, "ip_address": ip, "status": s.value if s else None, "type_name": t,
             "tags": tags.get(i, [])} for i, n, ip, s, t in rows]


def _name_taken(db: Session, model, name: str, own_id: Optional[int] = None) -> bool:
    q = db.query(model.id).filter(func.lower(model.name) == name.strip().lower())
    if own_id is not None:
        q = q.filter(model.id != own_id)
    return q.first() is not None


def _get_group(db: Session, group_id: int) -> AssetGroup:
    g = db.get(AssetGroup, group_id)
    if g is None:
        raise HTTPException(status_code=404, detail="Group not found")
    return g


@groups_router.get("")
def list_groups(current_user: User = Depends(require_permission("ASSET_LIST", "read")),
                db: Session = Depends(get_db)):
    """Groups with their current asset count (a dynamic group's rules are evaluated now)."""
    return [_group_out(db, g) for g in db.query(AssetGroup).order_by(AssetGroup.name)]


@groups_router.post("/preview")
def preview(body: PreviewBody, current_user: User = Depends(require_permission("ASSET_LIST", "read")),
            db: Session = Depends(get_db)):
    """The assets these rules select right now (the first 50) and how many there are."""
    ids = G.rule_member_ids(db, _rules(body.rules))
    return {"count": len(ids), "assets": _assets_out(db, ids, 50)}


@groups_router.get("/tags")
def list_tags(current_user: User = Depends(require_permission("ASSET_LIST", "read")),
              db: Session = Depends(get_db)):
    return G.all_tags(db)


@groups_router.get("/tags/assets")
def tags_by_asset(current_user: User = Depends(require_permission("ASSET_LIST", "read")),
                  db: Session = Depends(get_db)):
    """Every tagged asset's tags: {asset_id: [tag, ...]}."""
    out: Dict[int, List[str]] = {}
    for aid, tag in db.query(AssetTag.asset_id, AssetTag.tag).order_by(AssetTag.tag):
        out.setdefault(aid, []).append(tag)
    return out


@groups_router.post("")
def create_group(body: GroupBody, request: Request,
                 current_user: User = Depends(require_permission("ASSET_LIST", "write")),
                 db: Session = Depends(get_db)):
    if _name_taken(db, AssetGroup, body.name):
        raise HTTPException(status_code=409, detail="A group with this name exists")
    g = AssetGroup(name=body.name.strip(), description=(body.description or "").strip() or None, kind=body.kind,
                   rules=_rules(body.rules) if body.kind == "dynamic" else [], created_by=current_user.id)
    db.add(g)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="A group with this name exists")
    if body.kind == "static":
        for aid in _existing_ids(db, body.asset_ids):
            db.add(AssetGroupMember(group_id=g.id, asset_id=aid))
    log_action(db, **_who(current_user, request, "asset_group.create", "asset_list", g.id),
               detail=f"Created asset group '{g.name}'")
    db.commit()
    return _group_out(db, g)


@groups_router.get("/{group_id}")
def get_group(group_id: int, current_user: User = Depends(require_permission("ASSET_LIST", "read")),
              db: Session = Depends(get_db)):
    g = _get_group(db, group_id)
    ids = G.member_ids(db, g)
    return {**_group_out(db, g, len(ids)), "assets": _assets_out(db, ids)}


@groups_router.put("/{group_id}")
def update_group(group_id: int, body: GroupBody, request: Request,
                 current_user: User = Depends(require_permission("ASSET_LIST", "write")),
                 db: Session = Depends(get_db)):
    g = _get_group(db, group_id)
    if _name_taken(db, AssetGroup, body.name, g.id):
        raise HTTPException(status_code=409, detail="A group with this name exists")
    g.name, g.description = body.name.strip(), (body.description or "").strip() or None
    if body.kind != g.kind:
        g.kind = body.kind
        db.query(AssetGroupMember).filter(AssetGroupMember.group_id == g.id).delete()
        if body.kind == "static":
            for aid in _existing_ids(db, body.asset_ids):
                db.add(AssetGroupMember(group_id=g.id, asset_id=aid))
    g.rules = _rules(body.rules) if g.kind == "dynamic" else []
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="A group with this name exists")
    log_action(db, **_who(current_user, request, "asset_group.update", "asset_list", g.id),
               detail=f"Changed asset group '{g.name}'")
    db.commit()
    return _group_out(db, g)


@groups_router.post("/{group_id}/members")
def change_members(group_id: int, body: MembersBody, request: Request,
                   current_user: User = Depends(require_permission("ASSET_LIST", "write")),
                   db: Session = Depends(get_db)):
    g = _get_group(db, group_id)
    if g.kind != "static":
        raise HTTPException(status_code=400, detail="Assets join a dynamic group through its rules")
    n = _change_members(db, g, body.asset_ids, body.action)
    if body.action == "add":
        log_action(db, **_who(current_user, request, "asset_group.members", "asset_list", g.id),
                   detail=f"Added {n} asset(s) to group '{g.name}'")
    else:
        log_action(db, **_who(current_user, request, "asset_group.members", "asset_list", g.id),
                   detail=f"Removed {n} asset(s) from group '{g.name}'")
    db.commit()
    return {"changed": n, "asset_count": len(G.member_ids(db, g))}


def _change_members(db: Session, g: AssetGroup, asset_ids: List[int], action: str) -> int:
    have = {r[0] for r in db.query(AssetGroupMember.asset_id).filter(AssetGroupMember.group_id == g.id)}
    if action == "add":
        new = [a for a in _existing_ids(db, asset_ids) if a not in have]
        for aid in new:
            db.add(AssetGroupMember(group_id=g.id, asset_id=aid))
        return len(new)
    return db.query(AssetGroupMember).filter(AssetGroupMember.group_id == g.id,
                                             AssetGroupMember.asset_id.in_(asset_ids)) \
        .delete(synchronize_session=False)


@groups_router.delete("/{group_id}")
def delete_group(group_id: int, request: Request,
                 current_user: User = Depends(require_permission("ASSET_LIST", "write")),
                 db: Session = Depends(get_db)):
    g = _get_group(db, group_id)
    used = db.query(func.count(ScheduledJob.id)).filter(ScheduledJob.group_id == g.id).scalar() or 0
    if used:
        raise HTTPException(status_code=409, detail="Scheduled audits use this group: delete them first")
    if db.query(GroupRun.id).filter(GroupRun.group_id == g.id, GroupRun.status.in_(R.ACTIVE)).first():
        raise HTTPException(status_code=409, detail="A group audit of this group is running")
    name = g.name
    db.delete(g)
    log_action(db, **_who(current_user, request, "asset_group.delete", "asset_list", group_id),
               detail=f"Deleted asset group '{name}'")
    db.commit()
    return {"deleted": group_id}


# ── bulk edit ────────────────────────────────────────────────────────────────

class BulkBody(BaseModel):
    asset_ids: List[int] = Field(..., min_length=1, max_length=MAX_BULK)
    action: Literal["add_tags", "remove_tags", "set_owner", "set_location", "set_status", "set_zone",
                    "add_to_group", "delete"]
    tags: List[str] = Field(default_factory=list, max_length=20)
    value: Optional[Any] = None
    confirm_count: Optional[int] = None      # delete: the number of assets, typed by the user


def _int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Not a number")


@bulk_router.post("/bulk")
def bulk_edit(body: BulkBody, request: Request,
              current_user: User = Depends(require_permission("ASSET_LIST", "write")),
              db: Session = Depends(get_db)):
    """One change to many assets. Each changed asset gets its own entry in the asset change history;
    the audit trail gets one line for the whole change."""
    ids = _existing_ids(db, body.asset_ids)
    if not ids:
        raise HTTPException(status_code=404, detail="Asset not found")
    a = body.action
    if a in ("add_tags", "remove_tags"):
        if not body.tags:
            raise HTTPException(status_code=400, detail="Enter at least one tag")
        try:
            n = G.add_tags(db, ids, body.tags) if a == "add_tags" else G.remove_tags(db, ids, body.tags)
            tags = ", ".join(G.normalize_tag(t) for t in body.tags)
        except G.RuleError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if a == "add_tags":
            log_action(db, **_who(current_user, request, "asset.bulk_tag", "asset_list"),
                       detail=f"Added tag(s) {tags} to {len(ids)} asset(s)")
        else:
            log_action(db, **_who(current_user, request, "asset.bulk_tag", "asset_list"),
                       detail=f"Removed tag(s) {tags} from {len(ids)} asset(s)")
        db.commit()
        return {"changed": n}
    if a in ("set_owner", "set_location", "set_status"):
        return _bulk_fields(db, ids, a, body.value, current_user, request)
    if a == "set_zone":
        require_permission("RISK", "write")(current_user=current_user, db=db)
        return _bulk_zone(db, ids, body.value, current_user, request)
    if a == "add_to_group":
        g = _get_group(db, _int(body.value))
        if g.kind != "static":
            raise HTTPException(status_code=400, detail="Assets join a dynamic group through its rules")
        n = _change_members(db, g, ids, "add")
        log_action(db, **_who(current_user, request, "asset_group.members", "asset_list", g.id),
                   detail=f"Added {n} asset(s) to group '{g.name}'")
        db.commit()
        return {"changed": n}
    return _bulk_delete(db, ids, body.confirm_count, current_user, request)


def _bulk_fields(db: Session, ids: List[int], action: str, value, user: User, request: Request) -> Dict:
    from app.models.asset_locations import AssetLocation
    from app.models.asset_owners import AssetOwner
    from app.models.asset_log import log_asset_updated
    from app.modules.assets.service import AssetService
    field = {"set_owner": "owner_id", "set_location": "location_id", "set_status": "status"}[action]
    if field == "status":
        try:
            value = StatusEnum(value)
        except ValueError:
            raise HTTPException(status_code=400, detail="Unknown status")
    else:
        model = AssetOwner if field == "owner_id" else AssetLocation
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = None
        if value is None or db.get(model, value) is None:
            raise HTTPException(status_code=400, detail="Choose an owner or location that exists")
    changed = 0
    for aid in ids:
        try:
            asset, changes = AssetService.update_asset(db, aid, {field: value})
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if asset is not None and changes:
            log_asset_updated(db, user.id, asset.id, asset.asset_name, changes, asset.ip_address)
            changed += 1
    who = _who(user, request, "asset.bulk_update", "asset_list")
    if field == "owner_id":
        log_action(db, **who, detail=f"Changed the owner of {changed} asset(s) in one step")
    elif field == "location_id":
        log_action(db, **who, detail=f"Changed the location of {changed} asset(s) in one step")
    else:
        log_action(db, **who, detail=f"Changed the status of {changed} asset(s) in one step")
    db.commit()
    return {"changed": changed}


def _bulk_zone(db: Session, ids: List[int], value, user: User, request: Request) -> Dict:
    from app.models.asset_log import log_asset_updated
    from app.models.risk import AssetRiskProfile, RiskZone
    from app.modules.risk.service import risk_calculation_service
    zone_id = _int(value) if value not in (None, "") else None
    if zone_id is not None and db.get(RiskZone, zone_id) is None:
        raise HTTPException(status_code=400, detail="Zone not found")
    changed = []
    for aid in ids:
        p = db.query(AssetRiskProfile).filter(AssetRiskProfile.asset_id == aid).first()
        if p is None:
            p = AssetRiskProfile(asset_id=aid, criticality_level="medium", criticality_score=50, created_by=user.id)
            db.add(p)
        if p.zone_id == zone_id and p.zone_is_default is False:
            continue
        p.zone_id, p.zone_is_default, p.updated_by = zone_id, False, user.id
        changed.append(aid)
    db.commit()
    for aid in changed:
        asset = db.get(Asset, aid)
        log_asset_updated(db, user.id, aid, asset.asset_name, changes={"risk_profile.zone_id": zone_id},
                          ip_address=asset.ip_address)
        try:
            risk_calculation_service.calculate(aid, db, trigger_type="profile_updated")
        except Exception:  # noqa: BLE001 - the score is recalculated on the next audit anyway
            db.rollback()
    log_action(db, **_who(user, request, "asset.bulk_update", "asset_list"),
               detail=f"Changed the zone of {len(changed)} asset(s) in one step")
    db.commit()
    return {"changed": len(changed)}


def _bulk_delete(db: Session, ids: List[int], confirm: Optional[int], user: User, request: Request) -> Dict:
    from app.models.asset_log import log_asset_deleted
    from app.modules.assets.service import AssetInUseError, AssetService
    require_permission("ASSET_LIST", "delete")(current_user=user, db=db)
    if confirm != len(ids):
        raise HTTPException(status_code=400, detail="Type the number of assets to confirm the deletion")
    deleted, refused = 0, []
    for aid in ids:
        asset = db.get(Asset, aid)
        name, ip = asset.asset_name, asset.ip_address
        try:
            if AssetService.delete_asset(db, aid):
                log_asset_deleted(db, user.id, aid, name, ip)
                deleted += 1
        except AssetInUseError as exc:
            db.rollback()
            refused.append({"id": aid, "asset_name": name, "reason": str(exc)})
    log_action(db, **_who(user, request, "asset.bulk_delete", "asset_list"),
               detail=f"Deleted {deleted} asset(s) in one step")
    db.commit()
    return {"deleted": deleted, "refused": refused}


# ── credential profiles ──────────────────────────────────────────────────────

class ProfileBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    kind: Literal["ssh", "winrm", "mssql", "sophos_api"] = "ssh"
    username: str = Field(..., min_length=1, max_length=256)
    secrets: Dict[str, Optional[str]] = Field(default_factory=dict)
    options: Dict[str, Any] = Field(default_factory=dict)
    description: Optional[str] = Field(None, max_length=2000)
    rotation_days: int = Field(90, ge=0, le=3650)


class ProfileTestBody(BaseModel):
    asset_id: int


def _secrets(body: ProfileBody) -> Dict[str, str]:
    for k, v in body.secrets.items():
        if k not in P.SECRET_FIELDS:
            raise HTTPException(status_code=400, detail="Unknown secret field")
        if v is not None and len(v) > 1024:
            raise HTTPException(status_code=400, detail="A secret is at most 1024 characters")
    return {k: v for k, v in body.secrets.items() if v}


def _get_profile(db: Session, profile_id: int) -> CredentialProfile:
    p = db.get(CredentialProfile, profile_id)
    if p is None:
        raise HTTPException(status_code=404, detail="Credential profile not found")
    return p


@profiles_router.get("")
def list_profiles(current_user: User = Depends(require_permission("CREDENTIAL_PROFILES", "read")),
                  db: Session = Depends(get_db)):
    """Profiles without their secrets: name, kind, user name, which secrets are set, age."""
    return [P.public(p) for p in db.query(CredentialProfile).order_by(CredentialProfile.name)]


@profiles_router.get("/technologies")
def technologies(current_user: User = Depends(require_permission("CREDENTIAL_PROFILES", "read"))):
    """Technology -> the profile kind it signs in with."""
    from app.modules.scheduling.audit_dispatch import SUPPORTED_TECHNOLOGIES
    return {t: P.kind_for(t) for t in SUPPORTED_TECHNOLOGIES if P.kind_for(t)}


@profiles_router.post("")
def create_profile(body: ProfileBody, request: Request, current_user: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    if _name_taken(db, CredentialProfile, body.name):
        raise HTTPException(status_code=409, detail="A credential profile with this name exists")
    try:
        p = P.create(db, {**body.model_dump(), "secrets": _secrets(body)}, current_user.id)
        db.flush()
    except P.ProfileError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="A credential profile with this name exists")
    log_action(db, **_who(current_user, request, "credential_profile.create", "credential_profiles", p.id),
               detail=f"Created credential profile '{p.name}' for user '{p.username}'")
    db.commit()
    return P.public(p)


@profiles_router.put("/{profile_id}")
def update_profile(profile_id: int, body: ProfileBody, request: Request,
                   current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    p = _get_profile(db, profile_id)
    if body.kind != p.kind:
        raise HTTPException(status_code=400, detail="The kind of a credential profile cannot change")
    if _name_taken(db, CredentialProfile, body.name, p.id):
        raise HTTPException(status_code=409, detail="A credential profile with this name exists")
    try:
        changed = P.update(db, p, {**body.model_dump(), "secrets": _secrets(body)})
        db.flush()
    except P.ProfileError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="A credential profile with this name exists")
    if changed:
        log_action(db, **_who(current_user, request, "credential_profile.update", "credential_profiles", p.id),
                   detail=f"Changed the sign-in details of credential profile '{p.name}'")
    else:
        log_action(db, **_who(current_user, request, "credential_profile.update", "credential_profiles", p.id),
                   detail=f"Changed credential profile '{p.name}'")
    db.commit()
    return P.public(p)


@profiles_router.delete("/{profile_id}")
def delete_profile(profile_id: int, request: Request, current_user: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    p = _get_profile(db, profile_id)
    if db.query(ScheduledJob.id).filter(ScheduledJob.credential_profile_id == p.id).first():
        raise HTTPException(status_code=409, detail="Scheduled audits use this profile: change or delete them first")
    if db.query(GroupRun.id).filter(GroupRun.credential_profile_id == p.id, GroupRun.status.in_(R.ACTIVE)).first():
        raise HTTPException(status_code=409, detail="A group audit with this profile is running")
    name = p.name
    db.delete(p)
    log_action(db, **_who(current_user, request, "credential_profile.delete", "credential_profiles", profile_id),
               detail=f"Deleted credential profile '{name}'")
    db.commit()
    return {"deleted": profile_id}


@profiles_router.post("/{profile_id}/test")
def test_profile(profile_id: int, body: ProfileTestBody, request: Request,
                 current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Sign in to one asset with the profile; nothing is changed on the device."""
    from app.core.asset_entitlement import AssetLimitExceeded, require_licensed_asset
    p = _get_profile(db, profile_id)
    asset = db.get(Asset, body.asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not asset.ip_address:
        raise HTTPException(status_code=400, detail="The asset has no IP address")
    try:
        require_licensed_asset(db, asset.id)
    except AssetLimitExceeded as exc:
        raise HTTPException(status_code=403, detail=exc.detail)
    try:
        P.test_sign_in(p, asset.ip_address)
        result, detail = "ok", None
    except PermissionError as exc:
        result, detail = "auth", R._clean(exc)
    except ConnectionError as exc:
        result, detail = "unreachable", R._clean(exc)
    except Exception as exc:  # noqa: BLE001
        result, detail = R.classify(str(exc)), R._clean(exc)
    log_action(db, **_who(current_user, request, "credential_profile.test", "credential_profiles", p.id),
               result="success" if result == "ok" else "failed",
               detail=f"Tested credential profile '{p.name}' on {asset.asset_name} ({asset.ip_address})")
    db.commit()
    return {"result": result, "detail": detail}


# ── group runs ───────────────────────────────────────────────────────────────

class RunBody(BaseModel):
    group_id: int
    technology: str = Field(..., max_length=40)
    credential_profile_id: int
    audit_profile: Optional[Literal["L1", "FULL"]] = None
    concurrency: int = Field(10, ge=1, le=R.MAX_CONCURRENCY)


def _get_run(db: Session, run_id: int) -> GroupRun:
    run = db.get(GroupRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Group audit not found")
    return run


@runs_router.get("")
def list_runs(limit: int = Query(100, ge=1, le=500),
              current_user: User = Depends(require_permission("AUDITING", "read")),
              db: Session = Depends(get_db)):
    rows = db.query(GroupRun).order_by(GroupRun.id.desc()).limit(limit).all()
    c = R.counts(db, [r.id for r in rows])
    return [R.summary(r, c[r.id]) for r in rows]


@runs_router.post("")
def start_run(body: RunBody, request: Request,
              current_user: User = Depends(require_permission("AUDITING", "write")),
              db: Session = Depends(get_db)):
    """Audit every asset of a group with one technology, signing in with a credential profile."""
    require_permission("CREDENTIAL_PROFILES", "read")(current_user=current_user, db=db)
    g = _get_group(db, body.group_id)
    p = _get_profile(db, body.credential_profile_id)
    try:
        run = R.start_run(db, g, body.technology, p, body.audit_profile, body.concurrency, current_user)
    except R.RunError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))
    total = db.query(func.count(GroupRunItem.id)).filter(GroupRunItem.run_id == run.id).scalar()
    log_action(db, **_who(current_user, request, "group_run.start", "auditing", run.id),
               detail=f"Started a {run.technology} audit of group '{g.name}' ({total} assets) "
                      f"with credential profile '{p.name}'")
    db.commit()
    return R.summary(run, R.counts(db, [run.id])[run.id])


@runs_router.get("/{run_id}")
def get_run(run_id: int, current_user: User = Depends(require_permission("AUDITING", "read")),
            db: Session = Depends(get_db)):
    run = _get_run(db, run_id)
    items = [{"id": i.id, "asset_id": i.asset_id, "asset_name": i.asset_name, "ip_address": i.ip_address,
              "status": i.status, "reason": i.reason, "detail": i.detail, "session_id": i.session_id,
              "compliance": i.compliance, "attempts": i.attempts, "started_at": i.started_at,
              "finished_at": i.finished_at} for i in run.items]
    return {**R.summary(run, R.counts(db, [run.id])[run.id]), "items": items}


@runs_router.post("/{run_id}/stop")
def stop_run(run_id: int, request: Request, current_user: User = Depends(require_permission("AUDITING", "write")),
             db: Session = Depends(get_db)):
    """Stop: queued assets are cancelled; audits already running finish."""
    run = _get_run(db, run_id)
    if run.status not in ("queued", "running"):
        raise HTTPException(status_code=400, detail="The group audit is not running")
    R.stop(db, run)
    log_action(db, **_who(current_user, request, "group_run.stop", "auditing", run.id),
               detail=f"Stopped the audit of group '{run.group_name}'")
    db.commit()
    return R.summary(run, R.counts(db, [run.id])[run.id])


@runs_router.post("/{run_id}/retry")
def retry_run(run_id: int, request: Request, current_user: User = Depends(require_permission("AUDITING", "write")),
              db: Session = Depends(get_db)):
    """Queue the assets that failed again, with the same profile."""
    require_permission("CREDENTIAL_PROFILES", "read")(current_user=current_user, db=db)
    run = _get_run(db, run_id)
    if run.credential_profile_id is None:
        raise HTTPException(status_code=400, detail="The credential profile was deleted")
    try:
        n = R.retry_failed(db, run)
    except R.RunError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    log_action(db, **_who(current_user, request, "group_run.retry", "auditing", run.id),
               detail=f"Retried {n} failed asset(s) of the audit of group '{run.group_name}'")
    db.commit()
    return R.summary(run, R.counts(db, [run.id])[run.id])
