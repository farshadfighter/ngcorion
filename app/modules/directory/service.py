"""
Sign-in with Active Directory / LDAP: the settings, sign-in of a directory account, and the
periodic check that ends access for accounts the directory has disabled, deleted or taken out of
every mapped group.

Settings live in System Configuration section "directory" (the service account's password
encrypted like every other System Configuration secret, so a restore on another server re-keys
it). Group mappings: a directory group → a role, and for roles other than admin, module
permissions. A user in several mapped groups gets the highest role and every permission any of
them gives; a user in none of them is refused.

Which password is checked: a local account (auth_source "local") always signs in with its own
password, whatever the directory says, so a local administrator keeps working when the directory
is down (and that sign-in raises the "emergency sign-in" alert while directory sign-in is on).
Any other name goes to the directory; its account is made at the first sign-in.
"""
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core import credential_crypto as cc
from app.core.security import get_password_hash
from app.models import User, UserPermission, UserRole
from app.models.security_audit_log import log_action
from app.models.system_config import SystemConfigSetting
from app.models.user_permission import ModuleEnum, get_all_modules

from .ldap import DirectoryUnavailable, DirectoryUser, Session as LdapSession, Settings, norm_dn

logger = logging.getLogger(__name__)

SECTION = "directory"
STATUS_SECTION = "directory_status"
ENC_PREFIX = "enc:v1:"              # same marker as the rest of System Configuration (rekey.py)
ROLE_RANK = {"guest": 0, "user": 1, "manager": 2, "admin": 3}
CHECK_MINUTES = 15

DEFAULT_CONFIG = {
    "enabled": False, "kind": "ad", "servers": [], "security": "ldaps", "base_dn": "", "bind_dn": "",
    "bind_password": "", "ca_pem": "", "user_attr": "", "user_filter": "", "group_filter": "",
    "mappings": [],
}


# ── Settings ──────────────────────────────────────────────────────────────

def _row(db: Session, section: str) -> Optional[SystemConfigSetting]:
    return db.query(SystemConfigSetting).filter(SystemConfigSetting.section == section).first()


def load_config(db: Session) -> Dict:
    """The stored settings, password decrypted."""
    row = _row(db, SECTION)
    cfg = {**DEFAULT_CONFIG, **((row.config_json or {}) if row else {})}
    pw = cfg.get("bind_password") or ""
    if pw.startswith(ENC_PREFIX):
        try:
            pw = cc.decrypt(pw[len(ENC_PREFIX):], cc.PURPOSE_SYSTEM_CONFIG)
        except ValueError:
            logger.error("[Directory] the service account password cannot be decrypted (SECRET_KEY changed?)")
            pw = ""
    cfg["bind_password"] = pw
    return cfg


def public_config(db: Session) -> Dict:
    """The settings for the UI: never the password, only whether one is stored."""
    cfg = load_config(db)
    out = {k: v for k, v in cfg.items() if k != "bind_password"}
    out["has_password"] = bool(cfg["bind_password"])
    return out


def save_config(db: Session, cfg: Dict, actor: User) -> Dict:
    stored = load_config(db)
    new = {**DEFAULT_CONFIG, **{k: cfg[k] for k in DEFAULT_CONFIG if k in cfg}}
    # An empty password field means "keep the stored one".
    password = cfg.get("bind_password") or stored["bind_password"]
    new["bind_password"] = ENC_PREFIX + cc.encrypt(password, cc.PURPOSE_SYSTEM_CONFIG) if password else ""
    row = _row(db, SECTION)
    if row is None:
        row = SystemConfigSetting(section=SECTION)
        db.add(row)
    row.config_json = new
    row.updated_by = actor.id
    db.commit()
    return public_config(db)


def settings_from(cfg: Dict) -> Settings:
    return Settings(kind=cfg["kind"], servers=[s for s in cfg["servers"] if s.strip()], security=cfg["security"],
                    base_dn=cfg["base_dn"], bind_dn=cfg["bind_dn"], bind_password=cfg["bind_password"],
                    ca_pem=cfg.get("ca_pem") or "", user_attr=cfg.get("user_attr") or "",
                    user_filter=cfg.get("user_filter") or "", group_filter=cfg.get("group_filter") or "")


def enabled(db: Session) -> bool:
    row = _row(db, SECTION)
    return bool(row and (row.config_json or {}).get("enabled"))


# ── Group mapping ─────────────────────────────────────────────────────────

@dataclass
class Grant:
    role: str
    permissions: Dict[str, Dict[str, bool]]     # module → {read, write, delete}
    groups: List[str]                           # the mapped groups that gave it (as configured)


def resolve(cfg: Dict, groups) -> Optional[Grant]:
    """What the user's groups give; None when no group of theirs is mapped."""
    mine = {norm_dn(g) for g in groups}
    hits = [m for m in cfg.get("mappings") or [] if norm_dn(m.get("group_dn", "")) in mine]
    if not hits:
        return None
    role = max((m["role"] for m in hits), key=lambda r: ROLE_RANK.get(r, -1))
    perms: Dict[str, Dict[str, bool]] = {}
    if role != "admin":
        for m in hits:
            for p in m.get("permissions") or []:
                cur = perms.setdefault(p["module"], {"read": False, "write": False, "delete": False})
                cur["read"] |= bool(p.get("can_read"))
                cur["write"] |= bool(p.get("can_write"))
                cur["delete"] |= bool(p.get("can_delete"))
    return Grant(role=role, permissions=perms, groups=[m["group_dn"] for m in hits])


def _apply_grant(db: Session, user: User, grant: Grant) -> List[str]:
    """Give the user the role and permissions their groups give; what changed ("role",
    "permissions"), for _log_changes."""
    changes = []
    if user.role.value != grant.role:
        changes.append("role")
        user.role = UserRole(grant.role)
    wanted = {} if grant.role == "admin" else grant.permissions
    current = {p.module.value: {"read": p.can_read, "write": p.can_write, "delete": p.can_delete}
               for p in db.query(UserPermission).filter(UserPermission.user_id == user.id)}
    current = {k: v for k, v in current.items() if any(v.values())}
    wanted = {k: v for k, v in wanted.items() if any(v.values())}
    if current != wanted:
        changes.append("permissions")
        db.query(UserPermission).filter(UserPermission.user_id == user.id).delete()
        valid = set(get_all_modules())
        for module, p in wanted.items():
            if module in valid:
                db.add(UserPermission(user_id=user.id, module=ModuleEnum(module), can_read=p["read"],
                                      can_write=p["write"], can_delete=p["delete"]))
    return changes


def _log_changes(db: Session, user: User, changes: List[str], ip: Optional[str], by_check: bool) -> None:
    who = {"user_id": None, "username": "system"} if by_check else {"user_id": user.id, "username": user.username}
    common = {"action": "user.directory_sync", "module": "user_management", "target_id": user.id, "ip_address": ip}
    for change in changes:
        if change == "role":
            log_action(db, **who, **common,
                       detail=f"Role of '{user.username}' set to '{user.role.value}' by its directory groups")
        elif change == "permissions":
            log_action(db, **who, **common, detail=f"Permissions of '{user.username}' set by its directory groups")
        else:
            log_action(db, **who, **common, detail=f"Turned on '{user.username}' again: the directory allows it")


# ── Sign-in ───────────────────────────────────────────────────────────────

@dataclass
class SignIn:
    outcome: str                      # ok | bad_credentials | disabled | no_group | inactive
    user: Optional[User] = None
    detail: str = ""


def local_account(db: Session, username: str) -> Optional[User]:
    """A local account with exactly this name (it is signed in locally, never via the directory)."""
    return db.query(User).filter(User.username == username, User.auth_source == "local").first()


def _directory_account(db: Session, name: str) -> Optional[User]:
    return (db.query(User).filter(User.auth_source == "ldap", func.lower(User.username) == name.lower())
            .first())


def _free_email(db: Session, email: Optional[str], user_id: Optional[int]) -> Optional[str]:
    if not email:
        return None
    clash = db.query(User).filter(func.lower(User.email) == email.lower())
    if user_id:
        clash = clash.filter(User.id != user_id)
    return None if clash.first() else email


def sign_in(db: Session, username: str, password: str, ip: Optional[str]) -> SignIn:
    """Check a name and password against the directory and bring the account up to date. Raises
    DirectoryUnavailable when no server can be used."""
    cfg = load_config(db)
    with LdapSession(settings_from(cfg)) as ds:
        found = ds.find_user(username)
        if found is None:
            return SignIn("bad_credentials", detail="Incorrect username or password")
        if not ds.check_password(found, password):
            return SignIn("bad_credentials", detail="Incorrect username or password")
        if found.disabled:
            return SignIn("disabled", detail="The account is disabled in the directory")
        found.groups = ds.groups_of(found)
    grant = resolve(cfg, found.groups)
    if grant is None:
        return SignIn("no_group", detail="The account is in no group mapped to an NGCorion role")
    return SignIn("ok", user=_provision(db, found, grant, ip))


def _provision(db: Session, found: DirectoryUser, grant: Grant, ip: Optional[str]) -> User:
    name = found.username.lower()
    user = _directory_account(db, name)
    now = datetime.now(timezone.utc)
    if user is None:
        user = User(username=name, email=_free_email(db, found.email, None),
                    hashed_password=get_password_hash(secrets.token_urlsafe(32)),
                    role=UserRole(grant.role), is_active=True, must_change_password=False,
                    auth_source="ldap", external_dn=found.dn)
        db.add(user)
        db.flush()
        _apply_grant(db, user, grant)
        user.directory_synced_at = now
        db.commit()
        log_action(db, user_id=user.id, username=user.username, action="user.create", module="user_management",
                   target_id=user.id, ip_address=ip,
                   detail=f"Created directory account '{user.username}' with role '{grant.role}' at its first sign-in")
        return user
    changes = _apply_grant(db, user, grant)
    user.external_dn = found.dn
    if found.email and not user.email:
        user.email = _free_email(db, found.email, user.id)
    if not user.is_active and user.disabled_by_directory:
        user.is_active, user.disabled_by_directory = True, False
        changes.append("enabled")
    user.directory_synced_at = now
    db.commit()
    _log_changes(db, user, changes, ip, by_check=False)
    return user


def check_password(db: Session, user: User, password: str) -> bool:
    """The password of a directory account (for steps that ask for it again, e.g. two-step setup)."""
    cfg = load_config(db)
    with LdapSession(settings_from(cfg)) as ds:
        found = ds.find_user(user.username)
        return bool(found and not found.disabled and ds.check_password(found, password))


def end_directory_sessions(db: Session) -> int:
    """Directory sign-in was turned off: every open session of a directory account ends now (their
    tokens are revoked like at sign-out). They cannot sign in again until it is turned back on."""
    from app.models.revoked_token import RevokedToken
    from app.models.user_session import UserSession
    now = datetime.now(timezone.utc)
    rows = (db.query(UserSession).join(User, User.id == UserSession.user_id)
            .filter(User.auth_source == "ldap", UserSession.expires_at > now).all())
    for row in rows:
        if db.get(RevokedToken, row.jti) is None:
            db.add(RevokedToken(jti=row.jti, user_id=row.user_id, expires_at=row.expires_at))
    db.commit()
    return len(rows)


# ── The periodic check ────────────────────────────────────────────────────

def _save_status(db: Session, status: Dict) -> None:
    row = _row(db, STATUS_SECTION)
    if row is None:
        row = SystemConfigSetting(section=STATUS_SECTION)
        db.add(row)
    row.config_json = status
    db.commit()


def last_status(db: Session) -> Optional[Dict]:
    row = _row(db, STATUS_SECTION)
    return row.config_json if row else None


def check_accounts(db: Session) -> Dict:
    """Every directory account against the directory: role and permissions follow its groups;
    disabled, deleted or out of every mapped group turns it off (its sessions end at the next
    request). Nothing changes when the directory cannot be reached."""
    now = datetime.now(timezone.utc)
    if not enabled(db):
        return {"ran_at": now.isoformat(), "ok": True, "skipped": True}
    cfg = load_config(db)
    users = db.query(User).filter(User.auth_source == "ldap", User.is_active.is_(True)).all()
    turned_off: List[Tuple[User, str]] = []     # (user, "missing" | "disabled" | "no_group")
    updated = 0
    try:
        with LdapSession(settings_from(cfg)) as ds:
            for user in users:
                found = ds.find_user(user.username)
                if found is None:
                    turned_off.append((user, "missing"))
                    continue
                if found.disabled:
                    turned_off.append((user, "disabled"))
                    continue
                grant = resolve(cfg, ds.groups_of(found))
                if grant is None:
                    turned_off.append((user, "no_group"))
                    continue
                changes = _apply_grant(db, user, grant)
                user.directory_synced_at = now
                db.commit()
                if changes:
                    updated += 1
                    _log_changes(db, user, changes, None, by_check=True)
    except DirectoryUnavailable as exc:
        db.rollback()
        status = {"ran_at": now.isoformat(), "ok": False, "error": str(exc), "checked": 0}
        _save_status(db, status)
        logger.warning("[Directory] check skipped: %s", exc)
        return status
    for user, why in turned_off:
        user.is_active, user.disabled_by_directory = False, True
        db.commit()
        common = {"user_id": None, "username": "system", "action": "user.directory_disable",
                  "module": "user_management", "target_id": user.id}
        if why == "missing":
            log_action(db, **common, detail=f"Turned off '{user.username}': no longer in the directory")
        elif why == "disabled":
            log_action(db, **common, detail=f"Turned off '{user.username}': disabled in the directory")
        else:
            log_action(db, **common, detail=f"Turned off '{user.username}': in no mapped directory group any more")
    db.commit()
    status = {"ran_at": now.isoformat(), "ok": True, "checked": len(users), "updated": updated,
              "turned_off": len(turned_off)}
    _save_status(db, status)
    return status
