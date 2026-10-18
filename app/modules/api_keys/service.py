"""
API keys of other systems (app/models/api_key.py): making, changing, renewing and revoking them, and their
scopes.

Scopes are read, or read and write, per permission module. Some modules are never given to a key:
managing users and using stored credential profiles (a key must not create accounts or borrow passwords).
Write is further withheld where it changes devices or the system itself - hardening, restoring device
backups, system configuration, logs - so a leaked key cannot reconfigure the network. Nothing is ever
deleted through a key (no delete permission). A key's role is always "user": administrator-only routes stay
closed to it.
"""
import re
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.core import api_keys as K
from app.core.security import get_password_hash
from app.models import User, UserPermission, UserRole
from app.models.api_key import AUTH_SOURCE_API_KEY, ApiKey
from app.models.user_permission import ModuleEnum

READ_MODULES = ["dashboard", "asset_list", "asset_requirement", "asset_auto_discovery", "auditing", "hardening",
                "risk", "cve", "remediation", "backup", "noc", "topology", "architecture_validation",
                "design_configuration", "reports", "logs", "system_config"]
WRITE_MODULES = ["asset_list", "asset_requirement", "asset_auto_discovery", "auditing", "cve", "remediation",
                 "noc", "topology", "architecture_validation", "design_configuration", "reports"]
MAX_DAYS = 365
DEFAULT_DAYS = 90
MAX_NETWORKS = 20


def clean_scopes(scopes: List[Dict]) -> List[Dict]:
    """[{"module", "write"}] limited to what a key may have; ValueError for anything else."""
    out = {}
    for s in scopes or []:
        module, write = s.get("module"), bool(s.get("write"))
        if module not in READ_MODULES:
            raise ValueError(f"An API key cannot have the module {module}")
        if write and module not in WRITE_MODULES:
            raise ValueError(f"An API key can only read the module {module}")
        out[module] = write
    if not out:
        raise ValueError("Give the key at least one module")
    return [{"module": m, "write": w} for m, w in sorted(out.items())]


def check_expiry(expires_at: datetime, now: Optional[datetime] = None) -> datetime:
    now = now or datetime.utcnow()
    if expires_at <= now:
        raise ValueError("The end date must be in the future")
    if expires_at > now + timedelta(days=MAX_DAYS + 1):          # the chosen day is valid to its end
        days = MAX_DAYS
        raise ValueError(f"An API key is valid for at most {days} days")
    return expires_at


def _username(db: Session, name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "key"
    base, n = f"api-{slug}", 1
    candidate = base
    while db.query(User.id).filter(User.username == candidate).first():
        n += 1
        candidate = f"{base}-{n}"
    return candidate


def _set_permissions(db: Session, user: User, scopes: List[Dict]) -> None:
    db.query(UserPermission).filter(UserPermission.user_id == user.id).delete()
    for s in scopes:
        db.add(UserPermission(user_id=user.id, module=ModuleEnum(s["module"]), can_read=True,
                              can_write=bool(s["write"]), can_delete=False))


def create(db: Session, by: User, name: str, description: Optional[str], scopes: List[Dict],
           allowed_ips: List[str], expires_at: datetime) -> Tuple[ApiKey, str]:
    """A new key and its token (shown once). Flushes; the caller commits."""
    scopes = clean_scopes(scopes)
    networks = K.clean_networks(allowed_ips)[:MAX_NETWORKS]
    check_expiry(expires_at)
    user = User(username=_username(db, name), email=None, hashed_password=get_password_hash(secrets.token_urlsafe(32)),
                role=UserRole.USER, is_active=True, auth_source=AUTH_SOURCE_API_KEY, must_change_password=False)
    db.add(user)
    db.flush()
    _set_permissions(db, user, scopes)
    key_id, secret = K.new_secret()
    while db.query(ApiKey.id).filter(ApiKey.key_id == key_id).first():
        key_id, secret = K.new_secret()
    key = ApiKey(key_id=key_id, name=name.strip(), description=(description or "").strip() or None,
                 secret_hash=K.hash_secret(secret), user_id=user.id, scopes=scopes, allowed_ips=networks or None,
                 expires_at=expires_at, created_by=by.id, created_at=datetime.utcnow())
    db.add(key)
    db.flush()
    return key, K.token_of(key_id, secret)


def update(db: Session, key: ApiKey, name: str, description: Optional[str], scopes: List[Dict],
           allowed_ips: List[str], expires_at: datetime) -> ApiKey:
    if key.revoked_at is not None:
        raise ValueError("A revoked key cannot be changed")
    key.scopes = clean_scopes(scopes)
    key.allowed_ips = K.clean_networks(allowed_ips)[:MAX_NETWORKS] or None
    key.expires_at = check_expiry(expires_at)
    key.name, key.description = name.strip(), (description or "").strip() or None
    _set_permissions(db, db.get(User, key.user_id), key.scopes)
    db.flush()
    return key


def renew(db: Session, key: ApiKey) -> str:
    """A new secret (the old token stops working at once); the new token, shown once."""
    if key.revoked_at is not None:
        raise ValueError("A revoked key cannot be renewed")
    _, secret = K.new_secret()
    key.secret_hash, key.renewed_at = K.hash_secret(secret), datetime.utcnow()
    db.flush()
    return K.token_of(key.key_id, secret)


def revoke(db: Session, key: ApiKey, by: User) -> None:
    """For good: the key stops working and its account is turned off (kept, so the audit trail keeps its
    name)."""
    if key.revoked_at is None:
        key.revoked_at, key.revoked_by = datetime.utcnow(), by.id
    user = db.get(User, key.user_id)
    if user is not None:
        user.is_active = False
    db.flush()


def status_of(key: ApiKey, now: Optional[datetime] = None) -> str:
    now = now or datetime.utcnow()
    if key.revoked_at is not None:
        return "revoked"
    return "expired" if key.expires_at <= now else "active"


def out(db: Session, key: ApiKey, names: Optional[Dict[int, str]] = None, now: Optional[datetime] = None) -> Dict:
    now = now or datetime.utcnow()
    iso = lambda d: d.isoformat() if d else None   # noqa: E731
    names = names or {}
    return {"id": key.id, "name": key.name, "description": key.description, "prefix": f"{K.PREFIX}{key.key_id}",
            "account": names.get(key.user_id), "scopes": key.scopes or [], "allowed_ips": key.allowed_ips or [],
            "status": status_of(key, now), "expires_at": iso(key.expires_at),
            "days_left": (key.expires_at - now).days if key.expires_at > now else 0,
            "created_at": iso(key.created_at), "created_by": names.get(key.created_by), "renewed_at": iso(key.renewed_at),
            "last_used_at": iso(key.last_used_at), "last_used_ip": key.last_used_ip,
            "revoked_at": iso(key.revoked_at), "revoked_by": names.get(key.revoked_by)}


def names_for(db: Session, keys: List[ApiKey]) -> Dict[int, str]:
    ids = {i for k in keys for i in (k.user_id, k.created_by, k.revoked_by) if i}
    return {u.id: u.username for u in db.query(User).filter(User.id.in_(ids))} if ids else {}
