"""
Active Directory / LDAP settings (system administrators only).

  GET  /api/system/directory              settings (never the password) and the last check
  PUT  /api/system/directory              save; an empty password keeps the stored one
  POST /api/system/directory/test         connect and bind with the given (unsaved) settings
  POST /api/system/directory/test-user    find a user, list their groups and what the mapping gives;
                                          with a password, check it too. Nothing is saved.
  POST /api/system/directory/groups       search groups by name, for the mapping editor
  POST /api/system/directory/check        run the account check now
"""
import re
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_admin
from app.models import User
from app.models.security_audit_log import log_action
from app.models.user_permission import get_all_modules

from . import service
from .ldap import DirectoryUnavailable, Session as LdapSession

router = APIRouter(prefix="/api/system/directory", tags=["Directory sign-in"])

_SERVER = re.compile(r"^[A-Za-z0-9.\-]{1,253}(:\d{1,5})?$")


class MappingPermission(BaseModel):
    module: str
    can_read: bool = False
    can_write: bool = False
    can_delete: bool = False


class GroupMapping(BaseModel):
    group_dn: str = Field(..., min_length=3, max_length=1024)
    role: Literal["admin", "manager", "user", "guest"]
    permissions: List[MappingPermission] = []

    @field_validator("permissions")
    @classmethod
    def _known_modules(cls, v):
        known = set(get_all_modules())
        bad = [p.module for p in v if p.module not in known]
        if bad:
            raise ValueError(f"Unknown module: {', '.join(bad)}")
        return v


class DirectoryConfig(BaseModel):
    enabled: bool = False
    kind: Literal["ad", "ldap"] = "ad"
    servers: List[str] = Field(default_factory=list, max_length=10)
    security: Literal["ldaps", "starttls", "plain"] = "ldaps"     # plain: no encryption, by choice
    base_dn: str = Field("", max_length=1024)
    bind_dn: str = Field("", max_length=1024)
    bind_password: Optional[str] = Field(None, max_length=256)   # empty: keep the stored one
    ca_pem: str = Field("", max_length=100_000)
    user_attr: str = Field("", max_length=64, pattern=r"^[A-Za-z0-9-]*$")
    user_filter: str = Field("", max_length=1024)
    group_filter: str = Field("", max_length=1024)
    mappings: List[GroupMapping] = Field(default_factory=list, max_length=100)

    @field_validator("servers")
    @classmethod
    def _servers(cls, v):
        out = [s.strip() for s in v if s.strip()]
        for s in out:
            if not _SERVER.match(s):
                raise ValueError(f"Not a server name or address: {s}")
        return out

    @field_validator("ca_pem")
    @classmethod
    def _pem(cls, v):
        if v.strip() and "-----BEGIN CERTIFICATE-----" not in v:
            raise ValueError("The CA certificate must be in PEM format (-----BEGIN CERTIFICATE-----)")
        return v

    @field_validator("user_filter", "group_filter")
    @classmethod
    def _filter(cls, v):
        v = v.strip()
        if v and not (v.startswith("(") and v.endswith(")") and v.count("(") == v.count(")")):
            raise ValueError("A filter must be in parentheses, e.g. (objectClass=user)")
        return v


def _complete(cfg: dict) -> None:
    missing = [label for key, label in (("servers", "servers"), ("base_dn", "base DN"),
                                        ("bind_dn", "service account"), ("bind_password", "service account password"))
               if not cfg.get(key)]
    if missing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Directory settings incomplete: {', '.join(missing)}")


def _merged(db: Session, body: DirectoryConfig) -> dict:
    """The posted settings, with the stored password when none was typed."""
    cfg = body.model_dump()
    if not cfg.get("bind_password"):
        cfg["bind_password"] = service.load_config(db)["bind_password"]
    cfg["mappings"] = [m.model_dump() for m in body.mappings]
    return cfg


@router.get("")
def get_directory(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return {"config": service.public_config(db), "status": service.last_status(db)}


@router.put("")
def put_directory(body: DirectoryConfig, request: Request, current_user: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    cfg = _merged(db, body)
    if cfg["enabled"]:
        _complete(cfg)
        if not cfg["mappings"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Map at least one directory group to a role before turning directory sign-in on")
    was_on = service.enabled(db)
    stored_security = service.load_config(db)["security"]
    saved = service.save_config(db, cfg, current_user)
    who = {"user_id": current_user.id, "username": current_user.username, "action": "system_config.directory",
           "module": "system_config", "ip_address": request.client.host if request.client else None}
    if saved["enabled"] and not was_on:
        log_action(db, **who, detail="Turned on sign-in with the organization's directory")
    elif was_on and not saved["enabled"]:
        service.end_directory_sessions(db)
        log_action(db, **who, detail="Turned off sign-in with the organization's directory")
    else:
        log_action(db, **who, detail="Changed the directory sign-in settings")
    if saved["security"] == "plain" and (stored_security != "plain" or not was_on) and saved["enabled"]:
        log_action(db, **who, detail="Directory sign-in uses plain LDAP: passwords cross the network unencrypted")
    return {"config": saved, "status": service.last_status(db)}


@router.post("/test")
def test_directory(body: DirectoryConfig, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    cfg = _merged(db, body)
    _complete(cfg)
    try:
        with LdapSession(service.settings_from(cfg)) as ds:
            base_found = ds.exists(cfg["base_dn"])
            return {"ok": base_found, "server": ds.address,
                    "message": "Connected and signed in as the service account"
                    if base_found else "Connected, but the base DN was not found"}
    except DirectoryUnavailable as exc:
        return {"ok": False, "server": None, "message": str(exc)}


class TestUser(BaseModel):
    config: DirectoryConfig
    username: str = Field(..., min_length=1, max_length=256)
    password: Optional[str] = Field(None, max_length=256)


@router.post("/test-user")
def test_user(body: TestUser, request: Request, current_user: User = Depends(require_admin),
              db: Session = Depends(get_db)):
    cfg = _merged(db, body.config)
    _complete(cfg)
    if body.password:   # checking someone's password is on record
        log_action(db, user_id=current_user.id, username=current_user.username, action="system_config.directory_test",
                   module="system_config", ip_address=request.client.host if request.client else None,
                   detail=f"Tested the directory sign-in of '{body.username}'")
    try:
        with LdapSession(service.settings_from(cfg)) as ds:
            found = ds.find_user(body.username)
            if found is None:
                return {"found": False}
            groups = sorted(ds.groups_of(found), key=str.lower)
            password_ok = ds.check_password(found, body.password) if body.password else None
    except DirectoryUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
    grant = service.resolve(cfg, groups)
    return {"found": True, "dn": found.dn, "username": found.username, "email": found.email,
            "display_name": found.display_name, "disabled": found.disabled, "groups": groups,
            "mapped_groups": grant.groups if grant else [], "role": grant.role if grant else None,
            "password_ok": password_ok}


class GroupSearch(BaseModel):
    config: DirectoryConfig
    text: str = Field("", max_length=128)


@router.post("/groups")
def search_groups(body: GroupSearch, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    cfg = _merged(db, body.config)
    _complete(cfg)
    try:
        with LdapSession(service.settings_from(cfg)) as ds:
            return ds.search_groups(body.text)
    except DirectoryUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))


@router.post("/check")
def check_now(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    if not service.enabled(db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Directory sign-in is off")
    return service.check_accounts(db)
