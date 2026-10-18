"""
API of API keys (app/modules/api_keys), under /api/api-keys: system administrators only. An API key itself
can never reach these routes (its account is never an administrator). Every change is in the audit trail.
"""
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_admin
from app.models import User
from app.models.api_key import ApiKey
from app.modules.api_keys import service as S

router = APIRouter(prefix="/api/api-keys", tags=["API keys"])


def _log(db: Session, user: User, request: Request, action: str, detail: str, target_id: Optional[int] = None):
    from app.models.security_audit_log import log_action
    log_action(db, user_id=user.id, username=user.username, action=action, module="user_management",
               target_id=target_id, ip_address=request.client.host if request.client else None, detail=detail)


def _get(db: Session, key_id: int) -> ApiKey:
    key = db.get(ApiKey, key_id)
    if key is None:
        raise HTTPException(status_code=404, detail="API key not found")
    return key


class ScopeIn(BaseModel):
    module: str = Field(..., max_length=40)
    write: bool = False


class KeyIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    scopes: List[ScopeIn] = Field(..., min_length=1, max_length=40)
    allowed_ips: List[str] = Field(default_factory=list, max_length=S.MAX_NETWORKS)
    expires_at: datetime


def _naive(dt: datetime) -> datetime:
    """UTC without tzinfo, as the database keeps times."""
    if dt.tzinfo is not None:
        from datetime import timezone
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


@router.get("")
def list_keys(current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    keys = db.query(ApiKey).order_by(ApiKey.revoked_at.isnot(None), ApiKey.created_at.desc()).all()
    names = S.names_for(db, keys)
    return {"keys": [S.out(db, k, names) for k in keys],
            "modules": {"read": S.READ_MODULES, "write": S.WRITE_MODULES},
            "max_days": S.MAX_DAYS, "default_days": S.DEFAULT_DAYS}


@router.post("", status_code=201)
def create_key(body: KeyIn, request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """A new key: the answer holds its token, shown this once."""
    try:
        key, token = S.create(db, current_user, body.name, body.description, [s.model_dump() for s in body.scopes],
                              body.allowed_ips, _naive(body.expires_at))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    name, account = key.name, db.get(User, key.user_id).username
    _log(db, current_user, request, "api_key.create", f"Created the API key {name} (account {account})", key.id)
    db.commit()
    return {"key": S.out(db, key, S.names_for(db, [key])), "token": token}


@router.put("/{key_id}")
def update_key(key_id: int, body: KeyIn, request: Request, current_user: User = Depends(require_admin),
               db: Session = Depends(get_db)):
    key = _get(db, key_id)
    try:
        S.update(db, key, body.name, body.description, [s.model_dump() for s in body.scopes], body.allowed_ips,
                 _naive(body.expires_at))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    name = key.name
    _log(db, current_user, request, "api_key.update", f"Changed the API key {name}", key.id)
    db.commit()
    return S.out(db, key, S.names_for(db, [key]))


@router.post("/{key_id}/renew")
def renew_key(key_id: int, request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """A new secret; the old token stops working at once. The answer holds the new token, shown this once."""
    key = _get(db, key_id)
    try:
        token = S.renew(db, key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    name = key.name
    _log(db, current_user, request, "api_key.renew", f"Renewed the secret of the API key {name}", key.id)
    db.commit()
    return {"key": S.out(db, key, S.names_for(db, [key])), "token": token}


@router.post("/{key_id}/revoke")
def revoke_key(key_id: int, request: Request, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    key = _get(db, key_id)
    S.revoke(db, key, current_user)
    name = key.name
    _log(db, current_user, request, "api_key.revoke", f"Revoked the API key {name}", key.id)
    db.commit()
    return S.out(db, key, S.names_for(db, [key]))
