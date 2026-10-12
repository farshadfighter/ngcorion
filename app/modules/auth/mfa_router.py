"""
Two-step sign-in (TOTP) endpoints; the rules live in app/core/mfa.py.

  POST /auth/login/mfa                  second sign-in step: mfa_token + code -> session
  GET  /auth/me/mfa                     the caller's state
  POST /auth/me/mfa/setup               a new secret to scan (password; and a code when replacing)
  POST /auth/me/mfa/confirm             first code from the new secret turns it on -> recovery codes
  POST /auth/me/mfa/recovery-codes      new recovery codes (password + code)
  POST /auth/me/mfa/disable             turn off (password + code), not for a role that requires it
  POST /api/users/{id}/mfa/reset        a system administrator clears another user's setup
  GET/PUT /api/system/authentication    the policy (system administrators)
  GET  /api/system/authentication/users every user's state, for the user list

Turning it on, off, replacing the app or a reset ends the user's other sessions (UserMfa.version);
the endpoints that do so for the caller answer with a fresh session for this browser.
"""
from datetime import datetime, timezone
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core import credential_crypto as cc
from app.core import mfa, totp
from app.core.auth_rate_limiter import check_login_rate_limit
from app.core.database import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.security import verify_password
from app.models import User
from app.models.security_audit_log import log_action, log_user_action
from app.schemas.auth import MfaLogin, Token

from .router import issue_session, log_login_attempt

router = APIRouter()
admin_router = APIRouter(tags=["Authentication"])


def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _log(db: Session, user: User, action: str, ip: Optional[str], detail: str, result: str = "success"):
    log_action(db, user_id=user.id, username=user.username, action=action, module="auth",
               target_id=user.id, ip_address=ip, result=result, detail=detail)


def _check_password(db: Session, user: User, password: str, request: Request, action: str) -> None:
    """The caller's own password, counted like sign-in failures (a stolen session cannot guess it)."""
    ip = _ip(request)
    check_login_rate_limit(db, ip, user.username)
    if not verify_password(password or "", user.hashed_password):
        log_login_attempt(db, user.username, False, ip, request.headers.get("user-agent", "Unknown"),
                          "Wrong password for a two-step sign-in change")
        _log(db, user, action, ip, "Wrong password for a two-step sign-in change", "failed")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The current password is incorrect.")


def _check_code(db: Session, user: User, row, code: str, request: Request, action: str) -> str:
    how = mfa.check_code(row, code)
    if how is None:
        db.rollback()
        ip = _ip(request)
        log_login_attempt(db, user.username, False, ip, request.headers.get("user-agent", "Unknown"),
                          "Wrong two-step code")
        _log(db, user, action, ip, "Wrong two-step code", "failed")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The code is not correct.")
    return how


# ── Second sign-in step ───────────────────────────────────────────────────

@router.post("/login/mfa", response_model=Token)
def login_mfa(body: MfaLogin, request: Request, db: Session = Depends(get_db)):
    """Exchange the password step's mfa_token and a code (app or recovery) for the session."""
    ip, agent = _ip(request), request.headers.get("user-agent", "Unknown")
    user = mfa.read_mfa_token(db, body.mfa_token)
    try:
        check_login_rate_limit(db, ip, user.username)
    except HTTPException:
        log_login_attempt(db, user.username, False, ip, agent, "Rate limited")
        _log(db, user, "auth.login", ip, "Rate limited", "failed")
        raise
    row = mfa.get_row(db, user.id, for_update=True)
    how = mfa.check_code(row, body.code)
    if how is None:
        db.rollback()
        log_login_attempt(db, user.username, False, ip, agent, "Wrong two-step code")
        _log(db, user, "auth.login", ip, "Wrong two-step code", "failed")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="The code is not correct.")
    left = len(row.recovery_codes or [])
    db.commit()
    log_login_attempt(db, user.username, True, ip, agent, f"Login successfully with {user.role.value} Role.")
    if how == "recovery":
        _log(db, user, "auth.login", ip,
             f"Login successful (role={user.role.value}) with a recovery code; {left} left")
    else:
        _log(db, user, "auth.login", ip, f"Login successful (role={user.role.value}) with a two-step code")
    answer = issue_session(db, user, ip)
    if how == "recovery":
        answer["mfa_recovery_codes_left"] = left
    return answer


# ── The caller's own setup ────────────────────────────────────────────────

class MfaStatus(BaseModel):
    enabled: bool
    required: bool
    enrolment_due: bool
    deadline: Optional[datetime] = None
    enabled_at: Optional[datetime] = None
    recovery_codes_left: int = 0


class MfaSetupRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)
    # Replacing the app of an account that already has one: a code from the current app.
    code: Optional[str] = Field(None, max_length=20)


class MfaSetup(BaseModel):
    secret: str
    otpauth_uri: str
    replacing: bool


class MfaCode(BaseModel):
    code: str = Field(..., min_length=6, max_length=20)


class MfaPasswordCode(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)
    code: str = Field(..., min_length=6, max_length=20)


class RecoveryCodes(BaseModel):
    recovery_codes: List[str]


class MfaEnabled(RecoveryCodes):
    session: Token


@router.get("/me/mfa", response_model=MfaStatus)
def my_mfa(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return mfa.status_of(db, current_user)


@router.post("/me/mfa/setup", response_model=MfaSetup)
def start_setup(body: MfaSetupRequest, request: Request,
                current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """A new secret for the authenticator app. It does nothing until a code from it is confirmed."""
    _check_password(db, current_user, body.password, request, "auth.mfa_setup")
    row = mfa.get_or_create_row(db, current_user.id, for_update=True)
    replacing = bool(row.enabled)
    if replacing:
        if not body.code:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Enter a code from your current authenticator app.")
        _check_code(db, current_user, row, body.code, request, "auth.mfa_setup")
    secret = totp.new_secret()
    row.pending_secret = cc.encrypt(secret, cc.PURPOSE_MFA)
    db.commit()
    return {"secret": secret, "otpauth_uri": totp.provisioning_uri(secret, current_user.username),
            "replacing": replacing}


@router.post("/me/mfa/confirm", response_model=MfaEnabled)
def confirm_setup(body: MfaCode, request: Request,
                  current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The first code from the new secret: two-step sign-in is on (or moved to the new app). Other
    sessions end; the answer carries the recovery codes (shown once) and a session for this one."""
    ip = _ip(request)
    row = mfa.get_row(db, current_user.id, for_update=True)
    if row is None or not row.pending_secret:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Start the setup again.")
    pending = cc.decrypt(row.pending_secret, cc.PURPOSE_MFA)
    step = totp.verify(pending, body.code)
    if step is None:
        db.rollback()
        _log(db, current_user, "auth.mfa_enable", ip, "Wrong two-step code", "failed")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="The code is not correct. Check the phone's clock and try the next code.")
    replacing = bool(row.enabled)
    row.secret, row.pending_secret = row.pending_secret, None
    row.enabled, row.last_used_step, row.deadline = True, step, None
    row.enabled_at = datetime.now(timezone.utc)
    codes = mfa.new_recovery_codes(row)
    mfa.bump(row)
    db.commit()
    _log(db, current_user, "auth.mfa_enable", ip,
         "Moved two-step sign-in to a new authenticator app" if replacing else "Turned on two-step sign-in")
    return {"recovery_codes": codes, "session": issue_session(db, current_user, ip)}


@router.post("/me/mfa/recovery-codes", response_model=RecoveryCodes)
def new_codes(body: MfaPasswordCode, request: Request,
              current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """A fresh set of recovery codes; the old ones stop working."""
    _check_password(db, current_user, body.password, request, "auth.mfa_recovery_codes")
    row = mfa.get_row(db, current_user.id, for_update=True)
    if row is None or not row.enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Two-step sign-in is not on.")
    _check_code(db, current_user, row, body.code, request, "auth.mfa_recovery_codes")
    codes = mfa.new_recovery_codes(row)
    db.commit()
    _log(db, current_user, "auth.mfa_recovery_codes", _ip(request), "Made new recovery codes")
    return {"recovery_codes": codes}


@router.post("/me/mfa/disable", response_model=Token)
def disable(body: MfaPasswordCode, request: Request,
            current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Turn two-step sign-in off; refused when the caller's role must use it."""
    if mfa.is_required(mfa.get_policy(db), current_user):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Your role must use two-step sign-in. To move it to a new phone, set it up again.")
    _check_password(db, current_user, body.password, request, "auth.mfa_disable")
    row = mfa.get_row(db, current_user.id, for_update=True)
    if row is None or not row.enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Two-step sign-in is not on.")
    _check_code(db, current_user, row, body.code, request, "auth.mfa_disable")
    _clear(row)
    db.commit()
    _log(db, current_user, "auth.mfa_disable", _ip(request), "Turned off two-step sign-in")
    return issue_session(db, current_user, _ip(request))


def _clear(row) -> None:
    row.enabled, row.secret, row.pending_secret = False, None, None
    row.last_used_step, row.enabled_at, row.recovery_codes = None, None, []
    row.deadline = None
    mfa.bump(row)


# ── System administrators ─────────────────────────────────────────────────

@admin_router.post("/api/users/{user_id}/mfa/reset")
def reset_user_mfa(user_id: int, request: Request,
                   current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """For a user who lost their phone and their recovery codes: their setup is cleared and their
    sessions end. If their role requires two-step sign-in they set it up again right after the next
    password sign-in. Not for one's own account."""
    if user_id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Manage your own two-step sign-in from your account menu")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    row = mfa.get_or_create_row(db, user.id, for_update=True)
    _clear(row)
    if mfa.is_required(mfa.get_policy(db), user):
        row.deadline = datetime.now(timezone.utc)
    db.commit()
    log_user_action(db, current_user, "user.mfa_reset", user.id, ip=_ip(request),
                    detail=f"Reset two-step sign-in for '{user.username}'; they set it up again at the next sign-in")
    return {"message": "Two-step sign-in was reset"}


class MfaPolicy(BaseModel):
    required_roles: List[Literal["admin", "manager", "user", "guest"]]
    grace_days: int = Field(..., ge=0, le=mfa.MAX_GRACE_DAYS)


@admin_router.get("/api/system/authentication", response_model=MfaPolicy)
def get_policy(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return mfa.get_policy(db)


@admin_router.put("/api/system/authentication", response_model=MfaPolicy)
def put_policy(body: MfaPolicy, request: Request,
               current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Which roles must use two-step sign-in, and the days a user of such a role has to set it up
    (from their next sign-in; system administrators get none). A deadline already given stays."""
    saved = mfa.save_policy(db, body.model_dump(), current_user)
    roles = ", ".join(saved["required_roles"]) or "none"
    log_action(db, user_id=current_user.id, username=current_user.username, action="system_config.authentication",
               module="system_config", ip_address=_ip(request),
               detail=f"Two-step sign-in required for: {roles}; grace period {saved['grace_days']} days")
    return saved


class UserMfaState(BaseModel):
    user_id: int
    enabled: bool
    required: bool
    enrolment_due: bool
    deadline: Optional[datetime] = None


@admin_router.get("/api/system/authentication/users", response_model=List[UserMfaState])
def users_state(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    policy = mfa.get_policy(db)
    rows = {r.user_id: r for r in db.query(mfa.UserMfa).all()}
    out = []
    for user in db.query(User).order_by(User.id).all():
        row = rows.get(user.id)
        required = mfa.is_required(policy, user)
        out.append({"user_id": user.id, "enabled": bool(row and row.enabled), "required": required,
                    "enrolment_due": mfa.enrolment_due(policy, user, row),
                    "deadline": row.deadline if (row and required and not row.enabled) else None})
    return out
