"""
Two-step sign-in (TOTP): the policy, a user's state, the short-lived token between the two steps,
and checking a code.

Policy (System Configuration section "authentication"): the roles that must use two-step sign-in
and how many days a user of such a role has to set it up. System administrators get no grace
period. Until a required user has set it up, their session can reach only the setup itself
(ENROLMENT_ALLOWED), and every other request answers 403 with X-MFA-Enrollment-Required.

Sign-in with two-step on: the password step returns an `mfa_token` (a JWT with purpose "mfa",
valid MFA_TOKEN_MINUTES), never an access token; POST /auth/login/mfa exchanges it and a code for
the access token. get_current_user refuses any token that has a purpose, so the mfa token opens
nothing else.

Every access token carries `mfv`, the user's UserMfa.version when it was issued. Turning two-step
on or off, or an administrator resetting it, raises the version and so ends every older session.
"""
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

import jwt
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core import credential_crypto as cc
from app.core import totp
from app.core.config import settings
from app.core.security import password_fingerprint
from app.models import User, UserRole
from app.models.system_config import SystemConfigSetting
from app.models.user_mfa import UserMfa

SECTION = "authentication"
ROLES = ("admin", "manager", "user", "guest")
DEFAULT_POLICY = {"required_roles": ["admin", "manager"], "grace_days": 7}
MAX_GRACE_DAYS = 90
MFA_TOKEN_MINUTES = 5
MFA_PURPOSE = "mfa"

# What a session may still reach while its user must set up two-step sign-in first.
ENROLMENT_ALLOWED = frozenset({
    "/auth/me", "/auth/me/password", "/auth/me/language", "/auth/logout",
    "/auth/me/mfa", "/auth/me/mfa/setup", "/auth/me/mfa/confirm",
})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


# ── Policy ────────────────────────────────────────────────────────────────

def get_policy(db: Session) -> Dict:
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION).first()
    stored = (row.config_json or {}) if row else {}
    roles = stored.get("required_roles", DEFAULT_POLICY["required_roles"])
    grace = stored.get("grace_days", DEFAULT_POLICY["grace_days"])
    return {"required_roles": [r for r in ROLES if r in (roles or [])],
            "grace_days": max(0, min(MAX_GRACE_DAYS, int(grace)))}


def save_policy(db: Session, policy: Dict, actor: User) -> Dict:
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION).first()
    if row is None:
        row = SystemConfigSetting(section=SECTION)
        db.add(row)
    row.config_json = {"required_roles": [r for r in ROLES if r in policy["required_roles"]],
                       "grace_days": int(policy["grace_days"])}
    row.updated_by = actor.id
    db.commit()
    return get_policy(db)


def is_required(policy: Dict, user: User) -> bool:
    return user.role.value in policy["required_roles"]


# ── A user's state ────────────────────────────────────────────────────────

def get_row(db: Session, user_id: int, for_update: bool = False) -> Optional[UserMfa]:
    query = db.query(UserMfa).filter(UserMfa.user_id == user_id)
    if for_update:
        query = query.with_for_update()
    return query.first()


def get_or_create_row(db: Session, user_id: int, for_update: bool = False) -> UserMfa:
    row = get_row(db, user_id, for_update)
    if row is None:
        row = UserMfa(user_id=user_id, enabled=False, recovery_codes=[], version=0)
        db.add(row)
        db.flush()
    return row


def version_of(row: Optional[UserMfa]) -> int:
    return int(row.version or 0) if row else 0


def bump(row: UserMfa) -> None:
    """End every session issued before now (their mfv no longer matches)."""
    row.version = version_of(row) + 1


def enrolment_due(policy: Dict, user: User, row: Optional[UserMfa], now: Optional[datetime] = None) -> bool:
    """The user must set up two-step sign-in before doing anything else."""
    if (row is not None and row.enabled) or not is_required(policy, user):
        return False
    if user.role == UserRole.ADMIN or policy["grace_days"] == 0:
        return True
    deadline = _aware(row.deadline) if row is not None else None
    return deadline is not None and deadline <= (now or _now())


def start_grace(db: Session, policy: Dict, user: User) -> Optional[UserMfa]:
    """At sign-in: a required user without two-step sign-in gets their deadline the first time."""
    if not is_required(policy, user):
        return get_row(db, user.id)
    row = get_or_create_row(db, user.id)
    if not row.enabled and row.deadline is None:
        days = 0 if user.role == UserRole.ADMIN else policy["grace_days"]
        row.deadline = _now() + timedelta(days=days)
        db.commit()
    return row


def status_of(db: Session, user: User) -> Dict:
    policy = get_policy(db)
    row = get_row(db, user.id)
    required = is_required(policy, user)
    return {
        "enabled": bool(row and row.enabled),
        "required": required,
        "enrolment_due": enrolment_due(policy, user, row),
        "deadline": _aware(row.deadline) if (row and required and not row.enabled) else None,
        "enabled_at": _aware(row.enabled_at) if (row and row.enabled) else None,
        "recovery_codes_left": len(row.recovery_codes or []) if (row and row.enabled) else 0,
    }


# ── The token between the two steps ───────────────────────────────────────

def issue_mfa_token(user: User, row: UserMfa) -> str:
    now = _now()
    return jwt.encode({
        "sub": user.username, "purpose": MFA_PURPOSE,
        "pwv": password_fingerprint(user.hashed_password), "mfv": version_of(row),
        "iat": now, "exp": now + timedelta(minutes=MFA_TOKEN_MINUTES),
    }, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def read_mfa_token(db: Session, token: str) -> User:
    """The user an mfa token was issued to, while it is still valid for them."""
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="The sign-in step has expired. Sign in again.")
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except jwt.InvalidTokenError:
        raise invalid
    if payload.get("purpose") != MFA_PURPOSE:
        raise invalid
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if (user is None or not user.is_active
            or payload.get("pwv") != password_fingerprint(user.hashed_password)
            or payload.get("mfv") != version_of(get_row(db, user.id))):
        raise invalid
    return user


# ── Codes ─────────────────────────────────────────────────────────────────

def secret_of(row: UserMfa) -> str:
    return cc.decrypt(row.secret, cc.PURPOSE_MFA)


def check_code(row: UserMfa, code: str) -> Optional[str]:
    """"totp" or "recovery" when the code is accepted (and used up), None otherwise. The row should
    be locked (get_row(for_update=True)) so two requests cannot use one code."""
    code = (code or "").strip()
    if not row or not row.enabled or not row.secret:
        return None
    step = totp.verify(secret_of(row), code, row.last_used_step)
    if step is not None:
        row.last_used_step = step
        return "totp"
    remaining = list(row.recovery_codes or [])
    for stored in remaining:
        if totp.recovery_code_matches(code, stored):
            remaining.remove(stored)
            row.recovery_codes = remaining
            return "recovery"
    return None


def new_recovery_codes(row: UserMfa) -> list:
    codes = totp.new_recovery_codes()
    row.recovery_codes = [totp.hash_recovery_code(c) for c in codes]
    return codes
