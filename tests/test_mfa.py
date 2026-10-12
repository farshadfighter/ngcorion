"""
Two-step sign-in (TOTP): the RFC test vectors, the sign-in step, setup, recovery codes, the policy
that forces setup, sessions ending when it changes, and an administrator's reset
(app/core/totp.py, app/core/mfa.py, app/modules/auth/mfa_router.py).
"""
import hashlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.core import mfa, totp
from app.core.database import SessionLocal
from app.core.dependencies import get_current_user
from app.core.security import create_access_token, get_password_hash, password_fingerprint
from app.models import LoginLog, User, UserRole
from app.models.system_config import SystemConfigSetting
from app.models.user_mfa import UserMfa
from app.modules.auth import mfa_router as r
from app.modules.auth.router import login
from app.schemas.auth import MfaLogin, UserLogin

PW = "Mfa-Pass-123!"


@pytest.fixture
def db():
    s = SessionLocal()
    s.query(SystemConfigSetting).filter(SystemConfigSetting.section == mfa.SECTION).delete()
    s.commit()
    yield s
    s.rollback()
    s.query(LoginLog).filter(LoginLog.username.like("mfa_%")).delete(synchronize_session=False)
    s.query(User).filter(User.username.like("mfa_%")).delete(synchronize_session=False)
    s.query(SystemConfigSetting).filter(SystemConfigSetting.section == mfa.SECTION).delete()
    s.commit()
    s.close()


def _user(db, name="mfa_probe", role=UserRole.USER):
    u = User(username=name, email=f"{name}@example.com", hashed_password=get_password_hash(PW),
             role=role, is_active=True)
    db.add(u)
    db.commit()
    return u


def _req(path="/x", ip="10.9.8.7"):
    return SimpleNamespace(url=SimpleNamespace(path=path), client=SimpleNamespace(host=ip),
                           headers={"user-agent": "pytest"}, method="POST")


def _creds(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _session_token(db, user):
    return create_access_token({"sub": user.username, "role": user.role.value,
                                "pwv": password_fingerprint(user.hashed_password),
                                "mfv": mfa.version_of(mfa.get_row(db, user.id))})


def _enrol(db, user):
    """Set up two-step sign-in the way the UI does; returns (secret, recovery codes, session token)."""
    setup = r.start_setup(r.MfaSetupRequest(password=PW), _req(), user, db)
    done = r.confirm_setup(r.MfaCode(code=totp.code_at(setup["secret"])), _req(), user, db)
    return setup["secret"], done["recovery_codes"], done["session"]["access_token"]


def _next_code(secret):
    """A valid code newer than the one just used (the next 30-second step)."""
    return totp.code_at(secret, datetime.now(timezone.utc).timestamp() + totp.STEP_SECONDS)


# ── RFC vectors and code rules ────────────────────────────────────────────

def test_rfc4226_hotp_vectors():
    key = b"12345678901234567890"
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    assert [totp.hotp(key, i) for i in range(10)] == expected


@pytest.mark.parametrize("when,code", [(59, "94287082"), (1111111109, "07081804"),
                                       (1234567890, "89005924"), (20000000000, "65353130")])
def test_rfc6238_totp_sha1_vectors(when, code):
    assert totp.hotp(b"12345678901234567890", when // 30, digits=8, digest=hashlib.sha1) == code


def test_codes_are_accepted_once_and_only_near_now():
    secret = totp.new_secret()
    now = 1_800_000_000
    code = totp.code_at(secret, now)
    step = totp.verify(secret, code, None, when=now)
    assert step == totp.step_at(now)
    assert totp.verify(secret, code, step, when=now) is None              # replay
    assert totp.verify(secret, totp.code_at(secret, now - 30), None, when=now) is not None  # 30 s drift
    assert totp.verify(secret, totp.code_at(secret, now - 90), None, when=now) is None
    assert totp.verify(secret, "12345", None, when=now) is None
    assert totp.verify(secret, "abcdef", None, when=now) is None


def test_recovery_codes_are_salted_hashes():
    code = totp.new_recovery_codes(1)[0]
    stored = totp.hash_recovery_code(code)
    assert code not in stored and stored != totp.hash_recovery_code(code)
    assert totp.recovery_code_matches(code.lower().replace("-", " "), stored)
    assert not totp.recovery_code_matches("AAAA-AAAA", stored)
    assert not totp.recovery_code_matches(code, "garbage")


def test_provisioning_uri():
    uri = totp.provisioning_uri("JBSWY3DPEHPK3PXP", "sara.ops")
    assert uri.startswith("otpauth://totp/NGCorion%3Asara.ops?secret=JBSWY3DPEHPK3PXP&issuer=NGCorion")


# ── Setup and sign-in ─────────────────────────────────────────────────────

def test_setup_needs_the_password_and_a_code_from_the_new_secret(db):
    user = _user(db)
    with pytest.raises(HTTPException) as exc:
        r.start_setup(r.MfaSetupRequest(password="wrong"), _req(), user, db)
    assert exc.value.status_code == 400
    setup = r.start_setup(r.MfaSetupRequest(password=PW), _req(), user, db)
    assert setup["otpauth_uri"].startswith("otpauth://totp/") and not setup["replacing"]
    row = mfa.get_row(db, user.id)
    assert not row.enabled and row.pending_secret and setup["secret"] not in row.pending_secret  # encrypted
    with pytest.raises(HTTPException):
        r.confirm_setup(r.MfaCode(code="000000"), _req(), user, db)
    done = r.confirm_setup(r.MfaCode(code=totp.code_at(setup["secret"])), _req(), user, db)
    assert len(done["recovery_codes"]) == 8
    db.refresh(row)
    assert row.enabled and row.pending_secret is None and row.version == 1
    assert r.my_mfa(user, db)["recovery_codes_left"] == 8


def test_password_alone_no_longer_opens_a_session(db):
    user = _user(db)
    secret, codes, _ = _enrol(db, user)
    first = login(UserLogin(username=user.username, password=PW), _req("/auth/login"), db)
    assert first["mfa_required"] and "access_token" not in first
    # the mfa token is not a session
    with pytest.raises(HTTPException) as exc:
        get_current_user(_creds(first["mfa_token"]), db, _req("/auth/me"))
    assert exc.value.status_code == 401
    with pytest.raises(HTTPException) as exc:
        r.login_mfa(MfaLogin(mfa_token=first["mfa_token"], code="000000"), _req(), db)
    assert exc.value.status_code == 401
    code = _next_code(secret)
    out = r.login_mfa(MfaLogin(mfa_token=first["mfa_token"], code=code), _req(), db)
    assert get_current_user(_creds(out["access_token"]), db, _req("/api/assets/")).id == user.id
    # the same code a second time is refused
    with pytest.raises(HTTPException):
        r.login_mfa(MfaLogin(mfa_token=first["mfa_token"], code=code), _req(), db)
    # a recovery code works once and says how many are left
    out = r.login_mfa(MfaLogin(mfa_token=first["mfa_token"], code=codes[0]), _req(), db)
    assert out["mfa_recovery_codes_left"] == 7
    with pytest.raises(HTTPException):
        r.login_mfa(MfaLogin(mfa_token=first["mfa_token"], code=codes[0]), _req(), db)


def test_wrong_codes_count_towards_the_sign_in_lockout(db):
    user = _user(db)
    _enrol(db, user)
    first = login(UserLogin(username=user.username, password=PW), _req("/auth/login", ip="10.0.0.55"), db)
    for _ in range(5):
        with pytest.raises(HTTPException) as exc:
            r.login_mfa(MfaLogin(mfa_token=first["mfa_token"], code="000000"), _req(ip="10.0.0.55"), db)
        assert exc.value.status_code == 401
    with pytest.raises(HTTPException) as exc:
        r.login_mfa(MfaLogin(mfa_token=first["mfa_token"], code="000000"), _req(ip="10.0.0.55"), db)
    assert exc.value.status_code == 429


def test_turning_it_on_ends_older_sessions(db):
    user = _user(db)
    before = _session_token(db, user)
    _, _, after = _enrol(db, user)
    with pytest.raises(HTTPException) as exc:
        get_current_user(_creds(before), db, _req("/auth/me"))
    assert exc.value.status_code == 401
    assert get_current_user(_creds(after), db, _req("/auth/me")).id == user.id


def test_disable_needs_password_and_code_and_is_refused_for_a_required_role(db):
    user = _user(db)
    secret, _, _ = _enrol(db, user)
    with pytest.raises(HTTPException):
        r.disable(r.MfaPasswordCode(password=PW, code="000000"), _req(), user, db)
    out = r.disable(r.MfaPasswordCode(password=PW, code=_next_code(secret)), _req(), user, db)
    assert out["access_token"] and not mfa.get_row(db, user.id).enabled
    assert mfa.get_row(db, user.id).version == 2

    boss = _user(db, "mfa_boss", UserRole.MANAGER)          # managers must use it by default
    secret, _, _ = _enrol(db, boss)
    with pytest.raises(HTTPException) as exc:
        r.disable(r.MfaPasswordCode(password=PW, code=_next_code(secret)), _req(), boss, db)
    assert "must use two-step" in exc.value.detail


def test_replacing_the_app_needs_a_code_from_the_old_one(db):
    user = _user(db)
    secret, _, _ = _enrol(db, user)
    with pytest.raises(HTTPException):
        r.start_setup(r.MfaSetupRequest(password=PW), _req(), user, db)
    setup = r.start_setup(r.MfaSetupRequest(password=PW, code=_next_code(secret)), _req(), user, db)
    assert setup["replacing"]
    # until confirmed, the old app still signs in
    assert mfa.get_row(db, user.id).enabled
    new_secret = setup["secret"]
    r.confirm_setup(r.MfaCode(code=totp.code_at(new_secret)), _req(), user, db)
    assert mfa.secret_of(mfa.get_row(db, user.id)) == new_secret


# ── Policy ────────────────────────────────────────────────────────────────

def test_admin_must_set_it_up_before_anything_else(db):
    admin = _user(db, "mfa_admin", UserRole.ADMIN)
    out = login(UserLogin(username=admin.username, password=PW), _req("/auth/login"), db)
    creds = _creds(out["access_token"])
    with pytest.raises(HTTPException) as exc:
        get_current_user(creds, db, _req("/api/assets/"))
    assert exc.value.status_code == 403 and exc.value.headers["X-MFA-Enrollment-Required"] == "1"
    for path in mfa.ENROLMENT_ALLOWED:
        assert get_current_user(creds, db, _req(path)).id == admin.id
    _, _, token = _enrol(db, admin)
    assert get_current_user(_creds(token), db, _req("/api/assets/")).id == admin.id


def test_grace_period_then_enforced(db):
    boss = _user(db, "mfa_mgr", UserRole.MANAGER)
    out = login(UserLogin(username=boss.username, password=PW), _req("/auth/login"), db)
    row = mfa.get_row(db, boss.id)
    assert row.deadline is not None and row.deadline > datetime.now(timezone.utc) + timedelta(days=6)
    creds = _creds(out["access_token"])
    assert get_current_user(creds, db, _req("/api/assets/")).id == boss.id   # within the grace period
    row.deadline = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    with pytest.raises(HTTPException) as exc:
        get_current_user(creds, db, _req("/api/assets/"))
    assert exc.value.status_code == 403


def test_policy_roles_and_users_outside_them(db):
    admin = _user(db, "mfa_admin2", UserRole.ADMIN)
    plain = _user(db, "mfa_plain", UserRole.USER)
    assert mfa.get_policy(db) == {"required_roles": ["admin", "manager"], "grace_days": 7}
    r.put_policy(r.MfaPolicy(required_roles=["admin", "user"], grace_days=0), _req(), admin, db)
    assert mfa.get_policy(db) == {"required_roles": ["admin", "user"], "grace_days": 0}
    out = login(UserLogin(username=plain.username, password=PW), _req("/auth/login"), db)
    with pytest.raises(HTTPException) as exc:            # grace 0: right away
        get_current_user(_creds(out["access_token"]), db, _req("/api/assets/"))
    assert exc.value.status_code == 403
    states = {s["user_id"]: s for s in r.users_state(admin, db)}
    assert states[plain.id]["required"] and states[plain.id]["enrolment_due"]


def test_admin_reset(db):
    admin = _user(db, "mfa_admin3", UserRole.ADMIN)
    user = _user(db, "mfa_lost_phone", UserRole.MANAGER)
    _, _, token = _enrol(db, user)
    with pytest.raises(HTTPException):
        r.reset_user_mfa(admin.id, _req(), admin, db)        # not for one's own account
    r.reset_user_mfa(user.id, _req(), admin, db)
    row = mfa.get_row(db, user.id)
    assert not row.enabled and row.secret is None and row.recovery_codes == []
    with pytest.raises(HTTPException):                       # their sessions ended
        get_current_user(_creds(token), db, _req("/auth/me"))
    # their role requires it: the next sign-in goes straight to setup
    out = login(UserLogin(username=user.username, password=PW), _req("/auth/login"), db)
    with pytest.raises(HTTPException) as exc:
        get_current_user(_creds(out["access_token"]), db, _req("/api/assets/"))
    assert exc.value.headers["X-MFA-Enrollment-Required"] == "1"


def test_row_is_never_deleted_by_disable_so_old_tokens_stay_dead(db):
    user = _user(db)
    t0 = _session_token(db, user)                   # mfv 0
    secret, _, _ = _enrol(db, user)
    r.disable(r.MfaPasswordCode(password=PW, code=_next_code(secret)), _req(), user, db)
    assert db.query(UserMfa).filter(UserMfa.user_id == user.id).count() == 1
    with pytest.raises(HTTPException):
        get_current_user(_creds(t0), db, _req("/auth/me"))


def test_console_password_reset_also_clears_two_step(db, monkeypatch):
    """The VM console's "reset the web administrator's password" is the way back in for an
    administrator who lost both the phone and the recovery codes."""
    import io
    import sys

    from appliance.ngcorion_appliance import system as appliance_system

    admin = _user(db, "mfa_console_admin", UserRole.ADMIN)
    _, _, token = _enrol(db, admin)
    script = appliance_system._RESET_PASSWORD_PY.replace('User.username == "admin"',
                                                        'User.username == "mfa_console_admin"')
    monkeypatch.setattr(sys, "stdin", io.StringIO("Console-Reset-Pass-9!\n"))
    exec(compile(script, "<console>", "exec"), {})
    db.expire_all()
    row = mfa.get_row(db, admin.id)
    assert not row.enabled and row.secret is None and row.version == 2
    with pytest.raises(HTTPException):
        get_current_user(_creds(token), db, _req("/auth/me"))
    out = login(UserLogin(username=admin.username, password="Console-Reset-Pass-9!"), _req("/auth/login"), db)
    assert out["access_token"] and out["must_change_password"]


def test_the_ui_is_told_when_setup_is_due(db):
    from app.modules.auth.router import read_current_user
    admin = _user(db, "mfa_admin4", UserRole.ADMIN)
    out = login(UserLogin(username=admin.username, password=PW), _req("/auth/login"), db)
    assert out["mfa_enrolment_due"] is True
    assert read_current_user(admin, db)["mfa_enrolment_due"] is True
    _, _, _ = _enrol(db, admin)
    assert read_current_user(admin, db)["mfa_enrolment_due"] is False
