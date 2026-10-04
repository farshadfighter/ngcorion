"""
Object-level access to audit sessions across the older target modules.

A non-admin may open only their own audit sessions (assert_session_access),
so every listing, count, history and statistic must be scoped the same way
(owned_sessions / owner_scope), and every hardening request that names a
session, a finding or an action must belong to the caller. Otherwise a user
could enumerate other users' targets and scores, or run fixes against (and
flip the results of) someone else's audit.
"""
import pytest
from fastapi import HTTPException

from app.core.database import SessionLocal
from app.core.dependencies import (
    owner_scope,
    require_own_action,
    require_own_result,
    require_own_session,
)
from app.core.security import get_password_hash
from app.models import User, UserRole
from app.models.audit import AuditResult, AuditSession, CheckStatus, DeviceType
from app.modules.apache.audit.service import ApacheAuditService
from app.modules.cisco.audit.service import AuditService as CiscoAuditService
from app.modules.fortinet.audit.service import FortinetAuditService
from app.modules.linux.audit.service import LinuxAuditService
from app.modules.mongodb.audit.service import MongoDBSHAuditService
from app.modules.mssql.audit.service import MSSQLAuditService

PREFIX = "ownership_probe_"


@pytest.fixture
def db():
    s = SessionLocal()
    yield s
    s.rollback()
    ids = [u.id for u in s.query(User).filter(User.username.like(PREFIX + "%"))]
    if ids:
        sids = [x.id for x in s.query(AuditSession).filter(AuditSession.user_id.in_(ids))]
        if sids:
            s.query(AuditResult).filter(AuditResult.session_id.in_(sids)).delete(synchronize_session=False)
            s.query(AuditSession).filter(AuditSession.id.in_(sids)).delete(synchronize_session=False)
        s.query(User).filter(User.id.in_(ids)).delete(synchronize_session=False)
    s.commit()
    s.close()


def _user(db, name, role=UserRole.USER):
    u = User(username=PREFIX + name, email=f"{PREFIX}{name}@example.com",
             hashed_password=get_password_hash("Probe-Pass-123"), role=role, is_active=True)
    db.add(u)
    db.flush()
    return u


def _session(db, user, device_type):
    s = AuditSession(user_id=user.id, target_ip="192.0.2.10", device_type=device_type, status="completed",
                     job_name=f"{PREFIX}{user.username}")
    db.add(s)
    db.flush()
    return s


@pytest.fixture
def two_users(db):
    alice, bob = _user(db, "alice"), _user(db, "bob")
    admin = _user(db, "admin", UserRole.ADMIN)
    sessions = {dt: (_session(db, alice, dt), _session(db, bob, dt))
                for dt in (DeviceType.CISCO, DeviceType.FORTINET, DeviceType.LINUX, DeviceType.MSSQL,
                           DeviceType.MONGODB, DeviceType.APACHE)}
    db.commit()
    return alice, bob, admin, sessions


LISTINGS = [
    (DeviceType.CISCO, lambda db, o: CiscoAuditService.get_all_sessions(db, 100, 0, owner_id=o)),
    (DeviceType.FORTINET, lambda db, o: FortinetAuditService.get_all_sessions(
        db, DeviceType.FORTINET, 100, 0, owner_id=o)),
    (DeviceType.LINUX, lambda db, o: LinuxAuditService.get_linux_sessions(db, 100, 0, owner_id=o)),
    (DeviceType.MSSQL, lambda db, o: MSSQLAuditService.get_all_sessions(db, 100, 0, owner_id=o)),
    (DeviceType.MONGODB, lambda db, o: MongoDBSHAuditService.get_all_sessions(db, 100, 0, owner_id=o)),
    (DeviceType.APACHE, lambda db, o: ApacheAuditService.get_apache_sessions(db, 100, 0, owner_id=o)),
]


@pytest.mark.parametrize("device_type,listing", LISTINGS, ids=[d.value for d, _ in LISTINGS])
def test_a_user_lists_only_their_own_sessions(db, two_users, device_type, listing):
    alice, bob, admin, sessions = two_users
    mine, theirs = sessions[device_type]
    seen = {s.id for s in listing(db, owner_scope(alice))}
    assert mine.id in seen and theirs.id not in seen
    everything = {s.id for s in listing(db, owner_scope(admin))}
    assert {mine.id, theirs.id} <= everything


def test_counts_and_statistics_are_scoped_too(db, two_users):
    alice, bob, admin, _ = two_users
    me = owner_scope(alice)
    assert MSSQLAuditService.get_sessions_count(db, owner_id=me) < MSSQLAuditService.get_sessions_count(db)
    assert LinuxAuditService.get_audit_statistics(db, owner_id=me)["total_sessions"] \
        < LinuxAuditService.get_audit_statistics(db)["total_sessions"]
    assert ApacheAuditService.get_audit_statistics(db, owner_id=me)["total_sessions"] \
        < ApacheAuditService.get_audit_statistics(db)["total_sessions"]


def test_hardening_cannot_name_someone_elses_session_or_finding(db, two_users):
    alice, bob, admin, sessions = two_users
    mine, theirs = sessions[DeviceType.CISCO]
    finding = AuditResult(session_id=theirs.id, check_number="IOS-L1-001", status=CheckStatus.FAIL)
    db.add(finding)
    db.commit()

    assert require_own_session(db, mine.id, alice).id == mine.id
    assert require_own_session(db, None, alice) is None
    for call in (lambda: require_own_session(db, theirs.id, alice),
                 lambda: require_own_result(db, finding.id, alice),
                 lambda: require_own_result(db, 2_000_000_000, alice)):
        with pytest.raises(HTTPException) as exc:
            call()
        assert exc.value.status_code == 404          # not 403: existence is not revealed
    assert require_own_result(db, finding.id, bob).id == finding.id
    assert require_own_result(db, finding.id, admin).id == finding.id


def test_hardening_actions_belong_to_their_creator():
    from types import SimpleNamespace

    action = SimpleNamespace(id=5, user_id=1)

    class _Q:
        def filter(self, *a):
            return self

        def first(self):
            return action

    db = SimpleNamespace(query=lambda *a: _Q())
    owner = SimpleNamespace(id=1, role=SimpleNamespace(value="user"))
    other = SimpleNamespace(id=2, role=SimpleNamespace(value="user"))
    admin = SimpleNamespace(id=3, role=SimpleNamespace(value="admin"))
    assert require_own_action(db, 5, owner) is action
    assert require_own_action(db, 5, admin) is action
    with pytest.raises(HTTPException) as exc:
        require_own_action(db, 5, other)
    assert exc.value.status_code == 404


def test_dashboard_recent_sessions_are_scoped(db, two_users):
    from app.modules.audit.dashboard_router import recent_sessions

    alice, bob, admin, sessions = two_users
    names = {i["job_name"] for i in recent_sessions(limit=100, current_user=alice, db=db)["items"]}
    assert PREFIX + alice.username in names and PREFIX + bob.username not in names


def test_fortigate_action_history_can_be_limited_to_one_user(db, two_users):
    from app.models import Asset, AssetType
    from app.models.hardening import HardeningAction
    from app.modules.fortinet.hardening.service import FortiGateHardeningService

    alice, bob, admin, sessions = two_users
    mine, theirs = sessions[DeviceType.FORTINET]
    t = AssetType(type_name=PREFIX + "firewall", category="network")
    db.add(t)
    db.flush()
    a = Asset(asset_name=PREFIX + "fw", asset_type_id=t.id, ip_address="192.0.2.10")
    db.add(a)
    db.flush()
    for user, sess in ((alice, mine), (bob, theirs)):
        r = AuditResult(session_id=sess.id, check_number="FG-SYS-001", status=CheckStatus.FAIL)
        db.add(r)
        db.flush()
        db.add(HardeningAction(audit_result_id=r.id, user_id=user.id, asset_id=a.id, audit_session_id=sess.id,
                               check_number="FG-SYS-001", check_title="probe", action_type="preview", commands_json="[]",
                               status="pending"))
    db.flush()
    mine_only = FortiGateHardeningService.get_action_history(db, asset_id=a.id, user_id=alice.id, limit=100)
    everyone = FortiGateHardeningService.get_action_history(db, asset_id=a.id, limit=100)
    assert {x.user_id for x in mine_only} == {alice.id}
    assert {x.user_id for x in everyone} == {alice.id, bob.id}
    db.rollback()
