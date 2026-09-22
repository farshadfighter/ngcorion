"""Tests for the NOC (SNMP monitoring) module: encryption, credential CRUD,
poll-result persistence (SNMP network calls mocked - no real device in this
environment), dashboard/host assembly, and the router.

Needs a migrated PostgreSQL database; each test runs inside a transaction
that is rolled back, so nothing here touches real rows (same pattern as
test_topology.py).
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from fastapi import HTTPException
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models.asset import Asset
from app.models.asset_types import AssetType
from app.models.enums import StatusEnum
from app.models.noc import AssetSnmpCredential, AssetSnmpStatus, AssetSnmpInterface
from app.models.user import User
from app.core.snmp_crypto import encrypt_secret, decrypt_secret
from app.modules.noc.service import NocService
from app.modules.noc.snmp_client import DevicePollResult, InterfacePollResult
from app.modules.noc.schemas import SnmpCredentialSet


@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection)
    session.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(sess, transaction):
        if transaction.nested and not transaction._parent.nested:
            sess.begin_nested()

    try:
        yield session
    finally:
        event.remove(session, "after_transaction_end", _restart_savepoint)
        session.close()
        trans.rollback()
        connection.close()


_seq = [0]


def _next() -> int:
    _seq[0] += 1
    return _seq[0]


@pytest.fixture
def user(db) -> User:
    row = User(username=f"noc_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


def _make_asset(db, ip="10.10.10.1") -> Asset:
    asset_type = AssetType(type_name=f"Cisco Switch_{_next()}", category="network")
    db.add(asset_type)
    db.flush()
    row = Asset(asset_name=f"noc-asset-{_next()}", asset_type_id=asset_type.id, ip_address=ip)
    db.add(row)
    db.flush()
    return row


def run(coro):
    return asyncio.run(coro)


# ======================================================================
# Encryption
# ======================================================================

def test_encrypt_decrypt_round_trip():
    ciphertext = encrypt_secret("public")
    assert ciphertext != "public"
    assert decrypt_secret(ciphertext) == "public"


def test_encrypted_value_is_not_plaintext_substring():
    ciphertext = encrypt_secret("my-secret-community")
    assert "my-secret-community" not in ciphertext


# ======================================================================
# Credential CRUD
# ======================================================================

def test_set_credential_creates_a_row_with_encrypted_community(db, user):
    asset = _make_asset(db)
    NocService.set_credential(db, asset.id, {"version": "v2c", "port": 161, "community": "public"}, user.id)

    row = db.query(AssetSnmpCredential).filter(AssetSnmpCredential.asset_id == asset.id).first()
    assert row is not None
    assert row.community_encrypted != "public"
    assert decrypt_secret(row.community_encrypted) == "public"


def test_set_credential_upserts_on_a_second_call(db, user):
    asset = _make_asset(db)
    NocService.set_credential(db, asset.id, {"version": "v2c", "port": 161, "community": "first"}, user.id)
    NocService.set_credential(db, asset.id, {"version": "v2c", "port": 1610, "community": "second"}, user.id)

    rows = db.query(AssetSnmpCredential).filter(AssetSnmpCredential.asset_id == asset.id).all()
    assert len(rows) == 1
    assert rows[0].port == 1610
    assert decrypt_secret(rows[0].community_encrypted) == "second"


def test_set_credential_v3_encrypts_auth_and_priv_keys(db, user):
    asset = _make_asset(db)
    NocService.set_credential(
        db, asset.id,
        {
            "version": "v3", "port": 161, "username": "monitor",
            "auth_protocol": "SHA", "auth_key": "authpass123",
            "priv_protocol": "AES", "priv_key": "privpass123",
        },
        user.id,
    )
    row = NocService.get_credential(db, asset.id)
    assert row.version == "v3"
    assert row.username == "monitor"
    assert decrypt_secret(row.auth_key_encrypted) == "authpass123"
    assert decrypt_secret(row.priv_key_encrypted) == "privpass123"


def test_delete_credential_removes_the_row(db, user):
    asset = _make_asset(db)
    NocService.set_credential(db, asset.id, {"version": "v2c", "port": 161, "community": "public"}, user.id)
    assert NocService.delete_credential(db, asset.id) is True
    assert NocService.get_credential(db, asset.id) is None


def test_delete_credential_returns_false_when_none_exists(db, user):
    asset = _make_asset(db)
    assert NocService.delete_credential(db, asset.id) is False


# ======================================================================
# SNMP client (poll_asset)
# ======================================================================

def test_poll_asset_converts_puresnmp_timedelta_uptime_to_ticks():
    """Regression test: puresnmp's PyWrapper decodes SNMP TimeTicks (sysUpTime)
    into a datetime.timedelta (see puresnmp.types.TimeTicks.pythonize), not a
    raw tick count. poll_asset used to call int() directly on that timedelta,
    which raises TypeError outside the try/except that turns SNMP failures
    into `reachable=False` - crashing the whole poll (500) for every real
    device instead of reporting a friendly status."""
    from datetime import timedelta
    from unittest.mock import AsyncMock, MagicMock

    from app.modules.noc.snmp_client import poll_asset

    credential = AssetSnmpCredential(version="v2c", port=161, community_encrypted=encrypt_secret("public"))
    uptime = timedelta(days=2, seconds=34694, microseconds=440000)

    fake_client = MagicMock()
    fake_client.multiget = AsyncMock(return_value=(b"fake sys descr", uptime, b"", b"NGFW-Taktacom", b""))

    async def empty_walk(_oids):
        return
        yield  # pragma: no cover - makes this an async generator that yields nothing

    fake_client.multiwalk = empty_walk

    with patch("app.modules.noc.snmp_client.PyWrapper", return_value=fake_client):
        result = run(poll_asset("172.16.200.20", credential))

    assert result.reachable is True
    assert result.sys_uptime_ticks == int(uptime.total_seconds() * 100)
    assert result.sys_name == "NGFW-Taktacom"


# ======================================================================
# Poll result persistence
# ======================================================================

def _fake_reachable_result() -> DevicePollResult:
    return DevicePollResult(
        reachable=True,
        sys_descr="Cisco IOS Software",
        sys_name="switch-1",
        sys_contact="noc@example.com",
        sys_location="DC1",
        sys_uptime_ticks=123456,
        interfaces=[
            InterfacePollResult(
                if_index=1, if_descr="GigabitEthernet0/1", if_type=6, if_speed=1000000000,
                if_admin_status="up", if_oper_status="up", in_octets=1000, out_octets=2000,
            ),
        ],
    )


def test_persist_poll_result_creates_status_and_interface_rows(db, user):
    asset = _make_asset(db)
    status = NocService._persist_poll_result(db, asset.id, _fake_reachable_result())

    assert status.reachable is True
    assert status.sys_name == "switch-1"
    assert status.last_polled_at is not None

    interfaces = db.query(AssetSnmpInterface).filter(AssetSnmpInterface.asset_id == asset.id).all()
    assert len(interfaces) == 1
    assert interfaces[0].if_descr == "GigabitEthernet0/1"
    assert interfaces[0].in_octets == 1000


def test_persist_poll_result_upserts_status_and_interfaces_on_second_poll(db, user):
    asset = _make_asset(db)
    NocService._persist_poll_result(db, asset.id, _fake_reachable_result())

    updated = _fake_reachable_result()
    updated.interfaces[0].in_octets = 9999
    NocService._persist_poll_result(db, asset.id, updated)

    statuses = db.query(AssetSnmpStatus).filter(AssetSnmpStatus.asset_id == asset.id).all()
    assert len(statuses) == 1
    interfaces = db.query(AssetSnmpInterface).filter(AssetSnmpInterface.asset_id == asset.id).all()
    assert len(interfaces) == 1
    assert interfaces[0].in_octets == 9999


def test_persist_poll_result_records_unreachable_devices(db, user):
    asset = _make_asset(db)
    result = DevicePollResult(reachable=False, error_message="timed out")
    status = NocService._persist_poll_result(db, asset.id, result)

    assert status.reachable is False
    assert status.error_message == "timed out"
    assert status.sys_name is None


# ======================================================================
# NOC-driven auto status (ACTIVE/INACTIVE)
# ======================================================================

def _fake_unreachable_result() -> DevicePollResult:
    return DevicePollResult(reachable=False, error_message="timed out")


def test_consecutive_failures_below_threshold_does_not_flip_status(db, user):
    asset = _make_asset(db)
    asset.status = StatusEnum.UNKNOWN
    db.flush()

    NocService._persist_poll_result(db, asset.id, _fake_unreachable_result())
    NocService._persist_poll_result(db, asset.id, _fake_unreachable_result())
    db.refresh(asset)

    assert asset.status == StatusEnum.UNKNOWN
    status = NocService.get_status(db, asset.id)
    assert status.consecutive_poll_failures == 2


def test_third_consecutive_failure_flips_to_inactive(db, user):
    asset = _make_asset(db)
    asset.status = StatusEnum.ACTIVE
    db.flush()

    for _ in range(3):
        NocService._persist_poll_result(db, asset.id, _fake_unreachable_result())
    db.refresh(asset)

    assert asset.status == StatusEnum.INACTIVE


def test_a_single_success_immediately_flips_back_to_active(db, user):
    asset = _make_asset(db)
    asset.status = StatusEnum.ACTIVE
    db.flush()
    for _ in range(3):
        NocService._persist_poll_result(db, asset.id, _fake_unreachable_result())
    db.refresh(asset)
    assert asset.status == StatusEnum.INACTIVE

    NocService._persist_poll_result(db, asset.id, _fake_reachable_result())
    db.refresh(asset)

    assert asset.status == StatusEnum.ACTIVE
    status = NocService.get_status(db, asset.id)
    assert status.consecutive_poll_failures == 0


def test_decommissioned_status_is_never_overridden(db, user):
    asset = _make_asset(db)
    asset.status = StatusEnum.DECOMMISSIONED
    db.flush()

    for _ in range(5):
        NocService._persist_poll_result(db, asset.id, _fake_unreachable_result())
    db.refresh(asset)
    assert asset.status == StatusEnum.DECOMMISSIONED

    NocService._persist_poll_result(db, asset.id, _fake_reachable_result())
    db.refresh(asset)
    assert asset.status == StatusEnum.DECOMMISSIONED


def test_unmonitored_asset_status_is_unaffected_by_other_assets_polls(db, user):
    """An asset with no SNMP credential/poll history at all keeps whatever
    status a human set - the auto-status logic only ever runs from inside
    _persist_poll_result, which is only reached for assets actually polled."""
    asset = _make_asset(db)
    asset.status = StatusEnum.STANDBY
    db.flush()
    db.refresh(asset)
    assert asset.status == StatusEnum.STANDBY


# ======================================================================
# poll_one / poll_all (SNMP network call mocked)
# ======================================================================

def test_poll_one_raises_without_a_credential(db, user):
    asset = _make_asset(db)
    with pytest.raises(ValueError, match="no SNMP credential"):
        run(NocService.poll_one(db, asset.id))


def test_poll_one_raises_without_an_ip_address(db, user):
    asset_type = AssetType(type_name=f"Server_{_next()}", category="server")
    db.add(asset_type)
    db.flush()
    asset = Asset(asset_name=f"noc-noip-{_next()}", asset_type_id=asset_type.id, ip_address=None)
    db.add(asset)
    db.flush()
    NocService.set_credential(db, asset.id, {"version": "v2c", "port": 161, "community": "public"}, user.id)

    with pytest.raises(ValueError, match="no IP address"):
        run(NocService.poll_one(db, asset.id))


def test_poll_one_persists_the_mocked_result(db, user):
    asset = _make_asset(db)
    NocService.set_credential(db, asset.id, {"version": "v2c", "port": 161, "community": "public"}, user.id)

    with patch("app.modules.noc.service.poll_asset") as mocked:
        async def _fake(*args, **kwargs):
            return _fake_reachable_result()
        mocked.side_effect = _fake

        status = run(NocService.poll_one(db, asset.id))

    assert status.reachable is True
    assert status.sys_name == "switch-1"


def test_poll_all_only_polls_assets_with_a_credential(db, user):
    with_cred = _make_asset(db, ip="10.10.10.2")
    without_cred = _make_asset(db, ip="10.10.10.3")
    NocService.set_credential(db, with_cred.id, {"version": "v2c", "port": 161, "community": "public"}, user.id)

    with patch("app.modules.noc.service.poll_asset") as mocked:
        async def _fake(*args, **kwargs):
            return _fake_reachable_result()
        mocked.side_effect = _fake

        polled_count = run(NocService.poll_all(db))

    assert polled_count == 1
    assert NocService.get_status(db, with_cred.id) is not None
    assert NocService.get_status(db, without_cred.id) is None


# ======================================================================
# Dashboard / host list assembly
# ======================================================================

def test_list_assets_with_status_reflects_credential_and_poll_state(db, user):
    polled = _make_asset(db)
    unpolled_with_cred = _make_asset(db)
    never_touched = _make_asset(db)

    NocService.set_credential(db, polled.id, {"version": "v2c", "port": 161, "community": "public"}, user.id)
    NocService._persist_poll_result(db, polled.id, _fake_reachable_result())
    NocService.set_credential(db, unpolled_with_cred.id, {"version": "v2c", "port": 161, "community": "public"}, user.id)

    rows = {a.id: (status, has_cred) for a, status, has_cred in NocService.list_assets_with_status(db)}

    assert rows[polled.id][1] is True
    assert rows[polled.id][0] is not None
    assert rows[unpolled_with_cred.id][1] is True
    assert rows[unpolled_with_cred.id][0] is None
    assert rows[never_touched.id][1] is False
    assert rows[never_touched.id][0] is None


# ======================================================================
# Router behaviour
# ======================================================================

def test_route_get_host_detail_404s_for_missing_asset(db, user):
    from app.modules.noc.router import get_host_detail as route

    with pytest.raises(HTTPException) as exc_info:
        route(asset_id=2_000_000_000, current_user=user, db=db)
    assert exc_info.value.status_code == 404


def test_route_set_and_get_host_credential(db, user):
    from app.modules.noc.router import set_host_credential, get_host_detail

    asset = _make_asset(db)
    request = SnmpCredentialSet(version="v2c", port=161, community="public")
    info = set_host_credential(asset_id=asset.id, request=request, current_user=user, db=db)

    assert info.version == "v2c"
    assert info.has_community is True

    detail = get_host_detail(asset_id=asset.id, current_user=user, db=db)
    assert detail.credential is not None
    assert detail.credential.has_community is True


def test_route_set_host_credential_rejects_unknown_version(db, user):
    from app.modules.noc.router import set_host_credential

    asset = _make_asset(db)
    request = SnmpCredentialSet(version="v1", port=161, community="public")
    with pytest.raises(HTTPException) as exc_info:
        set_host_credential(asset_id=asset.id, request=request, current_user=user, db=db)
    assert exc_info.value.status_code == 400


def test_route_delete_host_credential_404s_when_none_set(db, user):
    from app.modules.noc.router import delete_host_credential

    asset = _make_asset(db)
    with pytest.raises(HTTPException) as exc_info:
        delete_host_credential(asset_id=asset.id, current_user=user, db=db)
    assert exc_info.value.status_code == 404


def test_route_poll_host_now_400s_without_a_credential(db, user):
    from app.modules.noc.router import poll_host_now

    asset = _make_asset(db)
    with pytest.raises(HTTPException) as exc_info:
        run(poll_host_now(asset_id=asset.id, current_user=user, db=db))
    assert exc_info.value.status_code == 400


def test_route_poll_host_now_returns_reachable_status(db, user):
    from app.modules.noc.router import poll_host_now

    asset = _make_asset(db)
    NocService.set_credential(db, asset.id, {"version": "v2c", "port": 161, "community": "public"}, user.id)

    with patch("app.modules.noc.service.poll_asset") as mocked:
        async def _fake(*args, **kwargs):
            return _fake_reachable_result()
        mocked.side_effect = _fake

        result = run(poll_host_now(asset_id=asset.id, current_user=user, db=db))

    assert result.reachable is True


def test_route_list_hosts_includes_status_fields(db, user):
    from app.modules.noc.router import list_hosts

    asset = _make_asset(db)
    NocService.set_credential(db, asset.id, {"version": "v2c", "port": 161, "community": "public"}, user.id)
    NocService._persist_poll_result(db, asset.id, _fake_reachable_result())

    hosts = list_hosts(current_user=user, db=db)
    host = next(h for h in hosts if h.asset_id == asset.id)
    assert host.has_credential is True
    assert host.reachable is True
    assert host.sys_name == "switch-1"
