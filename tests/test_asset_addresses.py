"""
Addresses of a host besides its inventory IP address.

Asked from the server: a FortiGate may be managed on one address and send syslog, or answer SNMP, on
another. SNMP now talks to the host's SNMP address when set (AssetSnmpCredential.poll_address); an asset
has other addresses (app/models/asset_address.py) that syslog is matched on too, and an unknown sender can
be assigned to the asset it is.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserRole
from app.models.asset_address import AssetAddress
from app.models.noc import AssetSnmpCredential
from app.models.syslog import SyslogSource
from app.modules.assets import addresses
from app.modules.noc import service as noc_service
from app.modules.noc.schemas import SnmpCredentialSet
from app.modules.syslog.intake import Intake

REQ = SimpleNamespace(client=SimpleNamespace(host="10.9.9.9"), headers={})


@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        connection.close()


_seq = [0]


def _n():
    _seq[0] += 1
    return _seq[0]


@pytest.fixture
def admin(db):
    u = User(username=f"addr_{_n()}", email=f"addr{_seq[0]}@corp.example", hashed_password="x",
             role=UserRole.ADMIN, is_active=True)
    db.add(u)
    db.flush()
    return u


def _asset(db, ip):
    t = AssetType(type_name=f"Addr type {_n()}", category="network")
    db.add(t)
    db.flush()
    a = Asset(asset_name=f"fgt-{_seq[0]}", asset_type_id=t.id, ip_address=ip)
    db.add(a)
    db.flush()
    return a


def test_adding_an_address(db, admin):
    fw = _asset(db, "10.88.0.1")
    other = _asset(db, "10.88.0.2")
    row = addresses.add(db, fw, " ::ffff:10.88.1.1 ", "logging interface", admin.id)
    assert (row.address, row.note) == ("10.88.1.1", "logging interface")
    for bad, reason in (("not-an-ip", "IPv4 or IPv6"), ("10.88.0.1", "own IP address"),
                        ("10.88.0.2", f"IP address of {other.asset_name}"),
                        ("10.88.1.1", f"already an address of {fw.asset_name}")):
        with pytest.raises(addresses.AddressError, match=reason):
            addresses.add(db, fw if bad != "10.88.1.1" else other, bad, None, admin.id)


def test_syslog_from_another_address_is_the_assets(db, admin):
    fw = _asset(db, "10.88.2.1")
    addresses.add(db, fw, "10.88.2.9", None, admin.id)
    intake = Intake()
    intake.load_assets(db)
    assert intake.known("10.88.2.1") == fw.id and intake.known("10.88.2.9") == fw.id


def test_assigning_an_unknown_sender(db, admin):
    from app.modules.syslog.router import AssignSource, assign_source
    fw = _asset(db, "10.88.3.1")
    db.add(SyslogSource(source_ip="10.88.3.7", asset_id=None, dropped=12))
    db.flush()
    out = assign_source("10.88.3.7", AssignSource(asset_id=fw.id), REQ, admin, db)
    assert out["address"] == "10.88.3.7"
    assert db.get(SyslogSource, "10.88.3.7").asset_id == fw.id
    assert db.query(AssetAddress).filter(AssetAddress.asset_id == fw.id).count() == 1
    with pytest.raises(HTTPException) as e:                      # once is enough
        assign_source("10.88.3.7", AssignSource(asset_id=fw.id), REQ, admin, db)
    assert e.value.status_code == 400


def test_snmp_talks_to_the_snmp_address_when_set(db, admin, monkeypatch):
    fw = _asset(db, "10.88.4.1")
    credential = noc_service.NocService.set_credential(db, fw.id, {"version": "v2c", "community": "public"}, admin.id)
    assert credential.target == "10.88.4.1"                       # none set: the asset's IP
    credential = noc_service.NocService.set_credential(
        db, fw.id, {"version": "v2c", "poll_address": "fgt-mgmt.corp.local"}, admin.id)
    assert credential.target == "fgt-mgmt.corp.local"

    seen = []

    async def fake_poll(address, cred):
        seen.append(address)
        raise RuntimeError("stop here")
    monkeypatch.setattr(noc_service, "poll_asset", fake_poll)
    with pytest.raises(RuntimeError):
        asyncio.run(noc_service.NocService.poll_one(db, fw.id))
    assert seen == ["fgt-mgmt.corp.local"]

    noc_service.NocService.set_credential(db, fw.id, {"version": "v2c", "poll_address": ""}, admin.id)
    assert db.query(AssetSnmpCredential).filter(AssetSnmpCredential.asset_id == fw.id).one().target == "10.88.4.1"


def test_snmp_address_must_be_an_address():
    assert SnmpCredentialSet(poll_address=" 10.1.1.1 ").poll_address == "10.1.1.1"
    assert SnmpCredentialSet(poll_address="fw-mgmt.example.org").poll_address == "fw-mgmt.example.org"
    assert SnmpCredentialSet(poll_address="").poll_address == ""
    with pytest.raises(ValidationError):
        SnmpCredentialSet(poll_address="bad host; rm -rf")


def test_an_unreadable_snmp_credential_is_logged_once(db, admin, monkeypatch, caplog):
    """A credential that no longer decrypts (SECRET_KEY changed) is one warning per host, not a
    traceback on every poll; another failure is still logged in full."""
    import logging
    fw = _asset(db, "10.88.5.1")
    noc_service.NocService.set_credential(db, fw.id, {"version": "v2c", "community": "public"}, admin.id)
    monkeypatch.setattr(db, "query", _only_assets(db, fw.id))

    async def unreadable(address, cred):
        raise ValueError("Could not decrypt stored secret - SECRET_KEY may have changed")
    monkeypatch.setattr(noc_service, "poll_asset", unreadable)
    noc_service._UNREADABLE.discard(fw.id)
    with caplog.at_level(logging.WARNING, logger=noc_service.logger.name):
        asyncio.run(noc_service.NocService.poll_all(db))
        asyncio.run(noc_service.NocService.poll_all(db))
    lines = [r for r in caplog.records if f"Asset {fw.id} not polled" in r.getMessage()]
    assert len(lines) == 1 and lines[0].exc_info is None

    async def broken(address, cred):
        raise ValueError("something else")
    monkeypatch.setattr(noc_service, "poll_asset", broken)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=noc_service.logger.name):
        asyncio.run(noc_service.NocService.poll_all(db))
    assert any(r.exc_info for r in caplog.records)


def _only_assets(db, asset_id):
    """db.query limited to this test's credential (the poll covers every credential in the database)."""
    real = db.query

    def query(*entities, **kw):
        q = real(*entities, **kw)
        if entities and entities[0] is AssetSnmpCredential:
            q = q.filter(AssetSnmpCredential.asset_id == asset_id)
        return q
    return query
