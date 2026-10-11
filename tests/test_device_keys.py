"""
Pinned device keys (app/modules/device_keys.py): administrators list the SSH host keys and TLS
certificates NGCorion pinned, and remove one after a legitimate reinstall, with an audit record.
"""
from types import SimpleNamespace

import paramiko
import pytest
from fastapi import HTTPException

from app.core import ssh_host_keys as hk
from app.core import tls_pins
from app.core.database import SessionLocal
from app.models.security_audit_log import AuditLog
from app.modules import device_keys

ADMIN = SimpleNamespace(id=None, username="keys-test-admin")
REQUEST = SimpleNamespace(client=SimpleNamespace(host="192.0.2.10"))


@pytest.fixture
def stores(tmp_path, monkeypatch):
    monkeypatch.setattr(hk.settings, "SSH_KNOWN_HOSTS_FILE", str(tmp_path / "known_hosts"))
    monkeypatch.setenv("SSL_PINS_FILE", str(tmp_path / "tls_pins.json"))
    hk.reset_store_cache()
    yield
    hk.reset_store_cache()


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()


class _NoAssets:
    """A session stand-in whose asset query finds nothing."""
    def query(self, _model):
        return self

    def filter(self, *_args):
        return []


def test_lists_ssh_and_tls_pins(stores):
    key = paramiko.ECDSAKey.generate()
    hk.get_store().add("10.1.1.1", 2222, key)
    tls_pins.check("10.1.1.2", 4444, b"certificate-der")
    pins = device_keys.list_device_keys(db=_NoAssets(), _admin=ADMIN)
    assert [(p.kind, p.host, p.port) for p in pins] == [("ssh", "10.1.1.1", 2222), ("tls", "10.1.1.2", 4444)]
    assert pins[0].key_type == key.get_name()
    assert pins[0].fingerprint == hk.key_fingerprint(key)
    assert pins[1].fingerprint == tls_pins.fingerprint(b"certificate-der")


def test_pins_are_matched_to_assets(stores):
    hk.get_store().add("10.1.1.1", 22, paramiko.ECDSAKey.generate())

    class _Assets(_NoAssets):
        def filter(self, *_args):
            return [SimpleNamespace(id=7, asset_name="core-switch", ip_address="10.1.1.1")]

    [pin] = device_keys.list_device_keys(db=_Assets(), _admin=ADMIN)
    assert (pin.asset_id, pin.asset_name) == (7, "core-switch")


def test_forgetting_a_key_is_audited_and_the_device_is_pinned_afresh(stores, db):
    old, new = paramiko.ECDSAKey.generate(), paramiko.ECDSAKey.generate()
    hk.get_store().add("10.1.1.3", 22, old)
    with pytest.raises(hk.SSHHostKeyMismatchError):
        hk.evaluate_host_key("10.1.1.3", 22, new)            # the reinstalled device is refused

    device_keys.forget_device_key("ssh", REQUEST, host="10.1.1.3", port=22, db=db, admin=ADMIN)

    hk.evaluate_host_key("10.1.1.3", 22, new)                 # pinned on the next connection
    assert hk.get_store().verify("10.1.1.3", 22, new) == hk.VerificationResult.MATCH
    record = (db.query(AuditLog).filter(AuditLog.action == "device_key.forget",
                                        AuditLog.username == ADMIN.username)
              .order_by(AuditLog.id.desc()).first())
    assert record is not None and record.ip_address == "192.0.2.10"
    assert "10.1.1.3:22" in record.detail and hk.key_fingerprint(old) in record.detail


def test_forgetting_a_tls_pin(stores, db):
    tls_pins.check("10.1.1.4", 4444, b"old-cert")
    device_keys.forget_device_key("tls", REQUEST, host="10.1.1.4", port=4444, db=db, admin=ADMIN)
    assert tls_pins.pinned("10.1.1.4", 4444) is None


def test_unknown_device_is_404(stores, db):
    with pytest.raises(HTTPException) as exc:
        device_keys.forget_device_key("ssh", REQUEST, host="10.9.9.9", port=22, db=db, admin=ADMIN)
    assert exc.value.status_code == 404


def test_only_administrators():
    routes = device_keys.router.routes
    assert len(routes) == 2
    for route in routes:
        calls = [d.call for d in route.dependant.dependencies]
        assert any(c.__name__ == "require_admin" for c in calls), route.path
