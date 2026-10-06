"""
The license client trusts only signed answers from the license server.

This is the regression suite for the bypass found during development: a local
stand-in "license server" that answered {"valid": true} to everything was
enough to unlock the product, because nothing checked who answered. Now every
answer must carry a token signed with a key built into NGCorion, about this
license and this machine, echoing the nonce of the request.

No network and no database: the client's HTTP layer is replaced by fake servers.
"""
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://test:test@localhost/test_licensing_unused")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-license-tests-only-not-real")

import pytest
import requests

from app.core import license_keys, license_state as st, machine_fingerprint as mf
from app.core.license_client import LicenseAnswerUntrusted, LicenseClient, LicenseRejected
from tests.license_signing_helpers import (  # noqa: F401  (fixture)
    LICENSE_KEY,
    OTHER_KEY,
    TEST_KEY,
    make_token,
    trusted_test_key,
)

ORG = "org-token-123"


def response(payload, status=200):
    r = requests.Response()
    r.status_code = status
    r._content = json.dumps(payload).encode()
    r.headers["Content-Type"] = "application/json"
    if status >= 400:
        r.url = "https://license.example/api"
    return r


class SigningServer:
    """Answers like the real license server: signs, echoes nonce and fingerprint."""

    def __init__(self, bound_fp=None, key=TEST_KEY, **claim_overrides):
        self.bound_fp = bound_fp
        self.key = key
        self.overrides = claim_overrides
        self.calls = []

    def __call__(self, method, path, idempotent=False, **kwargs):
        body = kwargs.get("json") or {}
        self.calls.append((path, body))
        typ = path.rsplit("/", 1)[-1]
        fp = body.get("vm_fingerprint")
        if typ == "activate":
            if self.bound_fp and self.bound_fp != fp:
                r = response({"detail": "this license already activate in another VM"}, 400)
                r.raise_for_status()
            self.bound_fp = fp
        extra = {"op": body.get("operation_type"), "count": body.get("count")} if typ == "consume" else {}
        claims = dict(typ=typ, lic=body["license_key"], fp=fp, nonce=body.get("nonce"), **extra)
        claims.update(self.overrides)
        token = make_token(key=self.key, **claims)
        payload = {"valid": True, "message": "ok", "organization_token": ORG, "signed_token": token,
                   # Plain fields a fake server could inflate: the client must ignore them.
                   "limits": {"max_audits": None, "max_hardens": None}}
        if typ == "heartbeat":
            payload = {"success": True, "message": "ok", "should_downgrade": False, "signed_token": token}
        return response(payload)


def stub_server(method, path, idempotent=False, **kwargs):
    """The development stand-in that used to unlock everything: no signature at all."""
    return response({"valid": True, "plan_type": "unlimited", "message": "ok", "organization_token": ORG,
                     "limits": {"max_audits": None, "max_hardens": None},
                     "usage": {"used_audits": 0, "used_hardens": 0}})


@pytest.fixture
def client(tmp_path, monkeypatch, trusted_test_key):
    monkeypatch.setattr(mf, "HW_UUID_FILE", tmp_path / "none-hw")
    monkeypatch.setattr(mf, "DMI_UUID_FILE", tmp_path / "none-dmi")
    host = tmp_path / "machine-id"
    host.write_text("0123456789abcdef0123456789abcdef\n")
    monkeypatch.setattr(mf, "HOST_MACHINE_ID_FILE", host)
    c = LicenseClient("https://license.example", str(tmp_path / "lic"))
    st._license_state.__init__()
    st._signed_token = None
    st._max_seen = None
    return c


def activate(client, server):
    client._request = server
    return client.activate(LICENSE_KEY)


# ==================== the bypass is closed ====================

def test_an_unsigned_answer_never_activates(client):
    client._request = stub_server
    with pytest.raises(LicenseAnswerUntrusted, match="not signed"):
        client.activate(LICENSE_KEY)
    assert client.get_license_data() is None


def test_an_unsigned_validation_locks_the_product(client):
    activate(client, SigningServer())
    st.set_license_state(client.validate())
    assert st.get_license_state().valid is True

    client._request = stub_server                      # someone swaps the license server
    with pytest.raises(LicenseRejected):
        st.refresh_license_state(client)
    state = st.get_license_state()
    assert state.valid is False
    assert "Untrusted license answer" in state.message


def test_an_answer_signed_with_another_key_is_refused(client):
    with pytest.raises(LicenseAnswerUntrusted, match="unknown key|not valid"):
        activate(client, SigningServer(key=OTHER_KEY))


def test_a_replayed_answer_is_refused(client):
    activate(client, SigningServer())
    client._request = SigningServer(nonce="recorded-earlier")
    with pytest.raises(LicenseAnswerUntrusted, match="replayed"):
        client.validate()


def test_an_answer_for_another_machine_is_refused(client):
    activate(client, SigningServer())
    client._request = SigningServer(fp="0" * 64)
    with pytest.raises(LicenseAnswerUntrusted, match="different machine"):
        client.validate()


def test_without_a_built_in_key_nothing_is_trusted(client, monkeypatch):
    monkeypatch.setattr(license_keys, "TRUSTED_LICENSE_KEYS", {})
    with pytest.raises(LicenseAnswerUntrusted, match="no license signing key built in"):
        activate(client, SigningServer())


# ==================== only signed values count ====================

def test_state_comes_from_the_token_not_the_plain_fields(client):
    activate(client, SigningServer())
    state = client.validate()
    assert state["limits"] == {"max_audits": 100, "max_hardens": 100}   # signed, not the inflated plain field
    assert state["valid"] is True and state["signed_token"]


def test_a_signed_no_is_a_no(client):
    activate(client, SigningServer())
    client._request = SigningServer(valid=False, msg="license has expierd", limits=None, usage=None)
    st.set_license_state(client.validate())
    assert st.get_license_state().valid is False


def test_consume_must_confirm_the_same_operation(client):
    activate(client, SigningServer())
    client._request = SigningServer()
    state = client.consume("audit", 1)
    assert state["usage"]["used_audits"] == 3

    client._request = SigningServer(op="harden")
    with pytest.raises(LicenseAnswerUntrusted, match="does not confirm"):
        client.consume("audit", 1)


def test_heartbeat_reports_downgrade_from_the_signed_answer(client):
    activate(client, SigningServer())
    client._request = SigningServer(down=True)
    result = client.heartbeat()
    assert result["should_downgrade"] is True
    assert result["state"]["signed_token"]


# ==================== machine binding ====================

def test_the_fingerprint_is_computed_here_not_asked_from_the_server(client):
    server = SigningServer()
    activate(client, server)
    paths = [p for p, _ in server.calls]
    assert "/api/fingerprint" not in paths
    assert server.calls[0][1]["vm_fingerprint"] == client.machine_fingerprint


def test_a_legacy_binding_is_moved_to_this_machine(client):
    """Releases before signing stored the license SERVER's fingerprint; the next validation re-activates."""
    activate(client, SigningServer())
    data = client.get_license_data()
    data["vm_fingerprint"] = "legacy-server-fingerprint"
    client.storage.save_license(data)

    server = SigningServer()
    client._request = server
    client.validate()
    assert [p for p, _ in server.calls] == ["/api/licenses/activate", "/api/licenses/validate"]
    assert client.get_license_data()["vm_fingerprint"] == client.machine_fingerprint


def test_a_license_bound_to_another_machine_is_rejected(client):
    activate(client, SigningServer())
    data = client.get_license_data()
    data["vm_fingerprint"] = "legacy-server-fingerprint"
    client.storage.save_license(data)

    client._request = SigningServer(bound_fp="another-real-machine")
    with pytest.raises(LicenseRejected, match="another VM"):
        client.validate()


def test_fingerprint_is_stable_and_follows_the_machine(tmp_path, monkeypatch):
    hw = tmp_path / "uuid"
    host = tmp_path / "machine-id"
    hw.write_text("4C4C4544-0042-3510-8051-B4C04F4E4432\n")
    host.write_text("aaaa\n")
    monkeypatch.setattr(mf, "HW_UUID_FILE", hw)
    monkeypatch.setattr(mf, "DMI_UUID_FILE", tmp_path / "none")
    monkeypatch.setattr(mf, "HOST_MACHINE_ID_FILE", host)

    first = mf.compute_fingerprint(tmp_path)
    assert first == mf.compute_fingerprint(tmp_path) and len(first) == 64
    host.write_text("bbbb\n")
    assert mf.compute_fingerprint(tmp_path) != first


def test_placeholder_uuid_and_missing_sources_fall_back_to_an_install_id(tmp_path, monkeypatch):
    hw = tmp_path / "uuid"
    hw.write_text("00000000-0000-0000-0000-000000000000")
    for name, path in (("HW_UUID_FILE", hw), ("DMI_UUID_FILE", tmp_path / "x"),
                       ("HOST_MACHINE_ID_FILE", tmp_path / "y"), ("LOCAL_MACHINE_ID_FILE", tmp_path / "z")):
        monkeypatch.setattr(mf, name, path)

    sources = mf.machine_sources(tmp_path)
    assert [n for n, _ in sources] == ["install"]
    assert mf.compute_fingerprint(tmp_path) == mf.compute_fingerprint(tmp_path)


# ==================== transport ====================

@pytest.mark.parametrize("url", ["http://10.0.0.20:8001", "http://license.example", "ftp://x"])
def test_plain_http_to_another_host_is_refused(tmp_path, url):
    with pytest.raises(RuntimeError, match="https"):
        LicenseClient(url, str(tmp_path))


@pytest.mark.parametrize("url", ["https://10.0.0.20", "http://127.0.0.1:8001", "http://localhost:8001"])
def test_https_and_loopback_are_accepted(tmp_path, url):
    assert LicenseClient(url, str(tmp_path)).server_url == url


# ==================== the consume dependency ====================

def test_unverified_consume_is_403_and_does_not_count(client):
    from types import SimpleNamespace

    from fastapi import HTTPException

    from app.core.dependencies import consume_quota_on_success

    activate(client, SigningServer())
    st.set_license_state(client.validate())
    before = st.get_license_state().usage

    client._request = stub_server
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(license_client=client)))
    with pytest.raises(HTTPException) as exc:
        consume_quota_on_success("audit")(request)
    assert exc.value.status_code == 403
    assert st.get_license_state().usage == before


# ==================== the license server's address ====================

def test_the_license_server_address_is_built_in(tmp_path):
    assert license_keys.LICENSE_SERVER_URL == "https://lic.ngcorion.com"
    assert LicenseClient(license_keys.LICENSE_SERVER_URL, str(tmp_path)).server_url == "https://lic.ngcorion.com"


def test_old_license_server_settings_are_ignored_and_named(monkeypatch):
    from app.core import config

    monkeypatch.setattr(config.settings, "LICENSE_SERVER_URL", "https://10.0.0.5")
    monkeypatch.setattr(config.settings, "LICENSE_SERVER_CA_BUNDLE", "")
    assert config.ignored_license_settings() == ["LICENSE_SERVER_URL"]
