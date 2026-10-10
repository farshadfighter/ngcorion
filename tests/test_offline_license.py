"""
Offline (air-gapped) licenses in NGCorion: the request file, installing the license file the
license server's admin signs for it, and running on it without any contact.

What is protected here:
* the request carries the license key, this machine's fingerprint and the asset count;
* only a genuine file installs: signed by a trusted key, of type "offline", for this machine,
  not ended - an edited, foreign-key, other-machine, ended or online token is refused and
  nothing is stored;
* an installed file is the license: validation and the heartbeat never contact the license
  server, the 48-hour/pilot rule does not apply, the asset limit does;
* it ends at offline_until, and a clock set back is noticed even across a restart;
* the endpoints are open before a license exists and admin-only after.
"""
import base64
import json
import time

import pytest

from app.core import license_state as st
from app.core.license_client import (
    OFFLINE_LICENSE_HEADER,
    OFFLINE_REQUEST_HEADER,
    LicenseAnswerUntrusted,
    LicenseClient,
)
from app.core import machine_fingerprint as mf
from tests.license_signing_helpers import (  # noqa: F401  (fixture)
    LICENSE_KEY,
    OTHER_KEY,
    make_token,
    trusted_test_key,
)

YEAR = 365 * 86400


@pytest.fixture
def client(tmp_path, monkeypatch, trusted_test_key):
    monkeypatch.setattr(mf, "HW_UUID_FILE", tmp_path / "none-hw")
    monkeypatch.setattr(mf, "DMI_UUID_FILE", tmp_path / "none-dmi")
    host = tmp_path / "machine-id"
    host.write_text("0123456789abcdef0123456789abcdef\n")
    monkeypatch.setattr(mf, "HOST_MACHINE_ID_FILE", host)
    c = LicenseClient("https://license.example", str(tmp_path / "lic"))

    def no_network(*a, **k):
        raise AssertionError("an offline license must never contact the license server")
    c._request = no_network
    st._license_state.__init__()
    st._signed_token = None
    st._max_seen = None
    yield c
    st._license_state.__init__()
    st._signed_token = None
    st._max_seen = None


def license_file(client, **claims):
    token = make_token(**{"typ": "offline", "fp": client.machine_fingerprint, "lic": LICENSE_KEY,
                          "msg": "offline license", "offline_until": int(time.time()) + YEAR, **claims})
    return f"{OFFLINE_LICENSE_HEADER}\n{token}\n"


def test_the_request_names_the_license_this_machine_and_the_assets(client):
    text = client.offline_request(LICENSE_KEY.lower(), asset_count=42)
    header, body = text.strip().split("\n")
    assert header == OFFLINE_REQUEST_HEADER
    data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    assert (data["lic"], data["fp"], data["assets"]) == (LICENSE_KEY, client.machine_fingerprint, 42)
    assert len(data["nonce"]) >= 16 and data["created"] <= time.time()
    with pytest.raises(ValueError):
        client.offline_request("not-a-key")


def test_a_genuine_file_installs_and_runs_without_contact(client):
    state = client.install_offline_license(license_file(client))
    assert state["offline_license"] is True and state["limits"] == {"max_assets": 350, "addon_packs": 2}
    assert client.is_offline()

    # Validation and the heartbeat answer from the file (client._request would fail the test).
    st.set_license_state(client.validate())
    assert client.heartbeat(asset_count=3)["state"]["offline_license"] is True
    current = st.get_license_state()
    assert (current.valid, current.offline_license, current.max_assets) == (True, True, 350)
    # A renewal request needs no key: the installed one is used.
    assert LICENSE_KEY in base64.urlsafe_b64decode(client.offline_request().split("\n")[1] + "==").decode()


@pytest.mark.parametrize("make, reason", [
    (lambda c: license_file(c, fp="f" * 64), "different machine"),
    (lambda c: license_file(c, typ="validate"), "Expected a 'offline' answer"),
    (lambda c: f"{OFFLINE_LICENSE_HEADER}\n{make_token(key=OTHER_KEY, typ='offline', fp=c.machine_fingerprint, offline_until=int(time.time()) + YEAR)}\n", "unknown key|not valid"),
    (lambda c: license_file(c, offline_until=int(time.time()) - 60), "already ended"),
    (lambda c: license_file(c, valid=False), "does not grant"),
    (lambda c: license_file(c).replace(OFFLINE_LICENSE_HEADER, OFFLINE_REQUEST_HEADER), "request file"),
    (lambda c: "hello", "not an NGCorion offline license file"),
])
def test_anything_but_a_genuine_file_for_this_machine_is_refused(client, make, reason):
    with pytest.raises(LicenseAnswerUntrusted, match=reason):
        client.install_offline_license(make(client))
    assert client.get_license_data() is None


def test_an_edited_file_does_not_verify(client):
    text = license_file(client)
    token = text.strip().split("\n")[1]
    body, sig = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["limits"] = {"max_assets": None, "addon_packs": 0}
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    with pytest.raises(LicenseAnswerUntrusted):
        client.install_offline_license(f"{OFFLINE_LICENSE_HEADER}\n{forged}.{sig}\n")


def test_no_pilot_fallback_but_the_file_ends(client):
    # Issued 200 days ago: an online license would long be a pilot or locked; this one runs.
    issued = int(time.time()) - 200 * 86400
    client.install_offline_license(license_file(client, iat=issued, offline_until=issued + YEAR))
    st.set_license_state(client.validate())
    state = st.get_license_state()
    assert (state.valid, state.offline_pilot, state.max_assets) == (True, False, 350)

    # Past offline_until: invalid until a renewed file is installed.
    with st._state_lock:
        st._license_state.offline_until = st._utc_from_epoch(int(time.time()) - 1)
    state = st.get_license_state()
    assert state.valid is False and "ended" in state.message


def test_a_clock_set_back_before_the_file_was_issued_invalidates(client):
    client.install_offline_license(license_file(client, iat=int(time.time()) + 7 * 86400,
                                                offline_until=int(time.time()) + YEAR))
    st.set_license_state(client.validate())
    state = st.get_license_state()
    assert state.valid is False and "set back" in state.message


def test_a_clock_set_back_while_down_is_noticed_after_a_restart(client):
    class Cache:
        state = None

        def save_state(self, s):
            self.state = s

        def load_state(self):
            return self.state

    cache = Cache()
    st.attach_state_cache(cache, verifier=client.verify_cached_token)
    client.install_offline_license(license_file(client))
    st.set_license_state(client.validate())
    # The process recorded a time a day ahead of now (the clock was later set back by a day).
    cache.state["last_seen"] = "2999-01-01T00:00:00"
    st._license_state.__init__()
    st._max_seen = None
    st.restore_cached_state()
    st.set_license_state(client.validate())
    assert st.get_license_state().valid is False


def test_endpoints_are_open_before_a_license_and_admin_only_after(monkeypatch):
    from types import SimpleNamespace

    from fastapi import HTTPException

    import importlib

    # The package re-exports `router` (the APIRouter), which shadows the module of that name.
    license_router = importlib.import_module("app.modules.license.router")

    monkeypatch.setattr(license_router, "get_license_state", lambda: SimpleNamespace(valid=False))
    license_router._require_admin_while_licensed(None, None)        # open: first-run screen
    monkeypatch.setattr(license_router, "get_license_state", lambda: SimpleNamespace(valid=True))
    with pytest.raises(HTTPException) as exc:
        license_router._require_admin_while_licensed(None, None)
    assert exc.value.status_code == 401

    from app.middleware.license_middleware import LicenseMiddleware
    assert {"/api/license/offline/request", "/api/license/offline/install"} <= LicenseMiddleware.PASSTHROUGH_PATHS
