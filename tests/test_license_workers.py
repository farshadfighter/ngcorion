"""
The license across worker processes.

The server runs several worker processes (uvicorn --workers 4 on the appliance), each with its own
copy of the license state. An offline license file installed through one of them only reached
that one: a reload that landed on another worker showed the activation screen again, until that
worker's hourly heartbeat. Now each worker notices a change in the license storage
(license_state.sync_with_storage, from the license middleware) and loads it, verified again.

"Another worker" here is a second LicenseClient on the same storage directory, which writes the
files the way the other process does without touching this process's state.
"""
import asyncio
import time

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core import license_state as st
from app.core import machine_fingerprint as mf
from app.core.license_client import OFFLINE_LICENSE_HEADER, LicenseClient
from app.middleware.license_middleware import LicenseMiddleware
from tests.license_signing_helpers import (  # noqa: F401  (fixture)
    LICENSE_KEY,
    OTHER_KEY,
    make_token,
    trusted_test_key,
)

YEAR = 365 * 86400


def _reset():
    st._license_state.__init__()
    st._signed_token = None
    st._max_seen = None
    st._state_cache = st._token_verifier = st._sync_client = None
    st._license_stamp = st._state_stamp = None
    st._last_sync = float("-inf")


@pytest.fixture
def clients(tmp_path, monkeypatch, trusted_test_key):  # noqa: F811  (the fixture imported above)
    """(this worker's client, attached to the state; another worker's client, same storage)."""
    monkeypatch.setattr(mf, "HW_UUID_FILE", tmp_path / "none-hw")
    monkeypatch.setattr(mf, "DMI_UUID_FILE", tmp_path / "none-dmi")
    host = tmp_path / "machine-id"
    host.write_text("0123456789abcdef0123456789abcdef\n")
    monkeypatch.setattr(mf, "HOST_MACHINE_ID_FILE", host)
    monkeypatch.setattr(st, "SYNC_INTERVAL_SECONDS", 0.0)

    def no_network(*a, **k):
        raise AssertionError("loading another worker's change must not contact the license server")

    here = LicenseClient("https://license.example", str(tmp_path / "lic"))
    other = LicenseClient("https://license.example", str(tmp_path / "lic"))
    here._request = other._request = no_network
    _reset()
    st.attach_state_cache(here.storage, verifier=here.verify_cached_token, client=here)
    yield here, other
    _reset()


def offline_file(client, **claims):
    token = make_token(**{"typ": "offline", "fp": client.machine_fingerprint, "lic": LICENSE_KEY,
                          "msg": "offline license", "offline_until": int(time.time()) + YEAR, **claims})
    return f"{OFFLINE_LICENSE_HEADER}\n{token}\n"


def online_license(client, other, **claims):
    """Another worker activated online and cached the signed answer it got."""
    other.storage.save_license({"license_key": LICENSE_KEY, "organization_token": "org",
                                "vm_fingerprint": other.machine_fingerprint})
    token = make_token(fp=other.machine_fingerprint, **claims)
    other.storage.save_state({"signed_token": token, "last_seen": None})
    return token


def test_an_offline_file_installed_in_another_worker_holds_here(clients):
    here, other = clients
    st.sync_with_storage()
    assert st.get_license_state().valid is False

    other.install_offline_license(offline_file(other))
    st.sync_with_storage()
    state = st.get_license_state()
    assert (state.valid, state.offline_license, state.max_assets) == (True, True, 350)


def _through_middleware(path="/api/assets/"):
    async def call_next(request):
        return JSONResponse({"ok": True})
    request = Request({"type": "http", "method": "GET", "path": path, "headers": [], "query_string": b""})
    return asyncio.run(LicenseMiddleware(app=None).dispatch(request, call_next)).status_code


def test_the_very_next_request_sees_it_through_the_middleware(clients):
    here, other = clients
    assert _through_middleware() == 403
    other.install_offline_license(offline_file(other))
    assert _through_middleware() == 200


def test_a_signed_answer_another_worker_got_online_is_taken(clients):
    here, other = clients
    token = online_license(here, other)
    st.sync_with_storage()
    state = st.get_license_state()
    assert (state.valid, state.offline_license, state.plan_code, state.offline) == (True, False, "NGC-BUS-250-1Y", False)
    assert st._signed_token == token


def test_an_older_answer_does_not_replace_a_newer_one(clients):
    here, other = clients
    online_license(here, other, plan="NGC-ENT-1000-1Y")
    st.sync_with_storage()
    assert st.get_license_state().plan_code == "NGC-ENT-1000-1Y"

    other.storage.save_state({"signed_token": make_token(fp=other.machine_fingerprint,
                                                         iat=int(time.time()) - 3600), "last_seen": None})
    st.sync_with_storage()
    assert st.get_license_state().plan_code == "NGC-ENT-1000-1Y"


def test_a_rejection_here_is_not_undone_by_an_older_answer(clients):
    here, other = clients
    online_license(here, other, iat=int(time.time()) - 600)
    st.mark_license_rejected("revoked")            # this worker was told "no" just now
    other.storage.save_state({"signed_token": make_token(fp=other.machine_fingerprint,
                                                         iat=int(time.time()) - 600), "last_seen": None})
    st.sync_with_storage()
    assert st.get_license_state().valid is False


@pytest.mark.parametrize("token", [
    lambda c: make_token(key=OTHER_KEY, fp=c.machine_fingerprint),     # not signed by a trusted key
    lambda c: make_token(fp="f" * 64),                                  # another machine
    lambda c: make_token(fp=c.machine_fingerprint, lic="OTHE-RLIC-ENSE-KEY0"),
])
def test_an_answer_that_does_not_verify_is_ignored(clients, token):
    here, other = clients
    online_license(here, other)
    other.storage.save_state({"signed_token": token(other), "last_seen": None})
    st.sync_with_storage()
    assert st.get_license_state().valid is False


def test_a_license_file_removed_elsewhere_ends_the_license_here(clients):
    here, other = clients
    other.install_offline_license(offline_file(other))
    st.sync_with_storage()
    assert st.get_license_state().valid is True

    other.deactivate()
    st.sync_with_storage()
    state = st.get_license_state()
    assert state.valid is False and state.max_assets is None


def test_with_a_valid_license_the_storage_is_looked_at_once_per_interval(clients, monkeypatch):
    here, other = clients
    other.install_offline_license(offline_file(other, plan="NGC-BUS-250-1Y"))
    st.sync_with_storage()
    monkeypatch.setattr(st, "SYNC_INTERVAL_SECONDS", 3600.0)

    other.install_offline_license(offline_file(other, plan="NGC-ENT-1000-1Y"))
    st.sync_with_storage()
    assert st.get_license_state().plan_code == "NGC-BUS-250-1Y"     # not looked yet
    st._last_sync = float("-inf")                                             # the interval has passed
    st.sync_with_storage()
    assert st.get_license_state().plan_code == "NGC-ENT-1000-1Y"


def test_without_storage_attached_nothing_happens():
    _reset()
    st.sync_with_storage()
    assert st.get_license_state().valid is False


def test_storage_files_are_replaced_whole_and_stay_private(clients):
    here, other = clients
    other.install_offline_license(offline_file(other))
    files = sorted(p.name for p in other.storage.storage_dir.iterdir())
    assert files == [".license.dat", ".license.key"]            # no temporary file left behind
    assert (other.storage.license_file.stat().st_mode & 0o777) == 0o600
