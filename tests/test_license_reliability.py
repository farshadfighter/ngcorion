"""
License reliability tests (backend).

These cover how the app behaves when the *license infrastructure* misbehaves,
which is different from how it behaves when a license is genuinely invalid:

- a license server that answers 5xx/429, or with a body that is not JSON, is an
  outage — it must never flip the in-memory state to "invalid" and lock the
  product out;
- a licensing verdict from the server — HTTP 200 with `valid: false` on
  validate, or HTTP 400 on the heartbeat — must fail closed immediately, with
  no grace window: the grace window covers outages, not rejections;
- without contact the license's plan holds for 48 hours, then the pilot
  (5 assets) for 30 days, then the state is invalid; a signed answer brings
  the plan back;
- the last validated state is cached on disk (as the license server's signed
  token) so a restart during an outage resumes where it was instead of
  refusing every request, while a cache past both windows, an edited cache, or
  a clock set back is refused;
- the heartbeat retries with backoff, survives failures, and never leaves a
  dead thread marked as running.

No network and no database: the license client is stubbed, and the state cache
is a small in-memory double.
"""
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://test:test@localhost/test_licensing_unused"
)
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-license-tests-only-not-real")

import pytest
import requests

from app.core import license_state as st
from app.core.heartbeat import HeartbeatService
from app.core.license_client import (
    LicenseNotActivated,
    LicenseRejected,
    LicenseServerError,
    LicenseServerUnreachable,
)
from app.core.license_token import claims_to_state, verify_token
from tests.license_signing_helpers import (  # noqa: F401  (fixture)
    FINGERPRINT,
    LICENSE_KEY,
    OTHER_KEY,
    TEST_KID,
    make_token,
    trusted_test_key,
)

VALID_RESPONSE = {
    "valid": True,
    "plan_code": "NGC-PRO-100-1Y",
    "plan_name": "NGCorion Professional",
    "is_pilot_mode": False,
    "message": "ok",
    "limits": {"max_assets": 100, "addon_packs": 0},
}


class FakeCache:
    """Stand-in for SecureStorage: only save_state/load_state are used."""

    def __init__(self, state=None):
        self.state = state

    def save_state(self, state):
        self.state = state

    def load_state(self):
        return self.state


class StubClient:
    """License client that answers validate()/heartbeat() however a test wants."""

    def __init__(self, validate_result=None, validate_error=None, heartbeat_error=None):
        self.validate_result = validate_result
        self.validate_error = validate_error
        self.heartbeat_error = heartbeat_error
        self.heartbeat_result = {"success": True, "message": "ok"}
        self.calls = 0

    def validate(self):
        self.calls += 1
        if self.validate_error:
            raise self.validate_error
        return self.validate_result

    def heartbeat(self, asset_count=None):
        self.asset_count = asset_count
        if self.heartbeat_error:
            raise self.heartbeat_error
        return self.heartbeat_result


def _reset():
    st._license_state.__init__()
    st._state_cache = None
    st._token_verifier = None
    st._signed_token = None
    st._max_seen = None


@pytest.fixture(autouse=True)
def clean_license_state():
    """Reset the module-level singleton and cache around every test."""
    _reset()
    yield
    _reset()


def verifier(token):
    """What the license client's verify_cached_token does, for this test's license and machine."""
    return claims_to_state(verify_token(token, license_key=LICENSE_KEY, vm_fingerprint=FINGERPRINT), token)


def signed_state(**claims):
    """A license state as the client returns it from a verified answer."""
    token = make_token(**claims)
    return verifier(token)


def restart(cache):
    """Simulate a process restart: memory is empty, the cache is not."""
    _reset()
    st.attach_state_cache(cache, verifier=verifier)


def _seed_valid_state():
    st.set_license_state(VALID_RESPONSE)


# ==================== server-side failures are not verdicts ====================

@pytest.mark.parametrize("status_code", [429, 500, 502, 503, 504])
def test_server_side_error_keeps_the_last_valid_state(status_code):
    """A broken license server must not revoke a good license.

    The license server reports verdicts as HTTP 200 with `valid: false`, so a
    5xx/429 is always its own failure. Treating it as "license invalid" used to
    403 every request in the product on a transient server fault.
    """
    _seed_valid_state()
    client = StubClient(
        validate_error=LicenseServerError("server broke", status_code=status_code)
    )

    state = st.refresh_license_state(client)

    assert state.valid is True
    assert state.offline is True
    assert "unreachable" in state.message.lower()


def test_license_server_error_is_handled_by_unreachable_handlers():
    """Every existing `except LicenseServerUnreachable` must also cover 5xx."""
    assert issubclass(LicenseServerError, LicenseServerUnreachable)


def test_connection_failure_keeps_the_last_valid_state():
    _seed_valid_state()
    client = StubClient(validate_error=LicenseServerUnreachable("connection refused"))

    state = st.refresh_license_state(client)

    assert state.valid is True
    assert state.offline is True


def test_server_verdict_still_fails_closed():
    """An explicit `valid: false` from the server is a real licensing decision."""
    _seed_valid_state()
    client = StubClient(validate_result={"valid": False, "message": "License expired"})

    state = st.refresh_license_state(client)

    assert state.valid is False
    assert state.offline is False
    assert state.message == "License expired"


# ==================== an explicit rejection blocks immediately ====================

def test_heartbeat_rejection_invalidates_without_waiting_for_the_grace_window():
    """HTTP 400 on the heartbeat is the server refusing this license.

    Expired, revoked, unknown key, fingerprint mismatch — the server looked it
    up and said no. That must take effect at once; coasting on the offline
    grace window would keep serving a license the server has already refused.
    """
    _seed_valid_state()
    assert st.get_license_state().valid is True

    service = HeartbeatService(
        StubClient(heartbeat_error=LicenseRejected("License has expired"))
    )
    assert service._run_once() is True   # the server answered: not a retryable failure

    state = st.get_license_state()
    assert state.valid is False
    assert state.offline is False        # a verdict, not an outage
    assert "License has expired" in state.message


def test_rejection_clears_the_plan_and_its_limit():
    _seed_valid_state()

    st.mark_license_rejected("License revoked")

    state = st.get_license_state()
    assert state.valid is False
    assert state.plan_code is None
    assert state.max_assets is None


def test_rejection_is_written_through_to_the_cache(trusted_test_key):
    """A restart must not resurrect the pre-rejection "valid" snapshot."""
    cache = FakeCache()
    st.attach_state_cache(cache, verifier=verifier)
    st.set_license_state(signed_state())
    assert cache.state["signed_token"]

    st.mark_license_rejected("Invalid VM fingerprint")
    assert cache.state["signed_token"] is None

    restart(cache)
    assert st.restore_cached_state() is False
    assert st.get_license_state().valid is False


def test_rejection_does_not_trigger_the_outage_backoff():
    """The verdict will not change in 60s — stay on the normal interval."""
    service = HeartbeatService(
        StubClient(heartbeat_error=LicenseRejected("License has expired")),
        interval_seconds=3600, retry_seconds=60,
    )
    service._run_once()

    assert service._consecutive_failures == 0
    assert service._next_delay(succeeded=True) == 3600


@pytest.mark.parametrize("error", [
    LicenseServerUnreachable("down"),
    LicenseServerError("broken", status_code=500),
])
def test_outages_still_do_not_invalidate(error):
    """The contrast case: a broken or absent server keeps the license alive."""
    _seed_valid_state()
    service = HeartbeatService(StubClient(heartbeat_error=error))

    service._run_once()

    state = st.get_license_state()
    assert state.valid is True
    assert state.offline is True


def test_missing_activation_does_not_raise():
    """"Not activated" is a steady state, not an error to retry once an hour."""
    client = StubClient(validate_error=LicenseNotActivated("No license is activated"))

    state = st.refresh_license_state(client)  # must not raise

    assert state.valid is False
    assert state.offline is False
    assert "No license is activated" in state.message


def test_hard_rejection_invalidates_and_reraises():
    """A 4xx is the server rejecting the request: fail closed, and say why."""
    _seed_valid_state()
    client = StubClient(validate_error=requests.HTTPError("400 Bad Request"))

    with pytest.raises(requests.HTTPError):
        st.refresh_license_state(client)

    state = st.get_license_state()
    assert state.valid is False
    assert "rejected by the license server" in state.message


# ==================== the cached state survives a restart ====================

def test_cached_state_is_restored_within_the_grace_window(trusted_test_key):
    cache = FakeCache()
    st.attach_state_cache(cache, verifier=verifier)
    st.set_license_state(signed_state())
    assert cache.state is not None, "a validated state must be persisted"

    restart(cache)

    assert st.restore_cached_state() is True
    restored = st.get_license_state()
    assert restored.valid is True
    assert (restored.plan_code, restored.max_assets) == ("NGC-BUS-250-1Y", 350)
    # Flagged offline until this process confirms with the server.
    assert restored.offline is True


def test_restored_state_keeps_the_signed_issue_time(trusted_test_key):
    """A restart must not silently reset the offline grace window: it counts from the signed iat."""
    issued = int(time.time()) - 40 * 3600
    cache = FakeCache({"signed_token": make_token(iat=issued), "last_seen": None})
    st.attach_state_cache(cache, verifier=verifier)

    assert st.restore_cached_state() is True
    assert abs((st.get_license_state().issued_at - datetime.utcfromtimestamp(issued)).total_seconds()) < 1


def test_cache_in_the_pilot_window_restores_as_the_pilot(trusted_test_key):
    cache = FakeCache({"signed_token": make_token(iat=int(time.time()) - 72 * 3600)})
    st.attach_state_cache(cache, verifier=verifier)

    assert st.restore_cached_state() is True
    state = st.get_license_state()
    assert (state.valid, state.offline_pilot, state.max_assets) == (True, True, 5)


def test_cached_state_past_both_windows_is_refused(trusted_test_key):
    cache = FakeCache({"signed_token": make_token(iat=int(time.time()) - (48 * 3600 + 31 * 86400))})
    st.attach_state_cache(cache, verifier=verifier)

    assert st.restore_cached_state() is False
    assert st.get_license_state().valid is False


def test_plain_cached_state_without_a_signed_token_is_refused(trusted_test_key):
    """The pre-signing cache format (plain fields) could be edited into a license: never restore it."""
    cache = FakeCache({**VALID_RESPONSE, "last_validated_at": datetime.utcnow().isoformat()})
    st.attach_state_cache(cache, verifier=verifier)

    assert st.restore_cached_state() is False
    assert st.get_license_state().valid is False


@pytest.mark.parametrize("token", [
    make_token(key=OTHER_KEY),                                   # signed by someone else
    make_token(fp="0" * 64),                                     # another machine's answer
    make_token(lic="OTHER-LICE-NSEK-EY00"),                      # another license
])
def test_edited_or_foreign_cached_token_is_refused(trusted_test_key, token):
    cache = FakeCache({"signed_token": token})
    st.attach_state_cache(cache, verifier=verifier)

    assert st.restore_cached_state() is False


def test_tampered_cached_token_is_refused(trusted_test_key):
    body, sig = make_token().split(".")
    import base64, json
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    claims["limits"] = {"max_audits": None, "max_hardens": None}
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    cache = FakeCache({"signed_token": f"{forged}.{sig}"})
    st.attach_state_cache(cache, verifier=verifier)

    assert st.restore_cached_state() is False


def test_cache_from_a_clock_set_back_is_refused(trusted_test_key):
    """The clock reads earlier than the last time recorded before the restart."""
    later = (datetime.utcnow() + timedelta(hours=10)).isoformat()
    cache = FakeCache({"signed_token": make_token(), "last_seen": later})
    st.attach_state_cache(cache, verifier=verifier)

    assert st.restore_cached_state() is False


def test_clock_set_back_while_running_invalidates(trusted_test_key):
    st.set_license_state(signed_state())
    assert st.get_license_state().valid is True
    st._max_seen = datetime.utcnow() + timedelta(hours=3)      # time seen before the clock went back

    state = st.get_license_state()
    assert state.valid is False
    assert "clock was set back" in state.message


def test_state_cache_write_failure_never_breaks_validation():
    class ExplodingCache(FakeCache):
        def save_state(self, state):
            raise OSError("disk full")

    st.attach_state_cache(ExplodingCache())
    st.set_license_state(VALID_RESPONSE)  # must not raise

    assert st.get_license_state().valid is True


# ==================== offline: own plan 48h, then the pilot, then locked ====================

def test_within_48_hours_the_license_keeps_its_plan(trusted_test_key):
    st.set_license_state(signed_state(iat=int(time.time()) - 47 * 3600))

    state = st.get_license_state()

    assert (state.valid, state.offline_pilot, state.max_assets, state.is_pilot_mode) == (True, False, 350, False)


def test_after_48_hours_it_falls_back_to_the_pilot(trusted_test_key):
    issued = int(time.time()) - 49 * 3600
    st.set_license_state(signed_state(iat=issued))

    state = st.get_license_state()

    assert (state.valid, state.offline_pilot, state.is_pilot_mode) == (True, True, True)
    assert state.max_assets == st.PILOT_FALLBACK_ASSETS == 5
    assert state.plan_code == "NGC-BUS-250-1Y"          # the license is unchanged
    expected_end = datetime.utcfromtimestamp(issued) + timedelta(hours=48, days=30)
    assert abs((state.offline_pilot_until - expected_end).total_seconds()) < 1
    assert "pilot" in state.message


def test_an_unlimited_license_offline_is_also_held_to_the_pilot(trusted_test_key):
    st.set_license_state(signed_state(iat=int(time.time()) - 50 * 3600,
                                      limits={"max_assets": None, "addon_packs": 0}))

    assert st.get_license_state().max_assets == 5


def test_after_the_pilot_month_it_locks(trusted_test_key):
    st.set_license_state(signed_state(iat=int(time.time()) - (48 * 3600 + 30 * 86400 + 60)))

    state = st.get_license_state()

    assert state.valid is False
    assert "pilot fallback" in state.message


def test_a_signed_answer_brings_the_plan_back(trusted_test_key):
    st.set_license_state(signed_state(iat=int(time.time()) - 60 * 3600))
    assert st.get_license_state().offline_pilot is True

    st.set_license_state(signed_state())                 # the server is reached again

    state = st.get_license_state()
    assert (state.valid, state.offline_pilot, state.max_assets) == (True, False, 350)


def test_an_expired_license_is_not_valid_offline(trusted_test_key):
    st.set_license_state(signed_state(exp=int(time.time()) - 60))

    state = st.get_license_state()

    assert state.valid is False
    assert "expired" in state.message


def test_a_token_without_an_asset_limit_gets_the_pilot_limit(trusted_test_key):
    """An answer from a license server before licensing v3 carries audit/hardening quotas; it
    must not be read as "unlimited assets"."""
    st.set_license_state(signed_state(limits={"max_audits": None, "max_hardens": None}))

    assert st.get_license_state().max_assets == 5


def test_the_offline_rules_are_not_configurable():
    from app.core.config import settings
    assert not hasattr(st, "_grace_window")
    assert st.OFFLINE_GRACE == timedelta(hours=48)
    assert settings.LICENSE_OFFLINE_GRACE_HOURS is None


# ==================== heartbeat ====================

def test_failed_heartbeat_backs_off_instead_of_waiting_a_full_interval():
    service = HeartbeatService(
        StubClient(), interval_seconds=3600, retry_seconds=60, max_retry_seconds=900
    )

    delays = [service._next_delay(succeeded=False) for _ in range(6)]

    assert delays == [60, 120, 240, 480, 900, 900]
    assert service._next_delay(succeeded=True) == 3600


def test_retry_delay_never_exceeds_the_normal_interval():
    service = HeartbeatService(
        StubClient(), interval_seconds=120, retry_seconds=60, max_retry_seconds=900
    )

    assert [service._next_delay(succeeded=False) for _ in range(4)] == [60, 120, 120, 120]


@pytest.mark.parametrize("error", [
    LicenseServerUnreachable("down"),
    LicenseServerError("broken", status_code=500),
    RuntimeError("unexpected"),
])
def test_heartbeat_failures_are_reported_not_raised(error):
    _seed_valid_state()
    service = HeartbeatService(StubClient(heartbeat_error=error))

    assert service._run_once() is False       # never raises out of the thread
    assert st.get_license_state().valid is True   # and never revokes the license


def test_successful_heartbeat_refreshes_the_state():
    client = StubClient(validate_result=VALID_RESPONSE)
    service = HeartbeatService(client)

    assert service._run_once() is True
    assert st.get_license_state().valid is True
    assert client.calls == 1


def test_heartbeat_reports_the_asset_count(monkeypatch):
    import app.core.heartbeat as hb
    monkeypatch.setattr(hb, "_asset_count", lambda: 42)
    client = StubClient(validate_result=VALID_RESPONSE)

    HeartbeatService(client)._run_once()

    assert client.asset_count == 42


def test_heartbeat_thread_survives_repeated_failures_and_stops_promptly():
    client = StubClient(heartbeat_error=LicenseServerUnreachable("down"))
    service = HeartbeatService(
        client, interval_seconds=60, retry_seconds=1, max_retry_seconds=1
    )
    service.start()
    try:
        time.sleep(0.2)
        assert service.is_alive() and service.running
    finally:
        started = time.monotonic()
        service.stop()
        elapsed = time.monotonic() - started

    assert not service.is_alive()
    # Event-based sleep: shutdown does not wait out the interval.
    assert elapsed < 2


def test_a_dead_heartbeat_thread_is_not_reported_as_running():
    """`running` must reflect reality, or start_heartbeat() refuses to restart."""
    class Killer:
        def heartbeat(self, asset_count=None):
            raise SystemExit("thread killer")

    service = HeartbeatService(Killer(), interval_seconds=1)
    service.start()
    for _ in range(50):
        if not service.running:
            break
        time.sleep(0.02)

    assert service.running is False
    # `running` is cleared in the loop's finally block, so the thread may take a
    # moment longer to actually exit — join before asserting on liveness.
    service.thread.join(timeout=2)
    assert not service.is_alive()

    # ...and the service can be brought back.
    service.client = StubClient(heartbeat_error=LicenseServerUnreachable("down"))
    service.start()
    try:
        assert service.is_alive()
    finally:
        service.stop()
