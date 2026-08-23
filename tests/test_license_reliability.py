"""
License reliability tests (backend).

These cover how the app behaves when the *license infrastructure* misbehaves,
which is different from how it behaves when a license is genuinely invalid:

- a license server that answers 5xx/429, or with a body that is not JSON, is an
  outage — it must never flip the in-memory state to "invalid" and lock the
  product out;
- a licensing verdict from the server (HTTP 200 with `valid: false`) must still
  fail closed;
- the last validated state is cached on disk so a restart during an outage
  resumes inside the offline grace window instead of refusing every request,
  while a cache older than the grace window is refused;
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
    LicenseServerError,
    LicenseServerUnreachable,
)

VALID_RESPONSE = {
    "valid": True,
    "plan_type": "plan_100",
    "is_pilot_mode": False,
    "message": "ok",
    "limits": {"max_audits": 100, "max_hardens": 100},
    "usage": {"used_audits": 3, "used_hardens": 1},
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

    def heartbeat(self):
        if self.heartbeat_error:
            raise self.heartbeat_error
        return self.heartbeat_result


@pytest.fixture(autouse=True)
def clean_license_state():
    """Reset the module-level singleton and cache around every test."""
    st._license_state.__init__()
    st._state_cache = None
    yield
    st._license_state.__init__()
    st._state_cache = None


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

def test_cached_state_is_restored_within_the_grace_window():
    cache = FakeCache()
    st.attach_state_cache(cache)
    _seed_valid_state()
    assert cache.state is not None, "a validated state must be persisted"

    # Simulate a process restart: memory is empty, the cache is not.
    st._license_state.__init__()
    st.attach_state_cache(cache)

    assert st.restore_cached_state() is True
    restored = st.get_license_state()
    assert restored.valid is True
    assert restored.plan_type == "plan_100"
    # Flagged offline until this process confirms with the server.
    assert restored.offline is True


def test_restored_state_keeps_the_original_validation_timestamp():
    """A restart must not silently reset the offline grace window."""
    validated_at = datetime.utcnow() - timedelta(hours=40)
    cache = FakeCache({**VALID_RESPONSE, "last_validated_at": validated_at.isoformat()})
    st.attach_state_cache(cache)

    assert st.restore_cached_state() is True
    assert abs(
        (st.get_license_state().last_validated_at - validated_at).total_seconds()
    ) < 1


def test_cached_state_past_the_grace_window_is_refused():
    stale = datetime.utcnow() - timedelta(hours=72)
    cache = FakeCache({**VALID_RESPONSE, "last_validated_at": stale.isoformat()})
    st.attach_state_cache(cache)

    assert st.restore_cached_state() is False
    assert st.get_license_state().valid is False


def test_cached_state_without_a_timestamp_is_refused():
    """Without a timestamp the grace window cannot be enforced — fail closed."""
    cache = FakeCache({**VALID_RESPONSE, "last_validated_at": None})
    st.attach_state_cache(cache)

    assert st.restore_cached_state() is False
    assert st.get_license_state().valid is False


def test_state_cache_write_failure_never_breaks_validation():
    class ExplodingCache(FakeCache):
        def save_state(self, state):
            raise OSError("disk full")

    st.attach_state_cache(ExplodingCache())
    st.set_license_state(VALID_RESPONSE)  # must not raise

    assert st.get_license_state().valid is True


def test_grace_window_still_expires_in_memory():
    _seed_valid_state()
    st._license_state.last_validated_at = datetime.utcnow() - timedelta(hours=49)

    state = st.get_license_state()

    assert state.valid is False
    assert "could not be re-validated" in state.message


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
        def heartbeat(self):
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
