"""
License State Management

In-memory singleton that holds the current license state.
Thread-safe for concurrent access from request handlers and heartbeat thread.

The state comes only from answers whose signed token verified (see
app/core/license_client.py). The on-disk cache keeps that signed token itself,
not the plain fields: at startup it is verified again, so the cache cannot be
edited into a "valid" license. The offline grace window counts from the
token's signed issue time, and a system clock that goes backwards (to stretch
that window) invalidates the state.
"""
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class LicenseState:
    """Current license state"""
    valid: bool = False
    plan_type: Optional[str] = None
    is_pilot_mode: bool = False
    limits: Optional[dict] = None
    usage: Optional[dict] = None
    message: str = "No license activated"
    last_validated_at: Optional[datetime] = None
    # True while the license server cannot be reached. The state is then served
    # from the last successful validation (within the offline grace window), so
    # a network blip between the app server and the license server does not lock
    # the product out. Consumers use it to return "license server unreachable"
    # instead of the misleading "no valid license".
    offline: bool = False
    # When the license server signed the answer this state comes from (UTC).
    # The offline grace window counts from here: a signed time cannot be moved.
    issued_at: Optional[datetime] = None


# Module-level singleton
_license_state = LicenseState()
_state_lock = threading.Lock()

# Optional on-disk cache of the last validated state (a SecureStorage instance,
# attached at startup). Without it, restarting the app while the license server
# is unreachable starts from an empty state and locks the product out
# immediately, even though the offline grace window says the last validated
# license is still good for hours.
_state_cache = None
# Verifies a cached signed token and returns the state it describes (the
# license client's verify_cached_token); attached with the cache.
_token_verifier = None
# The signed token the current state comes from, kept for the cache.
_signed_token: Optional[str] = None
# Latest wall-clock time this process has seen. A clock that later reads
# earlier than this (minus the tolerance) was set back.
_max_seen: Optional[datetime] = None
CLOCK_ROLLBACK_TOLERANCE = timedelta(minutes=5)


def attach_state_cache(store, verifier=None) -> None:
    """
    Register the store used to persist the last validated state, and the
    function that verifies a cached signed token (token -> state dict, raising
    when it does not verify).

    `store` only needs save_state(dict) / load_state() -> Optional[dict]
    (SecureStorage implements both), so this module stays free of any
    license-client import. Without a verifier nothing cached is ever restored.
    """
    global _state_cache, _token_verifier
    _state_cache = store
    _token_verifier = verifier


def _utc_from_epoch(value) -> Optional[datetime]:
    try:
        return datetime.utcfromtimestamp(int(value))
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _seen_now() -> datetime:
    """The current time, recorded as the latest time seen. Caller holds the lock."""
    global _max_seen
    now = datetime.utcnow()
    if _max_seen is None or now > _max_seen:
        _max_seen = now
    return now


def _persist_state() -> None:
    """Write the current state to the cache. Never raises: a cache write is a
    convenience, and failing it must not break validation. Caller holds the lock."""
    if _state_cache is None or not settings.LICENSE_STATE_CACHE_ENABLED:
        return
    try:
        _seen_now()
        _state_cache.save_state({
            # Only the signed token is trusted on restore; nothing else here
            # can turn into a license.
            "signed_token": _signed_token if _license_state.valid else None,
            "last_seen": _max_seen.isoformat() if _max_seen else None,
        })
    except Exception as exc:
        logger.warning(f"[License] Could not cache license state: {exc}")


def restore_cached_state() -> bool:
    """
    Load the last validated state from the cache into memory.

    Called at startup *before* the first validation attempt, so that if the
    license server is unreachable right then, the app comes up on the cached
    state instead of on "no license activated". The cache holds the signed
    token of the last answer; it is verified again here (signature, license
    key, this machine), and the offline grace window keeps counting from the
    token's signed issue time, so a restart neither resets the window nor
    accepts an edited cache. A clock that reads earlier than the issue time or
    than the last time recorded before the restart means the clock was set
    back, and the cache is refused.

    Returns True when a state was restored.
    """
    global _signed_token, _max_seen
    if _state_cache is None or not settings.LICENSE_STATE_CACHE_ENABLED:
        return False
    try:
        cached = _state_cache.load_state()
    except Exception as exc:
        logger.warning(f"[License] Could not read cached license state: {exc}")
        return False
    if not cached:
        return False

    token = cached.get("signed_token")
    if not token or _token_verifier is None:
        # Caches written before signed licensing hold plain fields that
        # anyone with the local key could edit: never restore those.
        logger.warning("[License] Cached license state has no signed token; ignoring it.")
        return False
    try:
        state = _token_verifier(token)
    except Exception as exc:
        logger.warning("[License] Cached license token does not verify (%s); ignoring it.", exc)
        return False

    issued = _utc_from_epoch(state.get("issued_at"))
    if issued is None:
        logger.warning("[License] Cached license token has no issue time; ignoring it.")
        return False

    now = datetime.utcnow()
    last_seen = None
    try:
        last_seen = datetime.fromisoformat(cached["last_seen"]) if cached.get("last_seen") else None
    except (TypeError, ValueError):
        last_seen = None
    if now < issued - CLOCK_ROLLBACK_TOLERANCE or (last_seen and now < last_seen - CLOCK_ROLLBACK_TOLERANCE):
        logger.warning(
            "[License] The system clock reads earlier than the cached license state was recorded; "
            "it was set back. Ignoring the cache."
        )
        return False

    age = now - issued
    if age > _grace_window():
        logger.warning(
            "[License] Cached license state is %.1fh old, past the %sh offline "
            "grace window; ignoring it.",
            age.total_seconds() / 3600, settings.LICENSE_OFFLINE_GRACE_HOURS,
        )
        return False

    with _state_lock:
        _license_state.valid = bool(state.get("valid", False))
        _license_state.plan_type = state.get("plan_type")
        _license_state.is_pilot_mode = bool(state.get("is_pilot_mode", False))
        _license_state.limits = state.get("limits")
        _license_state.usage = state.get("usage")
        _license_state.last_validated_at = issued
        _license_state.issued_at = issued
        _signed_token = token
        if last_seen and (_max_seen is None or last_seen > _max_seen):
            _max_seen = last_seen
        # Not yet confirmed by the server in this process.
        _license_state.offline = True
        _license_state.message = (
            "Using the last validated license state cached "
            f"{age.total_seconds() / 3600:.1f}h ago; "
            "re-validating with the license server."
        )
    logger.info(
        "[License] Restored cached license state (valid=%s, plan=%s, age=%.1fh)",
        state.get("valid"), state.get("plan_type"), age.total_seconds() / 3600,
    )
    return True


def _grace_window() -> timedelta:
    """How long a validated state survives without a successful re-validation."""
    return timedelta(hours=settings.LICENSE_OFFLINE_GRACE_HOURS)


def get_license_state() -> LicenseState:
    """
    Get current license state (thread-safe read).

    Fails closed on staleness: a state that has not been confirmed by the
    license server within LICENSE_OFFLINE_GRACE_HOURS is reported as invalid,
    even if the last answer we got was "valid". Otherwise a permanently
    unreachable license server would grant an unlimited free run.
    """
    with _state_lock:
        valid = _license_state.valid
        message = _license_state.message
        last = _license_state.last_validated_at
        # The grace window counts from the signed issue time when there is one.
        reference = _license_state.issued_at or last
        previous_max = _max_seen
        now = _seen_now()

        if valid and previous_max is not None and now < previous_max - CLOCK_ROLLBACK_TOLERANCE:
            valid = False
            message = (
                "The system clock was set back. Correct the date and time; the license "
                "is re-validated with the license server."
            )
        elif valid and reference is not None and now - reference > _grace_window():
            valid = False
            message = (
                f"License could not be re-validated for more than "
                f"{settings.LICENSE_OFFLINE_GRACE_HOURS}h. Check connectivity to "
                f"the license server."
            )

        # Return a copy to avoid external mutation
        return LicenseState(
            valid=valid,
            plan_type=_license_state.plan_type,
            is_pilot_mode=_license_state.is_pilot_mode,
            limits=_license_state.limits.copy() if _license_state.limits else None,
            usage=_license_state.usage.copy() if _license_state.usage else None,
            message=message,
            last_validated_at=last,
            offline=_license_state.offline,
            issued_at=_license_state.issued_at,
        )


def set_license_state(data: dict):
    """Update the license state from a verified answer (thread-safe write).

    `data` is what the license client returns: the state described by a
    verified signed token, with its issue time and the token itself.
    """
    global _signed_token
    with _state_lock:
        _license_state.valid = data.get("valid", False)
        _license_state.plan_type = data.get("plan_type")
        _license_state.is_pilot_mode = data.get("is_pilot_mode", False)
        _license_state.limits = data.get("limits")
        _license_state.usage = data.get("usage")
        _license_state.message = data.get("message", "")
        _license_state.last_validated_at = datetime.utcnow()
        _license_state.issued_at = _utc_from_epoch(data.get("issued_at"))
        _license_state.offline = False
        _signed_token = data.get("signed_token")
        _persist_state()


def mark_license_server_offline(error) -> None:
    """
    Flag that the license server could not be reached, without touching
    validity.

    Used by the heartbeat loop: a failed heartbeat never invalidates a license
    on its own (the server-side 48h rule does that), but the state must show
    `offline` so API errors say "license server unreachable" instead of
    "no valid license".
    """
    with _state_lock:
        _license_state.offline = True
        if _license_state.valid:
            _license_state.message = (
                f"License server unreachable; using the last validated state: {error}"
            )
        else:
            _license_state.message = f"License server unreachable: {error}"
        # Record the time seen, so a clock set back during an outage is noticed after a restart.
        _persist_state()


def mark_license_rejected(reason) -> None:
    """
    Invalidate the license immediately, on an explicit verdict from the server.

    This is the opposite of mark_license_server_offline(): there the server
    could not be reached, so the last validated state coasts through the offline
    grace window. Here the server *did* answer and said no (HTTP 400 on the
    heartbeat: expired, revoked, unknown key, fingerprint mismatch), so there is
    nothing to wait for — the grace window exists to cover outages, not
    rejections.

    The new state is written through to the on-disk cache as well, so a restart
    cannot resurrect the old "valid" snapshot from before the rejection.
    """
    global _signed_token
    with _state_lock:
        _license_state.valid = False
        _license_state.offline = False
        _license_state.plan_type = None
        _license_state.is_pilot_mode = False
        _license_state.limits = None
        _license_state.usage = None
        _license_state.last_validated_at = datetime.utcnow()
        _license_state.issued_at = None
        _license_state.message = f"License rejected by the license server: {reason}"
        _signed_token = None
        _persist_state()


def refresh_license_state(client) -> LicenseState:
    """
    Call client.validate() and update in-memory state.
    Returns the updated state.

    Distinguishes two very different failures:

    * The license server answered and said the license is not valid -> the
      answer is stored as-is and the app locks down. That is a real licensing
      decision.
    * The license server could not be reached -> the last successful state is
      kept (and flagged `offline`) for up to LICENSE_OFFLINE_GRACE_HOURS. A
      remote license server WILL have transient outages; flipping `valid` to
      False on the first failed call would 403 every request in the product
      because of a dropped packet.

    * No license is activated at all -> valid=False with an actionable message
      ("activate a license key"), and no exception: this is a steady state, not
      a transient error, and raising it once an hour from the heartbeat thread
      only produced noisy stack traces.

    Never raises for connectivity problems (including 5xx from the license
    server) — callers read `state.offline`.
    """
    from app.core.license_client import LicenseNotActivated, LicenseRejected, LicenseServerUnreachable

    try:
        result = client.validate()
        set_license_state(result)
        return get_license_state()
    except LicenseRejected as e:
        # Refused, or answered with something that does not verify: block now,
        # clear the cached token, and let the caller see why.
        mark_license_rejected(e.detail)
        logger.error(f"[License] Validation rejected: {e.detail}")
        raise
    except LicenseServerUnreachable as e:
        # Covers both "no answer" and LicenseServerError (5xx/429/garbage body).
        # A broken license server is an outage, never a licensing verdict, so
        # the last validated state stands until the grace window runs out.
        mark_license_server_offline(e)
        logger.warning(f"[License] {e}")
        return get_license_state()
    except LicenseNotActivated as e:
        with _state_lock:
            _license_state.valid = False
            _license_state.offline = False
            _license_state.plan_type = None
            _license_state.limits = None
            _license_state.usage = None
            _license_state.message = str(e)
        logger.warning(f"[License] {e}")
        return get_license_state()
    except Exception as e:
        # The server answered with a real 4xx, i.e. it rejected the request.
        # Treat it as a failed validation (fail closed) and say so clearly.
        with _state_lock:
            _license_state.valid = False
            _license_state.offline = False
            _license_state.message = (
                f"License validation was rejected by the license server: {e}"
            )
        logger.error(f"[License] Validation rejected: {e}")
        raise


def update_usage(operation_type: str, delta: int):
    """
    Optimistically update local usage counter after successful consume.
    Thread-safe.
    """
    with _state_lock:
        if _license_state.usage is None:
            return
        
        usage_key_map = {
            "audit": "used_audits",
            "harden": "used_hardens",
        }
        
        usage_key = usage_key_map.get(operation_type)
        if usage_key and usage_key in _license_state.usage:
            _license_state.usage[usage_key] += delta
