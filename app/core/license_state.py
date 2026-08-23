"""
License State Management

In-memory singleton that holds the current license state.
Thread-safe for concurrent access from request handlers and heartbeat thread.
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


# Module-level singleton
_license_state = LicenseState()
_state_lock = threading.Lock()

# Optional on-disk cache of the last validated state (a SecureStorage instance,
# attached at startup). Without it, restarting the app while the license server
# is unreachable starts from an empty state and locks the product out
# immediately, even though the offline grace window says the last validated
# license is still good for hours.
_state_cache = None


def attach_state_cache(store) -> None:
    """
    Register the store used to persist the last validated state.

    `store` only needs save_state(dict) / load_state() -> Optional[dict]
    (SecureStorage implements both), so this module stays free of any
    license-client import.
    """
    global _state_cache
    _state_cache = store


def _persist_state() -> None:
    """Write the current state to the cache. Never raises: a cache write is a
    convenience, and failing it must not break validation. Caller holds the lock."""
    if _state_cache is None or not settings.LICENSE_STATE_CACHE_ENABLED:
        return
    try:
        _state_cache.save_state({
            "valid": _license_state.valid,
            "plan_type": _license_state.plan_type,
            "is_pilot_mode": _license_state.is_pilot_mode,
            "limits": _license_state.limits,
            "usage": _license_state.usage,
            "message": _license_state.message,
            "last_validated_at": (
                _license_state.last_validated_at.isoformat()
                if _license_state.last_validated_at else None
            ),
        })
    except Exception as exc:
        logger.warning(f"[License] Could not cache license state: {exc}")


def restore_cached_state() -> bool:
    """
    Load the last validated state from the cache into memory.

    Called at startup *before* the first validation attempt, so that if the
    license server is unreachable right then, the app comes up on the cached
    state instead of on "no license activated". The cached timestamp is
    restored as-is, so the offline grace window keeps counting from the last
    real validation and is not silently reset by a restart.

    Returns True when a state was restored.
    """
    if _state_cache is None or not settings.LICENSE_STATE_CACHE_ENABLED:
        return False
    try:
        cached = _state_cache.load_state()
    except Exception as exc:
        logger.warning(f"[License] Could not read cached license state: {exc}")
        return False
    if not cached:
        return False

    last_raw = cached.get("last_validated_at")
    try:
        last = datetime.fromisoformat(last_raw) if last_raw else None
    except (TypeError, ValueError):
        last = None
    if last is None:
        # Without a timestamp the grace window cannot be enforced, and an
        # ungraced cached "valid" would never expire. Fail closed.
        logger.warning(
            "[License] Cached license state has no usable timestamp; ignoring it."
        )
        return False

    age = datetime.utcnow() - last
    if age > _grace_window():
        logger.warning(
            "[License] Cached license state is %.1fh old, past the %sh offline "
            "grace window; ignoring it.",
            age.total_seconds() / 3600, settings.LICENSE_OFFLINE_GRACE_HOURS,
        )
        return False

    with _state_lock:
        _license_state.valid = bool(cached.get("valid", False))
        _license_state.plan_type = cached.get("plan_type")
        _license_state.is_pilot_mode = bool(cached.get("is_pilot_mode", False))
        _license_state.limits = cached.get("limits")
        _license_state.usage = cached.get("usage")
        _license_state.last_validated_at = last
        # Not yet confirmed by the server in this process.
        _license_state.offline = True
        _license_state.message = (
            "Using the last validated license state cached "
            f"{age.total_seconds() / 3600:.1f}h ago; "
            "re-validating with the license server."
        )
    logger.info(
        "[License] Restored cached license state (valid=%s, plan=%s, age=%.1fh)",
        cached.get("valid"), cached.get("plan_type"), age.total_seconds() / 3600,
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

        if valid and last is not None and datetime.utcnow() - last > _grace_window():
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
        )


def set_license_state(data: dict):
    """Update license state from validation response (thread-safe write)"""
    with _state_lock:
        _license_state.valid = data.get("valid", False)
        _license_state.plan_type = data.get("plan_type")
        _license_state.is_pilot_mode = data.get("is_pilot_mode", False)
        _license_state.limits = data.get("limits")
        _license_state.usage = data.get("usage")
        _license_state.message = data.get("message", "")
        _license_state.last_validated_at = datetime.utcnow()
        _license_state.offline = False
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
    with _state_lock:
        _license_state.valid = False
        _license_state.offline = False
        _license_state.plan_type = None
        _license_state.is_pilot_mode = False
        _license_state.limits = None
        _license_state.usage = None
        _license_state.last_validated_at = datetime.utcnow()
        _license_state.message = f"License rejected by the license server: {reason}"
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
    from app.core.license_client import LicenseNotActivated, LicenseServerUnreachable

    try:
        result = client.validate()
        set_license_state(result)
        return get_license_state()
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
