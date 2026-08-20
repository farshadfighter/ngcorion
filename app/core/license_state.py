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

    Never raises for connectivity problems — callers read `state.offline`.
    """
    from app.core.license_client import LicenseServerUnreachable

    try:
        result = client.validate()
        set_license_state(result)
        return get_license_state()
    except LicenseServerUnreachable as e:
        mark_license_server_offline(e)
        logger.warning(f"[License] {e}")
        return get_license_state()
    except Exception as e:
        # The server answered with something we could not use (HTTP error,
        # malformed payload). Treat it as a failed validation.
        with _state_lock:
            _license_state.valid = False
            _license_state.offline = False
            _license_state.message = f"License validation failed: {str(e)}"
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
