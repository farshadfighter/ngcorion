"""
License State Management

In-memory singleton that holds the current license state.
Thread-safe for concurrent access from request handlers and heartbeat thread.
"""
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


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


# Module-level singleton
_license_state = LicenseState()
_state_lock = threading.Lock()


def get_license_state() -> LicenseState:
    """Get current license state (thread-safe read)"""
    with _state_lock:
        # Return a copy to avoid external mutation
        return LicenseState(
            valid=_license_state.valid,
            plan_type=_license_state.plan_type,
            is_pilot_mode=_license_state.is_pilot_mode,
            limits=_license_state.limits.copy() if _license_state.limits else None,
            usage=_license_state.usage.copy() if _license_state.usage else None,
            message=_license_state.message,
            last_validated_at=_license_state.last_validated_at
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


def refresh_license_state(client) -> LicenseState:
    """
    Call client.validate() and update in-memory state.
    Returns updated state.
    """
    try:
        result = client.validate()
        set_license_state(result)
        return get_license_state()
    except Exception as e:
        # On error, mark as invalid
        with _state_lock:
            _license_state.valid = False
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
            "asset": "used_assets",
            "discovery": "used_discoveries",
            "audit": "used_audits",
            "harden": "used_hardens",
            "monitor": "used_monitors"
        }
        
        usage_key = usage_key_map.get(operation_type)
        if usage_key and usage_key in _license_state.usage:
            _license_state.usage[usage_key] += delta
