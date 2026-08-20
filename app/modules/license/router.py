"""
License Router

Endpoints for license activation and status checking.
Frontend talks to these endpoints instead of directly to the license server.
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import logging
import requests

from app.core.license_state import get_license_state, refresh_license_state
from app.core.license_client import LicenseServerUnreachable
from app.core.heartbeat import start_heartbeat

logger = logging.getLogger(__name__)

# How long a server-validated state is considered fresh. Within this window we
# serve the cached state instead of re-validating, so a burst of status reads
# (e.g. several components mounting right after login) collapses to one call and
# we stay well under the license server's rate limit.
STATUS_REFRESH_TTL_SECONDS = 10


router = APIRouter(prefix="/api/license", tags=["License"])


class LicenseActivateRequest(BaseModel):
    """Request to activate a license"""
    license_key: str


class LicenseStatusResponse(BaseModel):
    """License status response"""
    valid: bool
    plan_type: Optional[str] = None
    is_pilot_mode: bool = False
    message: str
    limits: Optional[dict] = None
    usage: Optional[dict] = None


@router.get("/status", response_model=LicenseStatusResponse)
def get_license_status(request: Request):
    """
    Get current license status.

    The license server's database is the persistent source of truth for usage
    counters. The in-memory state in this process is only a cache that is synced
    at startup and on the hourly heartbeat, so it can be stale or empty after a
    restart (or differ between multiple workers). To keep the usage numbers
    correct and stable across logout/login and restarts, we reconcile with the
    license server on every status read, falling back to the cached state only
    when the server is unreachable.

    Asset Management is not license-gated — `limits`/`usage` only ever contain
    the audit/hardening dimensions.
    """
    state = get_license_state()
    client = getattr(request.app.state, "license_client", None)

    last = state.last_validated_at
    is_fresh = (
        last is not None
        and (datetime.utcnow() - last).total_seconds() < STATUS_REFRESH_TTL_SECONDS
    )

    if client is not None and not is_fresh:
        try:
            # Refresh from the authoritative license server. refresh_license_state
            # keeps the last validated state (flagged `offline`) when the server
            # is unreachable — never flip validity on a transient outage, or the
            # license middleware would lock the whole app out.
            state = refresh_license_state(client)
        except Exception as e:
            logger.warning(f"License status refresh failed, using cached state: {e}")
            state = get_license_state()

    usage = dict(state.usage) if state.usage else None

    return LicenseStatusResponse(
        valid=state.valid,
        plan_type=state.plan_type,
        is_pilot_mode=state.is_pilot_mode,
        message=state.message,
        limits=state.limits,
        usage=usage
    )


@router.post("/activate", response_model=LicenseStatusResponse)
def activate_license(data: LicenseActivateRequest, request: Request):
    """
    Activate a license key
    
    Steps:
    1. Call license server to activate
    2. Save license data locally
    3. Validate and update in-memory state
    4. Start heartbeat service
    5. Return license status
    """
    client = request.app.state.license_client
    
    try:
        # Activate with license server
        result = client.activate(data.license_key)
        
        # Immediately validate to populate state
        refresh_license_state(client)
        
        # Start heartbeat
        start_heartbeat(client)
        
        # Return current state
        state = get_license_state()
        return LicenseStatusResponse(
            valid=state.valid,
            plan_type=state.plan_type,
            is_pilot_mode=state.is_pilot_mode,
            message=state.message,
            limits=state.limits,
            usage=state.usage
        )
    
    except LicenseServerUnreachable as e:
        # Not the user's fault and not a licensing verdict: the license server
        # could not be reached at all. 503 + an actionable message beats a 500.
        logger.warning(f"License activation could not reach the license server: {e}")
        raise HTTPException(
            status_code=503,
            detail=(
                "License server is unreachable. Check that LICENSE_SERVER_URL "
                "points at the license server and that the network/firewall "
                "allows it, then try again."
            ),
        )

    except requests.HTTPError as e:
        # License server returned an error
        if e.response is not None:
            detail = e.response.json().get("detail", str(e))
        else:
            detail = str(e)
        raise HTTPException(status_code=400, detail=detail)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Activation failed: {str(e)}")
