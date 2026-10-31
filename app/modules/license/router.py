"""
License Router

Endpoints for license activation and status checking.
Frontend talks to these endpoints instead of directly to the license server.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
import logging
import requests

from app.core.asset_entitlement import count_assets, usage as asset_usage
from app.core.license_state import get_license_state, refresh_license_state, sync_with_storage
from app.core.database import get_db
from app.core.dependencies import get_current_user, license_error_detail, require_admin
from app.core.license_client import LicenseRejected, LicenseServerError, LicenseServerUnreachable
from app.core.heartbeat import start_heartbeat
from app.models.security_audit_log import log_action

logger = logging.getLogger(__name__)

# How long a server-validated state is considered fresh. Within this window we
# serve the cached state instead of re-validating, so a burst of status reads
# (e.g. several components mounting right after login) collapses to one call and
# we stay well under the license server's rate limit.
STATUS_REFRESH_TTL_SECONDS = 10


router = APIRouter(prefix="/api/license", tags=["License"])

_optional_bearer = HTTPBearer(auto_error=False)


class LicenseActivateRequest(BaseModel):
    """Request to activate a license"""
    license_key: str


class LicenseStatusResponse(BaseModel):
    """License status: the license's plan and its asset limit, as the signed answers say, with the
    offline rules applied (license_state.get_license_state). No counts from the inventory here:
    this endpoint answers before login; GET /api/license/usage has them."""
    valid: bool
    message: str
    plan_code: Optional[str] = None
    plan_name: Optional[str] = None
    is_pilot_mode: bool = False
    # None = unlimited.
    max_assets: Optional[int] = None
    addon_packs: int = 0
    expires_at: Optional[datetime] = None
    # When the license server last signed an answer for this installation.
    last_contact_at: Optional[datetime] = None
    # The license server cannot be reached right now.
    offline: bool = False
    # No signed answer for more than 48h: running on the pilot entitlement
    # until `offline_pilot_until` (then locked), or until the server is reached.
    offline_pilot: bool = False
    offline_pilot_until: Optional[datetime] = None
    # An offline (air-gapped) license file is installed: no contact at all,
    # valid until offline_until; renewed by a new file.
    offline_license: bool = False
    offline_until: Optional[datetime] = None


class OfflineRequestBody(BaseModel):
    """The license key for a new offline license; empty for a renewal of the installed one."""
    license_key: Optional[str] = Field(default=None, max_length=32)


class OfflineRequestResponse(BaseModel):
    filename: str
    content: str


class OfflineInstallBody(BaseModel):
    """The license file the license server's administrator signed for this machine."""
    content: str = Field(min_length=1, max_length=16384)


class LicenseUsageResponse(BaseModel):
    """The inventory against the license (asset_entitlement.usage)."""
    used: int
    max_assets: Optional[int] = None
    unlimited: bool = False
    over_limit: bool = False
    remaining: Optional[int] = None
    # While over the limit: assets with a higher id are outside the license
    # (audits and hardening refused); None when all are covered.
    licensed_through_id: Optional[int] = None


def _status(state) -> LicenseStatusResponse:
    return LicenseStatusResponse(
        valid=state.valid,
        message=state.message,
        plan_code=state.plan_code,
        plan_name=state.plan_name,
        is_pilot_mode=state.is_pilot_mode,
        max_assets=state.max_assets if state.valid else None,
        addon_packs=state.addon_packs,
        expires_at=state.expires_at,
        last_contact_at=state.issued_at,
        offline=state.offline,
        offline_pilot=state.offline_pilot,
        offline_pilot_until=state.offline_pilot_until,
        offline_license=state.offline_license,
        offline_until=state.offline_until,
    )


@router.get("/status", response_model=LicenseStatusResponse)
def get_license_status(request: Request):
    """
    Get current license status.

    The license server is the source of truth for the plan and its limit. The
    in-memory state in this process is a cache synced at startup and on the
    hourly heartbeat, so it can be stale after a restart (or differ between
    workers); the status read reconciles with the license server (at most every
    STATUS_REFRESH_TTL_SECONDS), falling back to the cached state only when the
    server is unreachable.
    """
    sync_with_storage()
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
            # refresh_license_state already handled connectivity failures and
            # 5xx internally; anything landing here is a hard rejection, and the
            # cached state it left behind is what we report.
            logger.warning(
                "License status refresh failed (%s: %s), using cached state",
                type(e).__name__, e,
            )
            state = get_license_state()

    return _status(state)


@router.get("/usage", response_model=LicenseUsageResponse)
def get_license_usage(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """How many assets the inventory holds against the license's limit (signed-in users)."""
    return LicenseUsageResponse(**asset_usage(db))


@router.post("/activate", response_model=LicenseStatusResponse)
def activate_license(
    data: LicenseActivateRequest,
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_optional_bearer),
    db: Session = Depends(get_db),
):
    """
    Unauthenticated only while no valid license is active - that is the
    first-run / expired-license screen, shown before anyone can log in. Once a
    license is valid, replacing it is an admin action; otherwise anyone who can
    reach the server could swap the installed key out from under the operator.
    """
    actor = _require_admin_while_licensed(credentials, db)
    try:
        status = _activate(data, request)
    except HTTPException as exc:
        _audit(db, actor, request, "license.activate", "failed", f"key {_masked(data.license_key)}: {exc.detail}")
        raise
    _audit(db, actor, request, "license.activate", "success",
           f"key {_masked(data.license_key)}, plan {getattr(status, 'plan_code', None)}, "
           f"{getattr(status, 'max_assets', None)} assets")
    return status


def _require_admin_while_licensed(credentials, db):
    """Without a valid license these endpoints are open (the first-run screen, shown before anyone
    can log in); with one, changing the license is an administrator's action. Returns the
    administrator, or None on the first-run screen."""
    if get_license_state().valid:
        if credentials is None:
            raise HTTPException(
                status_code=401,
                detail="Administrator login is required to replace an active license",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return require_admin(get_current_user(credentials, db))
    return None


def _masked(license_key: Optional[str]) -> str:
    """A license key as the audit trail shows it: enough to tell keys apart, not enough to use."""
    key = (license_key or "").strip()
    return f"{key[:4]}…{key[-4:]}" if len(key) > 8 else "…"


def _audit(db: Session, actor, request: Request, action: str, result: str, detail: str) -> None:
    """A license change in the audit trail. Before the first license there is nobody signed in:
    the actor is then the first-run screen."""
    log_action(db, user_id=actor.id if actor else None,
               username=actor.username if actor else "(first-run screen)",
               action=action, module="license",
               ip_address=request.client.host if request is not None and request.client else None,
               result=result, detail=str(detail)[:500])


# ---------- offline (air-gapped) licenses ----------

@router.post("/offline/request", response_model=OfflineRequestResponse)
def offline_license_request(
    data: OfflineRequestBody,
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_optional_bearer),
    db: Session = Depends(get_db),
):
    """The request file for an offline license (or for renewing the installed one): license key,
    this machine's fingerprint and the asset count. The license administrator signs a license file
    for it. Same access rule as activation."""
    _require_admin_while_licensed(credentials, db)
    client = request.app.state.license_client
    try:
        assets = count_assets(db)
    except Exception:  # noqa: BLE001  (the count is information; the request works without it)
        assets = None
    try:
        content = client.offline_request(data.license_key, assets)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    key = (data.license_key or (client.get_license_data() or {}).get("license_key") or "license").strip().upper()
    return OfflineRequestResponse(filename=f"ngcorion-{key}.ngcreq", content=content)


@router.post("/offline/install", response_model=LicenseStatusResponse)
def offline_license_install(
    data: OfflineInstallBody,
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_optional_bearer),
    db: Session = Depends(get_db),
):
    """Install an offline license file: verified (signature, this machine, still valid) and stored;
    from then on NGCorion runs without contacting the license server until the file ends."""
    actor = _require_admin_while_licensed(credentials, db)
    client = request.app.state.license_client
    try:
        client.install_offline_license(data.content)
    except LicenseRejected as exc:
        logger.warning("Offline license file not accepted: %s", exc.detail)
        _audit(db, actor, request, "license.offline_install", "failed", exc.detail)
        raise HTTPException(status_code=400, detail=exc.detail)
    refresh_license_state(client)
    start_heartbeat(client)
    status = _status(get_license_state())
    _audit(db, actor, request, "license.offline_install", "success",
           f"plan {status.plan_code}, {status.max_assets} assets, valid until {status.offline_until}")
    return status


def _activate(data: LicenseActivateRequest, request: Request):
    """
    Activate a license key
    
    Steps:
    1. Call license server to activate
    2. Save license data locally
    3. Validate and update in-memory state
    4. Start the heartbeat service and send a heartbeat at once
    5. Return license status
    """
    client = request.app.state.license_client
    
    try:
        # Activate with license server
        client.activate(data.license_key)
        
        # Immediately validate to populate state
        refresh_license_state(client)
        
        # Start the heartbeat, and send one now: it carries the asset count,
        # which the license server should see from the moment of activation
        # rather than at the next hourly beat. It runs on the heartbeat thread;
        # this request does not wait for it.
        start_heartbeat(client, beat_now=True)
        
        # Return current state
        return _status(get_license_state())
    
    except LicenseServerError as e:
        # The server answered with a 5xx/429: it is broken or overloaded, and
        # the license key the operator just typed is very probably fine.
        logger.error(f"License activation: license server error: {e}")
        raise HTTPException(
            status_code=503,
            detail=(
                f"License server returned HTTP {e.status_code}. The license key "
                f"was not rejected — the server itself is failing. Try again "
                f"shortly, and check the license server's own logs."
            ),
            headers={"Retry-After": "30"},
        )

    except LicenseServerUnreachable as e:
        # Not the user's fault and not a licensing verdict: the license server
        # could not be reached at all. 503 + an actionable message beats a 500.
        logger.warning(f"License activation could not reach the license server: {e}")
        raise HTTPException(
            status_code=503,
            detail=(
                "The license server (lic.ngcorion.com) is unreachable. Check that "
                "this server resolves lic.ngcorion.com (DNS) and may connect to it "
                "on port 443 (firewall, proxy), then try again."
            ),
            headers={"Retry-After": "30"},
        )

    except LicenseRejected as e:
        # The answer did not verify (not signed by the NGCorion license server,
        # or not about this license or machine), or the license was refused.
        logger.warning(f"License activation not accepted: {e.detail}")
        raise HTTPException(status_code=400, detail=e.detail)

    except requests.HTTPError as e:
        # License server rejected the request (4xx) — a real answer about this
        # key. Parse its message defensively: a non-JSON body used to raise
        # inside this handler and surface as an opaque 500.
        detail = license_error_detail(e, "License activation was rejected.")
        logger.warning(f"License activation rejected by the license server: {detail}")
        raise HTTPException(status_code=400, detail=detail)

    except HTTPException:
        raise

    except Exception as e:
        # The cause is in the server log only: this answer may go to someone not signed in (no valid
        # license yet), and an unexpected error's text can name files, hosts or queries.
        logger.exception("License activation failed unexpectedly")
        raise HTTPException(
            status_code=500,
            detail=f"Activation failed ({type(e).__name__}). The cause is in the server log.",
        )
