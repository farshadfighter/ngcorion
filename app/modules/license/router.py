"""
License Router

Endpoints for license activation and status checking.
Frontend talks to these endpoints instead of directly to the license server.
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
import requests

from app.core.license_state import get_license_state, refresh_license_state, set_license_state
from app.core.heartbeat import start_heartbeat


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
def get_license_status():
    """
    Get current license status
    
    Returns in-memory license state without calling the license server.
    """
    state = get_license_state()
    return LicenseStatusResponse(
        valid=state.valid,
        plan_type=state.plan_type,
        is_pilot_mode=state.is_pilot_mode,
        message=state.message,
        limits=state.limits,
        usage=state.usage
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
    
    except requests.HTTPError as e:
        # License server returned an error
        if e.response is not None:
            detail = e.response.json().get("detail", str(e))
        else:
            detail = str(e)
        raise HTTPException(status_code=400, detail=detail)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Activation failed: {str(e)}")
