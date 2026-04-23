from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import crud, schemas
from ..database import get_db
from ..utils.signing import verify_signature
from fastapi import Header
from typing import Optional, Union

router = APIRouter(prefix="/api/licenses", tags=["licenses"])

def verify_request_signature(
    x_timestamp: Optional[str] = Header(None),
    x_signature: Optional[str] = Header(None),
    data: Union[schemas.LicenseValidate, schemas.OperationConsume] = None
):
    """Verify HMAC signature for protected endpoints"""
    if not x_timestamp or not x_signature:
        raise HTTPException(status_code=401, detail="Missing signature headers")
    
    request_data = {
        "license_key": data.license_key,
        "organization_token": data.organization_token,
        "vm_fingerprint": data.vm_fingerprint
    }
    
    # Add operation-specific fields if present
    if isinstance(data, schemas.OperationConsume):
        request_data["operation_type"] = data.operation_type
        request_data["count"] = data.count
    
    # Use organization_token as the shared secret
    if not verify_signature(request_data, x_signature, x_timestamp, data.organization_token):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    return True

@router.post("/activate", response_model=schemas.ValidationResponse)
def activate_license(data: schemas.LicenseActivate, db: Session = Depends(get_db)):
    """license activision with VM fingerprint"""
    success, message, license = crud.activate_license(db, data.license_key, data.vm_fingerprint)
    
    if not success:
        raise HTTPException(status_code=400, detail=message)
    
    return schemas.ValidationResponse(
        valid=True,
        message=message,
        plan_type=license.plan_type,
        is_pilot_mode=license.is_pilot_mode,
        organization_token=license.organization_token,
        limits={
            "max_assets": license.max_assets,
            "max_discoveries": license.max_discoveries,
            "max_audits": license.max_audits,
            "max_hardens": license.max_hardens,
            "max_monitors": license.max_monitors
        },
        usage={
            "used_assets": license.used_assets,
            "used_discoveries": license.used_discoveries,
            "used_audits": license.used_audits,
            "used_hardens": license.used_hardens,
            "used_monitors": license.used_monitors
        }
    )

@router.post("/validate", response_model=schemas.ValidationResponse)
def validate_license(
    data: schemas.LicenseValidate,
    db: Session = Depends(get_db),
    x_timestamp: Optional[str] = Header(None),
    x_signature: Optional[str] = Header(None)
):
    """license validation"""
    # Verify signature
    verify_request_signature(x_timestamp, x_signature, data)
    
    success, message, license = crud.validate_license(
        db, data.license_key, data.organization_token, data.vm_fingerprint
    )
    
    if not success:
        return schemas.ValidationResponse(valid=False, message=message)
    
    return schemas.ValidationResponse(
        valid=True,
        message=message,
        plan_type=license.plan_type,
        is_pilot_mode=license.is_pilot_mode,
        limits={
            "max_assets": license.max_assets,
            "max_discoveries": license.max_discoveries,
            "max_audits": license.max_audits,
            "max_hardens": license.max_hardens,
            "max_monitors": license.max_monitors
        },
        usage={
            "used_assets": license.used_assets,
            "used_discoveries": license.used_discoveries,
            "used_audits": license.used_audits,
            "used_hardens": license.used_hardens,
            "used_monitors": license.used_monitors
        }
    )

@router.post("/heartbeat", response_model=schemas.HeartbeatResponse)
def heartbeat(data: schemas.LicenseValidate, db: Session = Depends(get_db)):
    """cheking validation"""
    success, message, should_downgrade = crud.heartbeat(
        db, data.license_key, data.organization_token, data.vm_fingerprint
    )
    
    if not success:
        raise HTTPException(status_code=400, detail=message)
    
    return schemas.HeartbeatResponse(
        success=True,
        message=message,
        should_downgrade=should_downgrade
    )

@router.post("/consume", response_model=schemas.ValidationResponse)
def consume_operation(
    data: schemas.OperationConsume,
    db: Session = Depends(get_db),
    x_timestamp: Optional[str] = Header(None),
    x_signature: Optional[str] = Header(None)
):
    """(asset, discovery, audit, harden, monitor)"""
    # Verify signature
    verify_request_signature(x_timestamp, x_signature, data)
    
    success, message, license = crud.consume_operation(
        db, data.license_key, data.organization_token, data.vm_fingerprint,
        data.operation_type, data.count
    )
    
    if not success:
        raise HTTPException(status_code=400, detail=message)
    
    return schemas.ValidationResponse(
        valid=True,
        message=message,
        plan_type=license.plan_type,
        is_pilot_mode=license.is_pilot_mode,
        limits={
            "max_assets": license.max_assets,
            "max_discoveries": license.max_discoveries,
            "max_audits": license.max_audits,
            "max_hardens": license.max_hardens,
            "max_monitors": license.max_monitors
        },
        usage={
            "used_assets": license.used_assets,
            "used_discoveries": license.used_discoveries,
            "used_audits": license.used_audits,
            "used_hardens": license.used_hardens,
            "used_monitors": license.used_monitors
        }
    )
