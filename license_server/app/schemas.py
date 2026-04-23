from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional
from .models import PlanType

class LicenseCreate(BaseModel):
    customer_name: str
    customer_email: EmailStr
    organization_name: str
    plan_type: PlanType

class LicenseActivate(BaseModel):
    license_key: str
    vm_fingerprint: str

class LicenseValidate(BaseModel):
    license_key: str
    organization_token: str
    vm_fingerprint: str

class OperationConsume(BaseModel):
    license_key: str
    organization_token: str
    vm_fingerprint: str
    operation_type: str  # "asset", "discovery", "audit", "harden", "monitor"
    count: int = 1

class LicenseResponse(BaseModel):
    id: int
    license_key: str
    organization_token: str
    customer_name: str
    customer_email: str
    organization_name: str
    plan_type: PlanType
    
    max_assets: Optional[int]
    max_discoveries: Optional[int]
    max_audits: Optional[int]
    max_hardens: Optional[int]
    max_monitors: Optional[int]
    
    used_assets: int
    used_discoveries: int
    used_audits: int
    used_hardens: int
    used_monitors: int
    
    vm_fingerprint: Optional[str]
    is_active: bool
    is_pilot_mode: bool
    
    created_at: datetime
    activated_at: Optional[datetime]
    expires_at: datetime
    last_validated_at: Optional[datetime]
    last_heartbeat_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class ValidationResponse(BaseModel):
    valid: bool
    message: str
    plan_type: Optional[PlanType] = None
    is_pilot_mode: bool = False
    limits: Optional[dict] = None
    usage: Optional[dict] = None
    organization_token: Optional[str] = None

class HeartbeatResponse(BaseModel):
    success: bool
    message: str
    should_downgrade: bool = False
