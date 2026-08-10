from sqlalchemy.orm import Session
from . import models, schemas
from datetime import datetime, timedelta, timezone
import secrets
import string
import hashlib

def generate_license_key() -> str:
    """generate license key: XXXX-XXXX-XXXX-XXXX"""
    chars = string.ascii_uppercase + string.digits
    parts = [''.join(secrets.choice(chars) for _ in range(4)) for _ in range(4)]
    return '-'.join(parts)

def generate_organization_token(org_name: str, customer_email: str) -> str:
    """generate unique token for each company"""
    unique_string = f"{org_name}:{customer_email}:{secrets.token_hex(16)}"
    return hashlib.sha256(unique_string.encode()).hexdigest()

def get_plan_limits(plan_type: models.PlanType) -> dict:
    """each plan limit

    Asset Management has no license entitlement — only audit and hardening
    operations are quota-gated.
    """
    limits = {
        models.PlanType.PILOT: {
            "max_audits": 2,
            "max_hardens": 2,
            "duration_days": 30
        },
        models.PlanType.PLAN_100: {
            "max_audits": 100,
            "max_hardens": 100,
            "duration_days": 365
        },
        models.PlanType.PLAN_250: {
            "max_audits": 250,
            "max_hardens": 250,
            "duration_days": 365
        },
        models.PlanType.PLAN_500: {
            "max_audits": 500,
            "max_hardens": 500,
            "duration_days": 365
        },
        models.PlanType.UNLIMITED: {
            "max_audits": None,
            "max_hardens": None,
            "duration_days": 365
        }
    }
    return limits.get(plan_type, limits[models.PlanType.PILOT])

def create_license(db: Session, license_data: schemas.LicenseCreate) -> models.License:
    license_key = generate_license_key()
    org_token = generate_organization_token(license_data.organization_name, license_data.customer_email)
    
    limits = get_plan_limits(license_data.plan_type)
    expires_at = datetime.now(timezone.utc) + timedelta(days=limits["duration_days"])
    
    db_license = models.License(
        license_key=license_key,
        organization_token=org_token,
        customer_name=license_data.customer_name,
        customer_email=license_data.customer_email,
        organization_name=license_data.organization_name,
        plan_type=license_data.plan_type,
        max_audits=limits["max_audits"],
        max_hardens=limits["max_hardens"],
        expires_at=expires_at,
        is_pilot_mode=(license_data.plan_type == models.PlanType.PILOT)
    )
    
    db.add(db_license)
    db.commit()
    db.refresh(db_license)
    return db_license

def get_license_by_key(db: Session, license_key: str) -> models.License:
    return db.query(models.License).filter(models.License.license_key == license_key).first()

def get_license_by_token(db: Session, org_token: str) -> models.License:
    return db.query(models.License).filter(models.License.organization_token == org_token).first()

def activate_license(db: Session, license_key: str, vm_fingerprint: str) -> tuple[bool, str, models.License]:
    license = get_license_by_key(db, license_key)
    
    if not license:
        return False, "license key not found", None
    
    if not license.is_active:
        return False, "license is deactivate", None
    
    if license.expires_at < datetime.now(timezone.utc):
        return False, "license is expierd", None
    
    # چک VM fingerprint - فقط یک ماشین مجاز
    if license.vm_fingerprint and license.vm_fingerprint != vm_fingerprint:
        return False, "this license already activate in another VM", None
    
    if not license.vm_fingerprint:
        license.vm_fingerprint = vm_fingerprint
        license.activated_at = datetime.now(timezone.utc)
        license.last_heartbeat_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(license)
    
    return True, "license activate successfully", license

def validate_license(db: Session, license_key: str, org_token: str, vm_fingerprint: str) -> tuple[bool, str, models.License]:
    license = get_license_by_key(db, license_key)
    
    if not license:
        return False, "license key not found", None
    
    if license.organization_token != org_token:
        return False, "company token is invalid", None
    
    if not license.is_active:
        return False, "license is deactive", None
    
    if license.expires_at < datetime.now(timezone.utc):
        return False, "license has expierd", None
    
    if license.vm_fingerprint != vm_fingerprint:
        return False, "VM fingerprint is not match", None
    
    # چک heartbeat - اگر بیش از 48 ساعت قطع بود
    if license.last_heartbeat_at:
        time_since_last = datetime.now(timezone.utc) - license.last_heartbeat_at
        if time_since_last > timedelta(hours=48):
            # تبدیل به Pilot
            downgrade_to_pilot(db, license)
            return False, "لایسنس به دلیل قطع ارتباط به حالت Pilot تبدیل شد", license
    
    license.last_validated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(license)
    
    return True, "invalid license", license

def heartbeat(db: Session, license_key: str, org_token: str, vm_fingerprint: str) -> tuple[bool, str, bool]:
    """چک روزانه - باید هر روز صدا زده شود"""
    license = get_license_by_key(db, license_key)
    
    if not license:
        return False, "license key has not found", False
    
    if license.organization_token != org_token or license.vm_fingerprint != vm_fingerprint:
        return False, "faild to authintication", False
    
    # چک آیا باید downgrade شود
    should_downgrade = False
    if license.last_heartbeat_at:
        time_since_last = datetime.now(timezone.utc) - license.last_heartbeat_at
        if time_since_last > timedelta(hours=48):
            downgrade_to_pilot(db, license)
            should_downgrade = True
    
    license.last_heartbeat_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(license)
    
    return True, "Heartbeat is ok", should_downgrade

def downgrade_to_pilot(db: Session, license: models.License):
    """convert license to Pilot"""
    pilot_limits = get_plan_limits(models.PlanType.PILOT)
    
    license.is_pilot_mode = True
    license.plan_type = models.PlanType.PILOT
    license.max_audits = pilot_limits["max_audits"]
    license.max_hardens = pilot_limits["max_hardens"]

    db.commit()

def consume_operation(db: Session, license_key: str, org_token: str, vm_fingerprint: str,
                     operation_type: str, count: int) -> tuple[bool, str, models.License]:
    """مصرف عملیات (audit, harden)"""

    valid, message, license = validate_license(db, license_key, org_token, vm_fingerprint)

    if not valid:
        return False, message, None

    operation_map = {
        "audit": ("max_audits", "used_audits"),
        "harden": ("max_hardens", "used_hardens"),
    }
    
    if operation_type not in operation_map:
        return False, "Operation is invalid", None
    
    max_field, used_field = operation_map[operation_type]
    max_value = getattr(license, max_field)
    used_value = getattr(license, used_field)

    # چک محدودیت (None = نامحدود)
    # Only enforce the ceiling for capped plans. The usage counter is always
    # incremented — including the Unlimited plan, where max_value is None —
    # so the frontend can report real usage instead of a frozen 0.
    if max_value is not None and used_value + count > max_value:
        return False, f"limit {operation_type} has expierd", license

    setattr(license, used_field, used_value + count)
    db.commit()
    db.refresh(license)

    return True, "operation successfully", license

def get_all_licenses(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.License).offset(skip).limit(limit).all()

def deactivate_license(db: Session, license_key: str) -> bool:
    license = get_license_by_key(db, license_key)
    if license:
        license.is_active = False
        db.commit()
        return True
    return False

def delete_license(db: Session, license_key: str) -> bool:
    """Permanently remove a license row from the database.

    Unlike deactivate_license (which only flips is_active to False), this
    hard-deletes the record. Intended for cleaning up legacy/obsolete
    licenses that no longer need to be retained.
    """
    license = get_license_by_key(db, license_key)
    if license:
        db.delete(license)
        db.commit()
        return True
    return False
