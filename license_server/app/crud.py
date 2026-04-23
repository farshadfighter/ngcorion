#TEST
from sqlalchemy.orm import Session
from . import models, schemas
from datetime import datetime, timedelta
import secrets
import string
import hashlib

def generate_license_key() -> str:
    """تولید کلید لایسنس: XXXX-XXXX-XXXX-XXXX"""
    chars = string.ascii_uppercase + string.digits
    parts = [''.join(secrets.choice(chars) for _ in range(4)) for _ in range(4)]
    return '-'.join(parts)

def generate_organization_token(org_name: str, customer_email: str) -> str:
    """تولید توکن منحصر به فرد برای سازمان"""
    unique_string = f"{org_name}:{customer_email}:{secrets.token_hex(16)}"
    return hashlib.sha256(unique_string.encode()).hexdigest()

def get_plan_limits(plan_type: models.PlanType) -> dict:
    """محدودیت‌های هر پلن"""
    limits = {
        models.PlanType.PILOT: {
            "max_assets": 5,
            "max_discoveries": 2,
            "max_audits": 2,
            "max_hardens": 2,
            "max_monitors": 2,
            "duration_days": 30
        },
        models.PlanType.BASIC1: {
            "max_assets": 15,
            "max_discoveries": 15,
            "max_audits": 15,
            "max_hardens": 15,
            "max_monitors": 15,
            "duration_days": 365
        },
        models.PlanType.BASIC2: {
            "max_assets": 50,
            "max_discoveries": 50,
            "max_audits": 50,
            "max_hardens": 50,
            "max_monitors": 50,
            "duration_days": 365
        },
        models.PlanType.BASIC3: {
            "max_assets": 150,
            "max_discoveries": 150,
            "max_audits": 150,
            "max_hardens": 150,
            "max_monitors": 150,
            "duration_days": 365
        },
        models.PlanType.ENTERPRISE: {
            "max_assets": None,
            "max_discoveries": None,
            "max_audits": None,
            "max_hardens": None,
            "max_monitors": None,
            "duration_days": 365
        }
    }
    return limits.get(plan_type, limits[models.PlanType.PILOT])

def create_license(db: Session, license_data: schemas.LicenseCreate) -> models.License:
    license_key = generate_license_key()
    org_token = generate_organization_token(license_data.organization_name, license_data.customer_email)
    
    limits = get_plan_limits(license_data.plan_type)
    expires_at = datetime.now() + timedelta(days=limits["duration_days"])
    
    db_license = models.License(
        license_key=license_key,
        organization_token=org_token,
        customer_name=license_data.customer_name,
        customer_email=license_data.customer_email,
        organization_name=license_data.organization_name,
        plan_type=license_data.plan_type,
        max_assets=limits["max_assets"],
        max_discoveries=limits["max_discoveries"],
        max_audits=limits["max_audits"],
        max_hardens=limits["max_hardens"],
        max_monitors=limits["max_monitors"],
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
        return False, "کلید لایسنس یافت نشد", None
    
    if not license.is_active:
        return False, "لایسنس غیرفعال است", None
    
    if license.expires_at < datetime.now():
        return False, "لایسنس منقضی شده است", None
    
    # چک VM fingerprint - فقط یک ماشین مجاز
    if license.vm_fingerprint and license.vm_fingerprint != vm_fingerprint:
        return False, "این لایسنس روی ماشین دیگری فعال شده است", None
    
    if not license.vm_fingerprint:
        license.vm_fingerprint = vm_fingerprint
        license.activated_at = datetime.now()
        license.last_heartbeat_at = datetime.now()
        db.commit()
        db.refresh(license)
    
    return True, "لایسنس با موفقیت فعال شد", license

def validate_license(db: Session, license_key: str, org_token: str, vm_fingerprint: str) -> tuple[bool, str, models.License]:
    license = get_license_by_key(db, license_key)
    
    if not license:
        return False, "کلید لایسنس یافت نشد", None
    
    if license.organization_token != org_token:
        return False, "توکن سازمان نامعتبر است", None
    
    if not license.is_active:
        return False, "لایسنس غیرفعال است", None
    
    if license.expires_at < datetime.now():
        return False, "لایسنس منقضی شده است", None
    
    if license.vm_fingerprint != vm_fingerprint:
        return False, "VM fingerprint مطابقت ندارد", None
    
    # چک heartbeat - اگر بیش از 48 ساعت قطع بود
    if license.last_heartbeat_at:
        time_since_last = datetime.now() - license.last_heartbeat_at
        if time_since_last > timedelta(hours=48):
            # تبدیل به Pilot
            downgrade_to_pilot(db, license)
            return False, "لایسنس به دلیل قطع ارتباط به حالت Pilot تبدیل شد", license
    
    license.last_validated_at = datetime.now()
    db.commit()
    db.refresh(license)
    
    return True, "لایسنس معتبر است", license

def heartbeat(db: Session, license_key: str, org_token: str, vm_fingerprint: str) -> tuple[bool, str, bool]:
    """چک روزانه - باید هر روز صدا زده شود"""
    license = get_license_by_key(db, license_key)
    
    if not license:
        return False, "کلید لایسنس یافت نشد", False
    
    if license.organization_token != org_token or license.vm_fingerprint != vm_fingerprint:
        return False, "اطلاعات احراز هویت نامعتبر است", False
    
    # چک آیا باید downgrade شود
    should_downgrade = False
    if license.last_heartbeat_at:
        time_since_last = datetime.now() - license.last_heartbeat_at
        if time_since_last > timedelta(hours=48):
            downgrade_to_pilot(db, license)
            should_downgrade = True
    
    license.last_heartbeat_at = datetime.now()
    db.commit()
    db.refresh(license)
    
    return True, "Heartbeat ثبت شد", should_downgrade

def downgrade_to_pilot(db: Session, license: models.License):
    """تبدیل لایسنس به حالت Pilot"""
    pilot_limits = get_plan_limits(models.PlanType.PILOT)
    
    license.is_pilot_mode = True
    license.plan_type = models.PlanType.PILOT
    license.max_assets = pilot_limits["max_assets"]
    license.max_discoveries = pilot_limits["max_discoveries"]
    license.max_audits = pilot_limits["max_audits"]
    license.max_hardens = pilot_limits["max_hardens"]
    license.max_monitors = pilot_limits["max_monitors"]
    
    db.commit()

def consume_operation(db: Session, license_key: str, org_token: str, vm_fingerprint: str, 
                     operation_type: str, count: int) -> tuple[bool, str, models.License]:
    """مصرف عملیات (asset, discovery, audit, harden, monitor)"""
    
    valid, message, license = validate_license(db, license_key, org_token, vm_fingerprint)
    
    if not valid:
        return False, message, None
    
    operation_map = {
        "asset": ("max_assets", "used_assets"),
        "discovery": ("max_discoveries", "used_discoveries"),
        "audit": ("max_audits", "used_audits"),
        "harden": ("max_hardens", "used_hardens"),
        "monitor": ("max_monitors", "used_monitors")
    }
    
    if operation_type not in operation_map:
        return False, "نوع عملیات نامعتبر است", None
    
    max_field, used_field = operation_map[operation_type]
    max_value = getattr(license, max_field)
    used_value = getattr(license, used_field)
    
    # چک محدودیت (None = نامحدود)
    if max_value is not None:
        if used_value + count > max_value:
            return False, f"محدودیت {operation_type} به پایان رسیده است", license
        
        setattr(license, used_field, used_value + count)
        db.commit()
        db.refresh(license)
    
    return True, "عملیات با موفقیت ثبت شد", license

def get_all_licenses(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.License).offset(skip).limit(limit).all()

def deactivate_license(db: Session, license_key: str) -> bool:
    license = get_license_by_key(db, license_key)
    if license:
        license.is_active = False
        db.commit()
        return True
    return False
