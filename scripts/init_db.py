"""
Database Initialization Script for NETEASE
==========================================
This script:
1. Creates all database tables
2. Creates the first admin user. Its password is taken from
   NGCORION_ADMIN_PASSWORD, or generated at random and printed once; it must
   pass the same password policy as every other account. There is no
   built-in default password.
3. Creates default asset types (the network zones come from the migrations)
4. Sets up admin permissions

Run from the project root, after `alembic upgrade head`:
    NGCORION_ADMIN_PASSWORD='...' uv run python scripts/init_db.py
"""

import sys
import os

# The project root (this file lives in scripts/), so `app` imports resolve.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import engine, Base, SessionLocal
from app.models import (
    User, UserPermission, LoginLog,
    Asset, AssetType, AssetOwner, AssetLocation,
    AssetDependency, AssetSecurityStatus,
    OSCatalog, VendorCatalog
)
from app.models.user import UserRole
from app.schemas.user import validate_password_strength
import bcrypt
import secrets
import string


def _admin_password() -> str:
    """NGCORION_ADMIN_PASSWORD, or a random password that meets the policy
    (upper, lower, digit, special, 20 characters)."""
    given = os.environ.get("NGCORION_ADMIN_PASSWORD")
    if given:
        return validate_password_strength(given)
    alphabet = string.ascii_letters + string.digits + "!@#%^*-_=+"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(20))
        try:
            return validate_password_strength(candidate)
        except ValueError:
            continue


def create_tables():
    """Create all database tables"""
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("✓ All tables created successfully!")


def create_admin_user(db):
    """Create default admin user"""
    print("\nCreating admin user...")
    
    # Check if admin already exists
    existing_admin = db.query(User).filter(User.username == "admin").first()
    if existing_admin:
        print("✓ Admin user already exists (skipping)")
        return existing_admin
    
    password = _admin_password()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Create admin user
    admin = User(
        username="admin",
        email="admin@netease.local",
        hashed_password=hashed_password,
        role=UserRole.ADMIN,
        is_active=True,
        # Whoever ran this script knows the password; the admin picks their own
        # at the first login.
        must_change_password=True,
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)
    
    print(f"✓ Admin user created!")
    print("  Username: admin")
    if os.environ.get("NGCORION_ADMIN_PASSWORD"):
        print("  Password: the one given in NGCORION_ADMIN_PASSWORD")
    else:
        print(f"  Password: {password}")
        print("  (generated now and shown only this once - store it safely or change it after the first login)")
    print("  Role: admin")
    
    return admin


def create_admin_permissions(db, admin_user):
    """Create full permissions for admin"""
    print("\nSetting up admin permissions...")
    
    # Check if permissions already exist
    existing = db.query(UserPermission).filter(UserPermission.user_id == admin_user.id).first()
    if existing:
        print("✓ Admin permissions already exist (skipping)")
        return
    
    modules = [
        'dashboard',
        'asset_requirement',
        'asset_list',
        'asset_auto_discovery',
        'user_management',
        'auditing',
        'hardening',
        'logs'
    ]
    
    for module in modules:
        permission = UserPermission(
            user_id=admin_user.id,
            module=module,
            can_read=True,
            can_write=True,
            can_delete=True
        )
        db.add(permission)
    
    db.commit()
    print(f"✓ Admin permissions created for {len(modules)} modules")


def create_default_asset_types(db):
    """Create default asset types"""
    print("\nCreating default asset types...")
    
    # Check if asset types already exist
    existing = db.query(AssetType).first()
    if existing:
        print("✓ Asset types already exist (skipping)")
        return
    
    asset_types = [
        {"type_name": "Firewall", "category": "Security", "description": "Network firewall device"},
        {"type_name": "Router", "category": "Network", "description": "Network router"},
        {"type_name": "Switch", "category": "Network", "description": "Network switch"},
        {"type_name": "Server", "category": "Compute", "description": "Physical or virtual server"},
        {"type_name": "Workstation", "category": "Endpoint", "description": "Desktop computer"},
        {"type_name": "Laptop", "category": "Endpoint", "description": "Laptop computer"},
        {"type_name": "Access Point", "category": "Network", "description": "Wireless access point"},
        {"type_name": "Storage", "category": "Storage", "description": "Storage device (NAS/SAN)"},
        {"type_name": "Printer", "category": "Peripheral", "description": "Network printer"},
        {"type_name": "IP Phone", "category": "Communication", "description": "VoIP phone"},
    ]
    
    for at in asset_types:
        asset_type = AssetType(**at)
        db.add(asset_type)
    
    db.commit()
    print(f"✓ Created {len(asset_types)} default asset types")


def create_default_os_catalog(db):
    """Create default OS catalog entries"""
    print("\nCreating default OS catalog...")
    
    existing = db.query(OSCatalog).first()
    if existing:
        print("✓ OS catalog already exists (skipping)")
        return
    
    os_list = [
        {"os_name": "Windows Server", "os_version": "2022", "os_family": "Windows"},
        {"os_name": "Windows Server", "os_version": "2019", "os_family": "Windows"},
        {"os_name": "Windows", "os_version": "11", "os_family": "Windows"},
        {"os_name": "Windows", "os_version": "10", "os_family": "Windows"},
        {"os_name": "Ubuntu", "os_version": "22.04 LTS", "os_family": "Linux"},
        {"os_name": "Ubuntu", "os_version": "20.04 LTS", "os_family": "Linux"},
        {"os_name": "CentOS", "os_version": "8", "os_family": "Linux"},
        {"os_name": "Red Hat Enterprise Linux", "os_version": "9", "os_family": "Linux"},
        {"os_name": "Cisco IOS", "os_version": "15.x", "os_family": "Network OS"},
        {"os_name": "FortiOS", "os_version": "7.x", "os_family": "Security OS"},
    ]
    
    for os_item in os_list:
        os_entry = OSCatalog(**os_item)
        db.add(os_entry)
    
    db.commit()
    print(f"✓ Created {len(os_list)} default OS entries")


def create_default_vendors(db):
    """Create default vendor catalog"""
    print("\nCreating default vendor catalog...")
    
    existing = db.query(VendorCatalog).first()
    if existing:
        print("✓ Vendor catalog already exists (skipping)")
        return
    
    vendors = [
        {"vendor_name": "Cisco", "vendor_type": "Network"},
        {"vendor_name": "Fortinet", "vendor_type": "Security"},
        {"vendor_name": "HP", "vendor_type": "Hardware"},
        {"vendor_name": "Dell", "vendor_type": "Hardware"},
        {"vendor_name": "Lenovo", "vendor_type": "Hardware"},
        {"vendor_name": "Microsoft", "vendor_type": "Software"},
        {"vendor_name": "VMware", "vendor_type": "Virtualization"},
        {"vendor_name": "Juniper", "vendor_type": "Network"},
        {"vendor_name": "Palo Alto", "vendor_type": "Security"},
        {"vendor_name": "Aruba", "vendor_type": "Network"},
    ]
    
    for v in vendors:
        vendor = VendorCatalog(**v)
        db.add(vendor)
    
    db.commit()
    print(f"✓ Created {len(vendors)} default vendors")


def main():
    print("=" * 50)
    print("NETEASE Database Initialization")
    print("=" * 50)
    
    # Create tables
    create_tables()
    
    # Create session
    db = SessionLocal()
    
    try:
        # Create admin user
        admin = create_admin_user(db)
        
        # Create admin permissions
        create_admin_permissions(db, admin)
        
        # Create default data
        create_default_asset_types(db)
        create_default_os_catalog(db)
        create_default_vendors(db)
        
        print("\n" + "=" * 50)
        print("✓ Database initialization complete!")
        print("=" * 50)
        print("\nSign in as 'admin' with the password shown above; you will be")
        print("asked to choose your own password at the first login.")
        print("=" * 50)
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
