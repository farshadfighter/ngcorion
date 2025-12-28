"""
Script to:
1. Activate the "admin" user (set is_active=True)
2. Create user "man" with admin role and all permissions

Run: python scripts/activate_and_create_users.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal
from app.models import User, UserPermission
from app.models.user import UserRole
from app.models.user_permission import ModuleEnum
import bcrypt


def activate_admin_user(db):
    """Activate the admin user"""
    print("\n1. Activating admin user...")

    admin = db.query(User).filter(User.username == "admin").first()
    if not admin:
        print("   ✗ Admin user not found in database!")
        return None

    if admin.is_active:
        print(f"   ✓ Admin user already active (is_active={admin.is_active})")
    else:
        admin.is_active = True
        db.commit()
        print(f"   ✓ Admin user activated! (is_active={admin.is_active})")

    return admin


def create_man_user(db):
    """Create user 'man' with admin role and all permissions"""
    print("\n2. Creating 'man' user...")

    # Check if user already exists
    existing = db.query(User).filter(User.username == "man").first()
    if existing:
        print(f"   ! User 'man' already exists (id={existing.id})")
        print("   Updating password and ensuring admin role...")

        # Update password
        password = "123456"
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        existing.hashed_password = hashed_password
        existing.role = UserRole.ADMIN
        existing.is_active = True
        db.commit()

        print(f"   ✓ User 'man' updated with admin role and new password")
        return existing

    # Hash password
    password = "123456"
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Create user
    man_user = User(
        username="man",
        email="man@netease.local",
        hashed_password=hashed_password,
        role=UserRole.ADMIN,
        is_active=True
    )
    db.add(man_user)
    db.commit()
    db.refresh(man_user)

    print(f"   ✓ User 'man' created!")
    print(f"     Username: man")
    print(f"     Password: 123456")
    print(f"     Role: ADMIN")
    print(f"     ID: {man_user.id}")

    return man_user


def create_full_permissions(db, user):
    """Create full permissions for a user on all modules"""
    print(f"\n3. Creating full permissions for user '{user.username}'...")

    # Delete existing permissions for this user
    existing_count = db.query(UserPermission).filter(UserPermission.user_id == user.id).delete()
    if existing_count > 0:
        print(f"   Removed {existing_count} existing permission records")

    # Create full permissions for all modules
    modules_created = 0
    for module in ModuleEnum:
        permission = UserPermission(
            user_id=user.id,
            module=module,
            can_read=True,
            can_write=True,
            can_delete=True
        )
        db.add(permission)
        modules_created += 1

    db.commit()
    print(f"   ✓ Created full permissions for {modules_created} modules:")
    for module in ModuleEnum:
        print(f"     - {module.value}: read=True, write=True, delete=True")


def main():
    print("=" * 55)
    print("  NETEASE - Activate Admin & Create Man User")
    print("=" * 55)

    db = SessionLocal()

    try:
        # 1. Activate admin user
        admin = activate_admin_user(db)

        # 2. Create 'man' user
        man_user = create_man_user(db)

        # 3. Create full permissions for 'man' user
        if man_user:
            create_full_permissions(db, man_user)

        print("\n" + "=" * 55)
        print("  ✓ All operations completed successfully!")
        print("=" * 55)
        print("\n  Users ready to login:")
        print("  ┌────────────┬────────────┬────────┐")
        print("  │ Username   │ Password   │ Role   │")
        print("  ├────────────┼────────────┼────────┤")
        print("  │ admin      │ 123456     │ ADMIN  │")
        print("  │ man        │ 123456     │ ADMIN  │")
        print("  └────────────┴────────────┴────────┘")
        print("=" * 55)

    except Exception as e:
        print(f"\n✗ Error: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
