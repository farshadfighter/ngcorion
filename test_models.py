"""
Test Models
Quick test to verify models and relationships work
"""

from app.core.database import SessionLocal
from app.models import *

# Create database session
db = SessionLocal()

try:
    # 1. Create AssetType
    asset_type = AssetType(
        type_name="Firewall",
        category="Security",
        description="Network security device"
    )
    db.add(asset_type)
    db.commit()
    print(f"✅ Created AssetType: {asset_type}")
    
    # 2. Get existing user (assuming you have user id=1)
    user = db.query(User).filter(User.id == 1).first()
    if not user:
        print("❌ No user found! Create a user first.")
        exit()
    print(f"✅ Found User: {user.username}")
    
    # 3. Create AssetOwner
    owner = AssetOwner(
        full_name="Ali Rezaei",
        department="Network",
        email="ali@company.com",
        user_id=user.id
    )
    db.add(owner)
    db.commit()
    print(f"✅ Created Owner: {owner}")
    
    # 4. Create Asset
    asset = Asset(
        asset_name="FW-Main",
        hostname="fw-main.local",
        asset_type_id=asset_type.id,
        owner_id=owner.id,
        status=StatusEnum.ACTIVE,
        user_id=user.id
    )
    db.add(asset)
    db.commit()
    print(f"✅ Created Asset: {asset}")
    
    # 5. Test relationships
    print(f"\n🔗 Testing Relationships:")
    print(f"  Asset type: {asset.asset_type.type_name}")
    print(f"  Asset owner: {asset.owner.full_name}")
    print(f"  Asset user: {asset.user.username}")
    
    print("\n✅ All tests passed!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    db.rollback()
    
finally:
    db.close()

