from app.core.database import SessionLocal
from app.models import AssetType, NetworkZone, OSCatalog, VendorCatalog

db = SessionLocal()

try:
    # Asset Types
    types = [
        ("Firewall", "Security"),
        ("Router", "Network"),
        ("Switch", "Network"),
        ("Server", "Infrastructure"),
        ("Endpoint", "Client"),
        ("Access Point", "Network"),
        ("Storage", "Infrastructure"),
        ("Application", "Application"),
        ("Database", "Application"),
        ("Security Appliance", "Security"),
    ]
    
    for name, cat in types:
        if not db.query(AssetType).filter(AssetType.type_name == name).first():
            db.add(AssetType(type_name=name, category=cat))
    
    # Network Zones
    zones = ["DMZ", "Internal", "Management", "Guest", "External"]
    for zone in zones:
        if not db.query(NetworkZone).filter(NetworkZone.zone_name == zone).first():
            db.add(NetworkZone(zone_name=zone))
    
    # OS Catalog
    os_list = [
        ("Windows Server", "2019", "Windows"),
        ("Ubuntu", "22.04", "Linux"),
        ("FortiOS", "7.2", "Network OS"),
    ]
    for name, ver, fam in os_list:
        if not db.query(OSCatalog).filter(OSCatalog.os_name == name, OSCatalog.os_version == ver).first():
            db.add(OSCatalog(os_name=name, os_version=ver, os_family=fam))
    
    # Vendors
    vendors = [
        ("Cisco", "Network"),
        ("HP", "Server"),
        ("Fortinet", "Security"),
    ]
    for name, vtype in vendors:
        if not db.query(VendorCatalog).filter(VendorCatalog.vendor_name == name).first():
            db.add(VendorCatalog(vendor_name=name, vendor_type=vtype))
    
    db.commit()
    print("✅ Seed data inserted!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    db.rollback()
finally:
    db.close()
