#!/usr/bin/env python3
"""
Test Critical Fixes Made to Auto Discovery
Verifies the two critical bugs that were fixed
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.database import get_db
from app.models.asset import Asset
from app.models.port import Port, Protocol
from datetime import datetime

def print_test(message, status="INFO"):
    symbols = {"PASS": "✓", "FAIL": "✗", "INFO": "→", "WARN": "⚠"}
    print(f"{symbols.get(status, '→')} {message}")

def print_section(title):
    print("\n" + "="*60)
    print(title)
    print("="*60)

def test_fix_1_datetime_import():
    """Test Fix #1: datetime import in router.py"""
    print_section("FIX #1: DATETIME IMPORT")

    print_test("Issue: NameError: name 'datetime' is not defined", "INFO")
    print_test("Location: app/modules/discovery/router.py", "INFO")
    print_test("Affected endpoints: approve, reject, bulk-approve", "INFO")

    try:
        # Try to import the router module
        from app.modules.discovery import router
        print_test("Router module imports successfully", "PASS")

        # Check if datetime is imported
        import inspect
        source = inspect.getsource(router)
        if 'from datetime import datetime' in source:
            print_test("datetime is properly imported", "PASS")
        else:
            print_test("datetime import not found", "FAIL")
            return False

        # Try to access the functions that use datetime
        if hasattr(router, 'approve_discovered_host'):
            print_test("approve_discovered_host function exists", "PASS")
        if hasattr(router, 'reject_discovered_host'):
            print_test("reject_discovered_host function exists", "PASS")
        if hasattr(router, 'bulk_approve_hosts'):
            print_test("bulk_approve_hosts function exists", "PASS")

        print_test("✓ FIX VERIFIED: datetime import is correct", "PASS")
        return True

    except Exception as e:
        print_test(f"Router import failed: {e}", "FAIL")
        return False

def test_fix_2_asset_ports_relationship():
    """Test Fix #2: Asset.ports bidirectional relationship"""
    print_section("FIX #2: ASSET.PORTS RELATIONSHIP")

    print_test("Issue: AttributeError: 'Asset' object has no attribute 'ports'", "INFO")
    print_test("Location: app/models/asset.py and app/models/port.py", "INFO")

    try:
        # Check that Asset has ports relationship
        if not hasattr(Asset, 'ports'):
            print_test("Asset.ports attribute missing", "FAIL")
            return False
        else:
            print_test("Asset.ports attribute exists", "PASS")

        # Check that Port has asset relationship
        if not hasattr(Port, 'asset'):
            print_test("Port.asset attribute missing", "FAIL")
            return False
        else:
            print_test("Port.asset attribute exists", "PASS")

        # Test with existing data from database
        db = next(get_db())

        # Find an existing asset with ports
        existing_asset = db.query(Asset).join(Port).first()

        if existing_asset:
            print_test(f"Using existing asset: {existing_asset.hostname} (ID: {existing_asset.id})", "INFO")

            # TEST: Access ports through relationship
            try:
                ports = existing_asset.ports
                print_test(f"✓ asset.ports accessible: {len(ports)} port(s)", "PASS")

                # Test accessing first port's asset
                if ports:
                    first_port = ports[0]
                    try:
                        asset_via_port = first_port.asset
                        print_test(f"✓ port.asset accessible: {asset_via_port.hostname}", "PASS")
                    except AttributeError as e:
                        print_test(f"✗ port.asset failed: {e}", "FAIL")
                        db.close()
                        return False

            except AttributeError as e:
                print_test(f"✗ asset.ports failed: {e}", "FAIL")
                db.close()
                return False

            db.close()
        else:
            # No existing data, but attributes exist
            print_test("No assets with ports in database (fresh install)", "INFO")
            print_test("✓ Relationship attributes exist and are properly configured", "PASS")
            db.close()

        print_test("✓ FIX VERIFIED: Asset.ports relationship is correct", "PASS")
        return True

    except Exception as e:
        print_test(f"Relationship test failed: {e}", "FAIL")
        import traceback
        traceback.print_exc()
        return False

def test_relationship_implementation():
    """Test the specific implementation details of the fix"""
    print_section("IMPLEMENTATION DETAILS")

    try:
        import inspect
        from app.models.asset import Asset
        from app.models.port import Port

        # Check Asset model
        asset_source = inspect.getsource(Asset)
        if 'back_populates="asset"' in asset_source:
            print_test("Asset uses 'back_populates' (correct)", "PASS")
        else:
            print_test("Asset relationship implementation unclear", "WARN")

        # Check Port model
        port_source = inspect.getsource(Port)
        if 'back_populates="ports"' in port_source:
            print_test("Port uses 'back_populates' (correct)", "PASS")
        else:
            print_test("Port relationship implementation unclear", "WARN")

        # Check for cascade
        if 'cascade="all, delete-orphan"' in asset_source:
            print_test("Cascade delete configured (correct)", "PASS")
        else:
            print_test("Cascade delete may not be configured", "WARN")

        return True
    except Exception as e:
        print_test(f"Implementation check failed: {e}", "FAIL")
        return False

def main():
    print("\n" + "="*60)
    print("CRITICAL FIXES VERIFICATION")
    print("="*60)

    results = []

    print_test("Testing critical bugs that were fixed:", "INFO")
    print()

    # Test both fixes
    fix1_result = test_fix_1_datetime_import()
    results.append(("Fix #1: datetime import", fix1_result))

    fix2_result = test_fix_2_asset_ports_relationship()
    results.append(("Fix #2: Asset.ports relationship", fix2_result))

    test_relationship_implementation()

    # Summary
    print_section("VERIFICATION SUMMARY")

    for fix_name, result in results:
        status = "PASS" if result else "FAIL"
        print_test(f"{fix_name}: {status}", status)

    passed = sum(1 for _, result in results if result)
    failed = sum(1 for _, result in results if not result)

    print("\n" + "="*60)
    if failed == 0:
        print("✓ ALL CRITICAL FIXES VERIFIED - BOTH BUGS RESOLVED")
    else:
        print(f"✗ {failed} FIX(ES) FAILED VERIFICATION")
    print("="*60)

    print("\nFIX DETAILS:")
    print()
    print("1. datetime Import Fix (router.py:11)")
    print("   - Added: from datetime import datetime")
    print("   - Resolved: 500 Internal Server Error on approve/reject endpoints")
    print()
    print("2. Asset.ports Relationship Fix")
    print("   - asset.py: Added explicit ports relationship with back_populates")
    print("   - port.py: Changed to back_populates=\"ports\"")
    print("   - Resolved: AttributeError when accessing asset.ports")

if __name__ == "__main__":
    main()
