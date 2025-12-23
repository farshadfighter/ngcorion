"""
Test Auto-Hardening Feature

Tests the new standalone auto-hardening workflow without a real Cisco device.
Uses mocked audit results to verify categorization and workflow logic.
"""

import sys
import os

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from app.models import User, Asset, AuditSession, AuditResult
from app.models.audit import DeviceType, CheckStatus
from app.core.database import SessionLocal
from app.modules.hardening.service import HardeningService
from datetime import datetime, timezone


def print_section(title):
    """Print a section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def test_categorization():
    """Test failure categorization into fixable and unfixable."""
    print_section("TEST 1: Failure Categorization")

    db = SessionLocal()
    try:
        # Get admin user
        print("\n1. Getting admin user...")
        user = db.query(User).filter(User.username == "admin").first()
        if not user:
            print("   ✗ Admin user not found. Please create it first.")
            return
        print(f"   ✓ Found user: {user.username} (ID: {user.id})")

        # Get or create test asset
        print("\n2. Getting test asset...")
        asset = db.query(Asset).filter(Asset.asset_name == "Test-Cisco-Router").first()
        if not asset:
            asset = Asset(
                asset_name="Test-Cisco-Router",
                hostname="test-router",
                ip_address="192.168.1.100",
                asset_type_id=1
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)
            print(f"   ✓ Created asset: {asset.asset_name} (ID: {asset.id})")
        else:
            print(f"   ✓ Found asset: {asset.asset_name} (ID: {asset.id})")

        # Create mock audit session
        print("\n3. Creating mock audit session...")
        session = AuditSession(
            template_id=None,
            user_id=user.id,
            asset_id=asset.id,
            target_ip=asset.ip_address,
            device_type=DeviceType.CISCO,
            status="completed",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            total_checks=26,
            passed_checks=20,
            failed_checks=6,
            error_checks=0,
            compliance_pct=76.9
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        print(f"   ✓ Created audit session (ID: {session.id})")

        # Create failed results with different characteristics
        print("\n4. Creating mock failed audit results...")

        # Fixable: SSH version 2 (no parameters needed)
        result1 = AuditResult(
            session_id=session.id,
            check_number="IOS-L1-007",
            check_title="SSH version 2 enabled",
            severity="medium",
            level="L1",
            status=CheckStatus.FAIL,
            evidence_snippet="ip ssh version 1",
            checked_at=datetime.now(timezone.utc)
        )
        db.add(result1)

        # Fixable: Disable CDP (no parameters needed)
        result2 = AuditResult(
            session_id=session.id,
            check_number="IOS-L1-018",
            check_title="Disable CDP globally",
            severity="low",
            level="L1",
            status=CheckStatus.FAIL,
            evidence_snippet="cdp run",
            checked_at=datetime.now(timezone.utc)
        )
        db.add(result2)

        # Unfixable: Enable secret (requires STRONG_SECRET parameter)
        result3 = AuditResult(
            session_id=session.id,
            check_number="IOS-L1-001",
            check_title="Use 'enable secret' only",
            severity="high",
            level="L1",
            status=CheckStatus.FAIL,
            evidence_snippet="enable password cisco123",
            checked_at=datetime.now(timezone.utc)
        )
        db.add(result3)

        # Fixable: Password encryption (no parameters needed)
        result4 = AuditResult(
            session_id=session.id,
            check_number="IOS-L1-010",
            check_title="Enable password encryption",
            severity="medium",
            level="L1",
            status=CheckStatus.FAIL,
            evidence_snippet="",
            checked_at=datetime.now(timezone.utc)
        )
        db.add(result4)

        # Unfixable: VTY access-class (requires ACL_NUMBER parameter)
        result5 = AuditResult(
            session_id=session.id,
            check_number="IOS-L1-003",
            check_title="Configure VTY access-class",
            severity="high",
            level="L1",
            status=CheckStatus.FAIL,
            evidence_snippet="",
            checked_at=datetime.now(timezone.utc)
        )
        db.add(result5)

        db.commit()
        print(f"   ✓ Created 5 failed audit results")

        # Test categorization
        print("\n5. Testing categorization logic...")
        failed_results = db.query(AuditResult).filter(
            AuditResult.session_id == session.id,
            AuditResult.status == CheckStatus.FAIL
        ).all()

        categorized = HardeningService._categorize_failures(failed_results, None)

        print(f"   ✓ Total failures: {len(failed_results)}")
        print(f"   ✓ Fixable: {len(categorized['fixable'])}")
        print(f"   ✓ Unfixable: {len(categorized['unfixable'])}")

        print("\n   Fixable checks:")
        for item in categorized['fixable']:
            print(f"      - {item['check_number']}: {item['check_title']}")

        print("\n   Unfixable checks:")
        for item in categorized['unfixable']:
            print(f"      - {item['check_number']}: {item['check_title']}")
            print(f"        Missing params: {item['missing_params']}")

        # Verify expected results
        assert len(categorized['fixable']) == 3, "Expected 3 fixable checks"
        assert len(categorized['unfixable']) == 2, "Expected 2 unfixable checks"

        fixable_checks = {item['check_number'] for item in categorized['fixable']}
        assert 'IOS-L1-007' in fixable_checks, "SSH v2 should be fixable"
        assert 'IOS-L1-018' in fixable_checks, "CDP disable should be fixable"
        assert 'IOS-L1-010' in fixable_checks, "Password encryption should be fixable"

        unfixable_checks = {item['check_number'] for item in categorized['unfixable']}
        assert 'IOS-L1-001' in unfixable_checks, "Enable secret should be unfixable"
        assert 'IOS-L1-003' in unfixable_checks, "VTY access-class should be unfixable"

        print("\n   ✓ Categorization logic verified!")

    finally:
        db.close()


def test_categorization_with_params():
    """Test categorization when parameters are provided."""
    print_section("TEST 2: Categorization with Parameters")

    db = SessionLocal()
    try:
        print("\n1. Finding audit session with unfixable checks...")

        # Get most recent session
        session = db.query(AuditSession).order_by(
            AuditSession.started_at.desc()
        ).first()

        if not session:
            print("   ✗ No audit session found. Run TEST 1 first.")
            return

        print(f"   ✓ Found session {session.id}")

        # Get failed results
        failed_results = db.query(AuditResult).filter(
            AuditResult.session_id == session.id,
            AuditResult.status == CheckStatus.FAIL
        ).all()

        print(f"   ✓ Found {len(failed_results)} failed checks")

        # Test categorization WITHOUT parameters
        print("\n2. Categorization without parameters:")
        categorized_no_params = HardeningService._categorize_failures(failed_results, None)
        print(f"   - Fixable: {len(categorized_no_params['fixable'])}")
        print(f"   - Unfixable: {len(categorized_no_params['unfixable'])}")

        # Test categorization WITH parameters
        print("\n3. Categorization with parameters:")
        parameters = {
            "STRONG_SECRET": "MySecret123!",
            "ACL_NUMBER": "99"
        }
        categorized_with_params = HardeningService._categorize_failures(
            failed_results,
            parameters
        )
        print(f"   - Fixable: {len(categorized_with_params['fixable'])}")
        print(f"   - Unfixable: {len(categorized_with_params['unfixable'])}")

        # Verify that providing parameters makes more checks fixable
        assert len(categorized_with_params['fixable']) > len(categorized_no_params['fixable']), \
            "Providing parameters should make more checks fixable"

        print("\n   ✓ Parameter handling verified!")
        print(f"   ✓ {len(categorized_with_params['fixable']) - len(categorized_no_params['fixable'])} more checks fixable with parameters")

    finally:
        db.close()


def test_check_fixable_helper():
    """Test the _is_check_fixable helper method."""
    print_section("TEST 3: Check Fixable Helper Method")

    print("\n1. Testing checks without parameters:")

    # Check with template, no params required
    is_fixable, missing = HardeningService._is_check_fixable("IOS-L1-007")
    print(f"   IOS-L1-007 (SSH v2): fixable={is_fixable}, missing={missing}")
    assert is_fixable == True, "SSH v2 should be fixable"
    assert missing == [], "SSH v2 should have no missing params"

    # Check with template, params required
    is_fixable, missing = HardeningService._is_check_fixable("IOS-L1-001")
    print(f"   IOS-L1-001 (Enable secret): fixable={is_fixable}, missing={missing}")
    assert is_fixable == False, "Enable secret should not be fixable without params"
    assert "STRONG_SECRET" in missing, "Enable secret should require STRONG_SECRET"

    # Check without template
    is_fixable, missing = HardeningService._is_check_fixable("IOS-L1-999")
    print(f"   IOS-L1-999 (No template): fixable={is_fixable}, missing={missing}")
    assert is_fixable == False, "Non-existent check should not be fixable"
    assert "NO_TEMPLATE" in missing, "Should indicate no template"

    print("\n2. Testing checks with provided parameters:")

    # Check with params, params provided
    params = {"STRONG_SECRET": "Pass123!"}
    is_fixable, missing = HardeningService._is_check_fixable("IOS-L1-001", params)
    print(f"   IOS-L1-001 with params: fixable={is_fixable}, missing={missing}")
    assert is_fixable == True, "Enable secret should be fixable with params"
    assert missing == [], "Should have no missing params"

    # Check with params, wrong params provided
    params = {"WRONG_PARAM": "value"}
    is_fixable, missing = HardeningService._is_check_fixable("IOS-L1-001", params)
    print(f"   IOS-L1-001 with wrong params: fixable={is_fixable}, missing={missing}")
    assert is_fixable == False, "Enable secret should not be fixable with wrong params"
    assert "STRONG_SECRET" in missing, "Should still require STRONG_SECRET"

    print("\n   ✓ All helper method tests passed!")


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("  AUTO-HARDENING FEATURE - TEST SUITE")
    print("=" * 70)
    print("\nThis test suite validates the new auto-hardening categorization logic.")
    print("Tests check fixable detection, parameter handling, and workflow helpers.")

    try:
        # Test 1: Basic categorization
        test_categorization()

        # Test 2: Categorization with parameters
        test_categorization_with_params()

        # Test 3: Helper method
        test_check_fixable_helper()

        # Summary
        print_section("TEST SUMMARY")
        print("\n✓ All tests completed successfully!")
        print("\nTest Results:")
        print("   ✓ Failure Categorization: PASSED")
        print("   ✓ Parameter Handling: PASSED")
        print("   ✓ Helper Methods: PASSED")

        print("\n" + "=" * 70)
        print("  The auto-hardening categorization logic is working correctly!")
        print("=" * 70)

    except Exception as e:
        print(f"\n\n✗ Test suite failed with error:")
        print(f"   {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
