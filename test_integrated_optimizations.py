"""
Test Integrated Optimizations

Verifies that optimizations work correctly in the main service files.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from app.core.database import SessionLocal
from app.modules.hardening.service import HardeningService
from app.modules.audit.service import AuditService
import time


def print_header(text):
    print(f"\n{'=' * 80}")
    print(f"  {text}")
    print('=' * 80)


def print_test(num, name):
    print(f"\n{num}. {name}")
    print('-' * 80)


def test_hardening_optimizations():
    """Test hardening service optimizations."""
    print_header("HARDENING SERVICE OPTIMIZATIONS")

    print_test(1, "Configuration Constants")
    assert hasattr(HardeningService, 'MAX_RETRIES'), "Missing MAX_RETRIES"
    assert hasattr(HardeningService, 'RETRY_DELAY'), "Missing RETRY_DELAY"
    assert hasattr(HardeningService, 'BATCH_SIZE'), "Missing BATCH_SIZE"
    print(f"   MAX_RETRIES: {HardeningService.MAX_RETRIES}")
    print(f"   RETRY_DELAY: {HardeningService.RETRY_DELAY}s")
    print(f"   BATCH_SIZE: {HardeningService.BATCH_SIZE}")
    print("   ✓ Constants configured")

    print_test(2, "Timed Operation Context Manager")
    assert hasattr(HardeningService, '_timed_operation'), "Missing _timed_operation"

    with HardeningService._timed_operation("Test operation"):
        time.sleep(0.1)

    print("   ✓ Context manager working")

    print_test(3, "Retry Method")
    assert hasattr(HardeningService, 'execute_hardening_with_retry'), "Missing execute_hardening_with_retry"
    print("   ✓ Retry method exists")

    print_test(4, "Statistics Method")
    assert hasattr(HardeningService, 'get_action_statistics'), "Missing get_action_statistics"

    db = SessionLocal()
    try:
        stats = HardeningService.get_action_statistics(db=db)
        print(f"   Total actions: {stats['total_actions']}")
        print(f"   By status: {stats['by_status']}")
        print(f"   Success rate: {stats['success_rate']}%")
        print("   ✓ Statistics method working")
    finally:
        db.close()


def test_audit_optimizations():
    """Test audit service optimizations."""
    print_header("AUDIT SERVICE OPTIMIZATIONS")

    print_test(1, "Configuration Constants")
    assert hasattr(AuditService, 'CACHE_TTL'), "Missing CACHE_TTL"
    assert hasattr(AuditService, 'BATCH_SIZE'), "Missing BATCH_SIZE"
    assert hasattr(AuditService, 'MAX_RETRIES'), "Missing MAX_RETRIES"
    assert hasattr(AuditService, 'RETRY_DELAY'), "Missing RETRY_DELAY"
    print(f"   CACHE_TTL: {AuditService.CACHE_TTL}s ({AuditService.CACHE_TTL / 3600}h)")
    print(f"   BATCH_SIZE: {AuditService.BATCH_SIZE}")
    print(f"   MAX_RETRIES: {AuditService.MAX_RETRIES}")
    print(f"   RETRY_DELAY: {AuditService.RETRY_DELAY}s")
    print("   ✓ Constants configured")

    print_test(2, "Cache Infrastructure")
    assert hasattr(AuditService, '_rules_cache'), "Missing _rules_cache"
    assert hasattr(AuditService, '_cache_timestamp'), "Missing _cache_timestamp"
    assert isinstance(AuditService._rules_cache, dict), "_rules_cache should be dict"
    assert isinstance(AuditService._cache_timestamp, dict), "_cache_timestamp should be dict"
    print("   ✓ Cache infrastructure present")

    print_test(3, "Timed Operation Context Manager")
    assert hasattr(AuditService, '_timed_operation'), "Missing _timed_operation"

    with AuditService._timed_operation("Test operation"):
        time.sleep(0.1)

    print("   ✓ Context manager working")

    print_test(4, "Cached Rules Method")
    assert hasattr(AuditService, '_get_cached_rules'), "Missing _get_cached_rules"

    # Clear cache
    AuditService._rules_cache.clear()
    AuditService._cache_timestamp.clear()

    # First call - builds cache
    start = time.time()
    rules_1 = AuditService._get_cached_rules("L1")
    first_time = time.time() - start

    print(f"   First call (build): {first_time:.3f}s")
    print(f"   Rules loaded: {len(rules_1)}")

    # Second call - from cache
    start = time.time()
    rules_2 = AuditService._get_cached_rules("L1")
    second_time = time.time() - start

    print(f"   Second call (cache): {second_time:.3f}s")

    assert rules_1 is rules_2, "Should return cached object"

    speedup = first_time / second_time if second_time > 0 else float('inf')
    print(f"   Speedup: {speedup:.1f}x faster")
    print("   ✓ Caching working")

    print_test(5, "Bulk Insert Method")
    assert hasattr(AuditService, '_bulk_insert_results'), "Missing _bulk_insert_results"
    print("   ✓ Bulk insert method exists")

    print_test(6, "Retry Method")
    assert hasattr(AuditService, 'execute_cisco_audit_with_retry'), "Missing execute_cisco_audit_with_retry"
    print("   ✓ Retry method exists")

    print_test(7, "Statistics Method")
    assert hasattr(AuditService, 'get_audit_statistics'), "Missing get_audit_statistics"

    db = SessionLocal()
    try:
        stats = AuditService.get_audit_statistics(db=db)
        print(f"   Total sessions: {stats['total_sessions']}")
        print(f"   Success rate: {stats['success_rate']}%")
        print(f"   Average compliance: {stats['average_compliance']}%")
        print("   ✓ Statistics method working")
    finally:
        db.close()


def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("  INTEGRATED OPTIMIZATIONS TEST SUITE")
    print("=" * 80)
    print("\nVerifying optimizations in main service files...\n")

    try:
        test_hardening_optimizations()
        test_audit_optimizations()

        print("\n" + "=" * 80)
        print("  TEST SUMMARY")
        print("=" * 80)
        print("\nResults:")
        print("   ✓ Hardening Optimizations        PASSED")
        print("   ✓ Audit Optimizations            PASSED")
        print("\nTotal: 2 test suites")
        print("Passed: 2")
        print("Failed: 0")
        print("\n" + "=" * 80)
        print("  ALL TESTS PASSED! ✓")
        print("  Optimizations integrated successfully!")
        print("=" * 80 + "\n")

    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}\n")
        return 1
    except Exception as e:
        print(f"\n✗ ERROR: {e}\n")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
