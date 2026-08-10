#!/usr/bin/env python3
"""
Test script for License Client SDK

Usage:
    python test_client.py YOUR-LICENSE-KEY-HERE
"""

import sys
import time
from client import LicenseClient, HeartbeatService

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_client.py YOUR-LICENSE-KEY")
        sys.exit(1)
    
    license_key = sys.argv[1]
    server_url = "http://localhost:8000"
    
    print("=" * 60)
    print("License Client SDK Test")
    print("=" * 60)
    
    # Initialize client
    client = LicenseClient(server_url=server_url)
    print(f"\n✓ Client initialized (server: {server_url})")
    
    # Activate license
    print(f"\n[1/5] Activating license...")
    try:
        result = client.activate(license_key)
        print(f"✓ License activated successfully")
        print(f"  - Plan: {result['plan_type']}")
        print(f"  - Organization Token: {result['organization_token'][:20]}...")
        print(f"  - Pilot Mode: {result['is_pilot_mode']}")
    except Exception as e:
        print(f"✗ Activation failed: {e}")
        return
    
    # Validate license
    print(f"\n[2/5] Validating license...")
    try:
        result = client.validate()
        if result['valid']:
            print(f"✓ License is valid")
            print(f"  - Plan: {result['plan_type']}")
            print(f"  - Limits: {result['limits']}")
            print(f"  - Current Usage: {result['usage']}")
        else:
            print(f"✗ License invalid: {result['message']}")
            return
    except Exception as e:
        print(f"✗ Validation failed: {e}")
        return
    
    # Test heartbeat
    print(f"\n[3/5] Testing heartbeat...")
    try:
        result = client.heartbeat()
        print(f"✓ Heartbeat successful: {result['message']}")
        if result.get('should_downgrade'):
            print(f"  ⚠ Warning: License will be downgraded")
    except Exception as e:
        print(f"✗ Heartbeat failed: {e}")
    
    # Consume operations (Asset Management has no license entitlement, so only
    # audit/harden are valid operation types)
    print(f"\n[4/5] Testing operation consumption...")
    operations = ["audit", "harden"]
    
    for op in operations:
        try:
            result = client.consume(operation_type=op, count=1)
            if result['valid']:
                print(f"✓ {op.capitalize()} operation consumed")
            else:
                print(f"✗ {op.capitalize()} failed: {result['message']}")
        except Exception as e:
            print(f"✗ {op.capitalize()} error: {e}")
    
    # Start heartbeat service
    print(f"\n[5/5] Starting background heartbeat service...")
    heartbeat = HeartbeatService(client, interval_seconds=60)
    heartbeat.start()
    print(f"✓ Heartbeat service started (interval: 60s)")
    
    print(f"\n{'=' * 60}")
    print("All tests completed successfully!")
    print("Heartbeat running... (will stop in 10 seconds)")
    print("=" * 60)
    
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    finally:
        heartbeat.stop()
        print("✓ Heartbeat service stopped")

if __name__ == "__main__":
    main()
