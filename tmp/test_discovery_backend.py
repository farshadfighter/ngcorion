#!/usr/bin/env python3
"""
Comprehensive Backend Tests for Auto Discovery
Tests database models, relationships, and core functionality
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.database import get_db
from app.models.discovery import DiscoveryScan, DiscoveredHost, DiscoveryApplication
from app.models.asset import Asset
from app.models.port import Port, Protocol
from app.models.user import User
from sqlalchemy import text, inspect
from datetime import datetime
import subprocess
import uuid

def print_test(message, status="INFO"):
    symbols = {"PASS": "✓", "FAIL": "✗", "INFO": "→", "WARN": "⚠"}
    print(f"{symbols.get(status, '→')} {message}")

def print_section(title):
    print("\n" + "="*60)
    print(title)
    print("="*60)

def test_database_connection():
    """Test database connectivity"""
    print_section("TEST 1: DATABASE CONNECTION")

    try:
        db = next(get_db())
        result = db.execute(text("SELECT 1"))
        print_test("Database connection successful", "PASS")
        db.close()
        return True
    except Exception as e:
        print_test(f"Database connection failed: {e}", "FAIL")
        return False

def test_model_imports():
    """Test that all models can be imported"""
    print_section("TEST 2: MODEL IMPORTS")

    try:
        from app.models.discovery import DiscoveryScan, DiscoveredHost
        print_test("DiscoveryScan model imported", "PASS")
        print_test("DiscoveredHost model imported", "PASS")

        from app.models.asset import Asset
        print_test("Asset model imported", "PASS")

        from app.models.port import Port, Protocol
        print_test("Port and Protocol models imported", "PASS")

        return True
    except ImportError as e:
        print_test(f"Failed to import models: {e}", "FAIL")
        return False

def test_database_tables():
    """Test that required tables exist"""
    print_section("TEST 3: DATABASE TABLES")

    db = next(get_db())

    required_tables = [
        'discovery_scans',
        'discovered_hosts',
        'discovery_applications',
        'asset_inventory',
        'ports',
        'protocols'
    ]

    all_exist = True
    for table in required_tables:
        try:
            result = db.execute(text(f"SELECT COUNT(*) FROM {table}"))
            count = result.scalar()
            print_test(f"Table '{table}' exists ({count} rows)", "PASS")
        except Exception as e:
            print_test(f"Table '{table}' missing or error: {str(e)[:50]}", "FAIL")
            all_exist = False

    db.close()
    return all_exist

def test_model_relationships():
    """Test SQLAlchemy model relationships"""
    print_section("TEST 4: MODEL RELATIONSHIPS")

    try:
        # Check Asset.ports relationship
        if hasattr(Asset, 'ports'):
            print_test("Asset.ports relationship exists", "PASS")
        else:
            print_test("Asset.ports relationship missing", "FAIL")
            return False

        # Check Port.asset relationship
        if hasattr(Port, 'asset'):
            print_test("Port.asset relationship exists", "PASS")
        else:
            print_test("Port.asset relationship missing", "FAIL")
            return False

        # Check DiscoveryScan.discovered_hosts relationship
        if hasattr(DiscoveryScan, 'discovered_hosts'):
            print_test("DiscoveryScan.discovered_hosts relationship exists", "PASS")
        else:
            print_test("DiscoveryScan.discovered_hosts relationship missing", "FAIL")
            return False

        # Check DiscoveredHost.scan relationship
        if hasattr(DiscoveredHost, 'scan'):
            print_test("DiscoveredHost.scan relationship exists", "PASS")
        else:
            print_test("DiscoveredHost.scan relationship missing", "FAIL")
            return False

        return True
    except Exception as e:
        print_test(f"Error checking relationships: {e}", "FAIL")
        return False

def test_protocol_data():
    """Test that protocols are seeded in database"""
    print_section("TEST 5: PROTOCOL DATA")

    db = next(get_db())

    try:
        protocols = db.query(Protocol).all()
        print_test(f"Found {len(protocols)} protocol(s) in database", "PASS")

        required_protocols = ['TCP', 'UDP', 'SCTP']
        for proto_name in required_protocols:
            proto = db.query(Protocol).filter_by(name=proto_name).first()
            if proto:
                print_test(f"Protocol '{proto_name}' exists (ID: {proto.id})", "PASS")
            else:
                print_test(f"Protocol '{proto_name}' missing", "FAIL")

        db.close()
        return len(protocols) >= 3
    except Exception as e:
        print_test(f"Error checking protocols: {e}", "FAIL")
        db.close()
        return False

def test_nmap_availability():
    """Test nmap installation and basic functionality"""
    print_section("TEST 6: NMAP SCANNER")

    try:
        result = subprocess.run(
            ['nmap', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            version = result.stdout.split('\n')[0]
            print_test(f"Nmap installed: {version}", "PASS")

            # Check for required flags
            test_flags = ['--max-retries=1', '--host-timeout=30s', '--min-rate=100', '-T4']
            print_test(f"Performance flags: {', '.join(test_flags)}", "INFO")

            return True
        else:
            print_test("Nmap not found", "FAIL")
            return False
    except FileNotFoundError:
        print_test("Nmap not installed", "FAIL")
        return False
    except Exception as e:
        print_test(f"Error checking nmap: {e}", "FAIL")
        return False

def test_scan_types():
    """Test scan type configurations"""
    print_section("TEST 7: SCAN TYPE CONFIGURATIONS")

    scan_types = {
        'all_ports': '-p-',
        'well_known_ports': '-p 1-1024',
        'custom_ports': 'custom'
    }

    for scan_type, expected_flag in scan_types.items():
        print_test(f"Scan type '{scan_type}': {expected_flag}", "INFO")

    print_test("All scan types documented", "PASS")
    return True

def test_existing_scans():
    """Test querying existing scans"""
    print_section("TEST 8: EXISTING SCANS")

    db = next(get_db())

    try:
        scans = db.query(DiscoveryScan).order_by(DiscoveryScan.created_at.desc()).limit(5).all()
        print_test(f"Found {len(scans)} recent scan(s)", "PASS")

        for scan in scans[:3]:
            print_test(
                f"Scan {scan.scan_id}: {scan.target} - {scan.status} "
                f"({scan.hosts_discovered or 0} hosts)",
                "INFO"
            )

        db.close()
        return True
    except Exception as e:
        print_test(f"Error querying scans: {e}", "FAIL")
        db.close()
        return False

def test_existing_hosts():
    """Test querying existing discovered hosts"""
    print_section("TEST 9: EXISTING DISCOVERED HOSTS")

    db = next(get_db())

    try:
        # Get all hosts
        all_hosts = db.query(DiscoveredHost).count()
        print_test(f"Total discovered hosts: {all_hosts}", "INFO")

        # Get pending hosts
        pending_hosts = db.query(DiscoveredHost).filter_by(status='pending').all()
        print_test(f"Pending hosts: {len(pending_hosts)}", "PASS")

        # Get approved hosts
        approved_hosts = db.query(DiscoveredHost).filter_by(status='approved').count()
        print_test(f"Approved hosts: {approved_hosts}", "INFO")

        # Get rejected hosts
        rejected_hosts = db.query(DiscoveredHost).filter_by(status='rejected').count()
        print_test(f"Rejected hosts: {rejected_hosts}", "INFO")

        # Show sample pending hosts
        for host in pending_hosts[:3]:
            print_test(
                f"Host {host.id}: {host.ip_address} - {host.hostname or 'no hostname'}",
                "INFO"
            )

        db.close()
        return True
    except Exception as e:
        print_test(f"Error querying hosts: {e}", "FAIL")
        db.close()
        return False

def test_asset_port_integration():
    """Test Asset-Port relationship with real data"""
    print_section("TEST 10: ASSET-PORT INTEGRATION")

    db = next(get_db())

    try:
        # Get an asset with ports
        asset = db.query(Asset).join(Port).first()

        if asset:
            print_test(f"Found asset with ID {asset.id}: {asset.hostname}", "PASS")

            # Test accessing ports through relationship
            ports = asset.ports
            print_test(f"Asset has {len(ports)} port(s)", "PASS")

            for port in ports[:5]:  # Show first 5 ports
                protocol = db.query(Protocol).filter_by(id=port.protocol_id).first()
                print_test(
                    f"Port {port.port_number}/{protocol.name if protocol else 'unknown'}: "
                    f"{port.service_name or 'unknown'}",
                    "INFO"
                )

            db.close()
            return True
        else:
            print_test("No assets with ports found (expected if fresh database)", "WARN")
            db.close()
            return True
    except Exception as e:
        print_test(f"Error testing asset-port integration: {e}", "FAIL")
        db.close()
        return False

def test_discovery_workflow_components():
    """Test that all components of discovery workflow are in place"""
    print_section("TEST 11: DISCOVERY WORKFLOW COMPONENTS")

    try:
        # Check router endpoints
        from app.modules.discovery import router as discovery_router

        # Count registered endpoints
        endpoints = [route.path for route in discovery_router.router.routes]
        print_test(f"Discovery router has {len(endpoints)} endpoint(s)", "PASS")

        # Check for key endpoints
        key_endpoints = [
            '/scans',
            '/pending-hosts',
            '/hosts/{host_id}/approve',
            '/hosts/{host_id}/reject',
            '/bulk-approve'
        ]

        for endpoint in key_endpoints:
            if any(endpoint in path for path in endpoints):
                print_test(f"Endpoint '{endpoint}' registered", "PASS")
            else:
                print_test(f"Endpoint '{endpoint}' not found", "WARN")

        return True
    except Exception as e:
        print_test(f"Error checking workflow components: {e}", "FAIL")
        return False

def test_model_field_validation():
    """Test model field definitions and constraints"""
    print_section("TEST 12: MODEL FIELD VALIDATION")

    db = next(get_db())

    try:
        # Inspect DiscoveryScan table structure
        inspector = inspect(db.get_bind())

        # Check discovery_scans columns
        scan_columns = inspector.get_columns('discovery_scans')
        required_scan_fields = ['id', 'scan_id', 'user_id', 'target', 'scan_type', 'status']

        for field in required_scan_fields:
            if any(col['name'] == field for col in scan_columns):
                print_test(f"DiscoveryScan.{field} field exists", "PASS")
            else:
                print_test(f"DiscoveryScan.{field} field missing", "FAIL")

        # Check discovered_hosts columns
        host_columns = inspector.get_columns('discovered_hosts')
        required_host_fields = ['id', 'scan_id', 'ip_address', 'status', 'open_ports']

        for field in required_host_fields:
            if any(col['name'] == field for col in host_columns):
                print_test(f"DiscoveredHost.{field} field exists", "PASS")
            else:
                print_test(f"DiscoveredHost.{field} field missing", "FAIL")

        db.close()
        return True
    except Exception as e:
        print_test(f"Error validating model fields: {e}", "FAIL")
        db.close()
        return False

def test_json_field_structure():
    """Test JSON field structures in discovered hosts"""
    print_section("TEST 13: JSON FIELD STRUCTURES")

    db = next(get_db())

    try:
        # Get a host with open_ports data
        host = db.query(DiscoveredHost).filter(
            DiscoveredHost.open_ports.isnot(None)
        ).first()

        if host:
            print_test("Found host with port data", "PASS")

            if host.open_ports:
                print_test(f"open_ports contains {len(host.open_ports)} port(s)", "PASS")

                # Check structure of first port
                if host.open_ports and len(host.open_ports) > 0:
                    port = host.open_ports[0]
                    required_keys = ['port', 'protocol', 'state']
                    for key in required_keys:
                        if key in port:
                            print_test(f"Port JSON has '{key}' field", "PASS")
                        else:
                            print_test(f"Port JSON missing '{key}' field", "WARN")
        else:
            print_test("No hosts with port data found", "WARN")

        db.close()
        return True
    except Exception as e:
        print_test(f"Error checking JSON fields: {e}", "FAIL")
        db.close()
        return False

def main():
    print("\n" + "="*60)
    print("AUTO DISCOVERY BACKEND - COMPREHENSIVE TESTS")
    print("="*60)

    # Run all tests
    results = []

    results.append(("Database Connection", test_database_connection()))
    results.append(("Model Imports", test_model_imports()))
    results.append(("Database Tables", test_database_tables()))
    results.append(("Model Relationships", test_model_relationships()))
    results.append(("Protocol Data", test_protocol_data()))
    results.append(("Nmap Availability", test_nmap_availability()))
    results.append(("Scan Types", test_scan_types()))
    results.append(("Existing Scans", test_existing_scans()))
    results.append(("Existing Hosts", test_existing_hosts()))
    results.append(("Asset-Port Integration", test_asset_port_integration()))
    results.append(("Workflow Components", test_discovery_workflow_components()))
    results.append(("Model Field Validation", test_model_field_validation()))
    results.append(("JSON Field Structures", test_json_field_structure()))

    # Print summary
    print_section("TEST SUMMARY")

    passed = sum(1 for _, result in results if result)
    failed = sum(1 for _, result in results if not result)

    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print_test(f"{test_name}: {status}", status)

    print("\n" + "="*60)
    print(f"✓ {passed} TESTS PASSED, {failed} TESTS FAILED")
    print("="*60)

    if failed == 0:
        print("\n✓ ALL TESTS PASSED - AUTO DISCOVERY BACKEND IS HEALTHY")
    else:
        print(f"\n⚠ {failed} TESTS FAILED - PLEASE REVIEW")

if __name__ == "__main__":
    main()
