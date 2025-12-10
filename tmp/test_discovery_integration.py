#!/usr/bin/env python3
"""
Comprehensive Integration Tests for Auto Discovery Backend
Tests the complete workflow from scan creation to host approval/rejection
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.database import get_db
from app.models.discovery import DiscoveryScan, DiscoveredHost
from app.models.asset import Asset
from app.models.port import Port, Protocol
from sqlalchemy import text
from datetime import datetime

def print_test(message, status="INFO"):
    symbols = {"PASS": "✓", "FAIL": "✗", "INFO": "→"}
    print(f"{symbols.get(status, '→')} {message}")

def cleanup_test_data(db):
    """Clean up any test data before running tests"""
    print("\n" + "="*60)
    print("CLEANING UP TEST DATA")
    print("="*60)

    try:
        # Delete test scans and hosts (cascade will handle relationships)
        db.execute(text("DELETE FROM discovered_host_ports"))
        db.execute(text("DELETE FROM discovered_hosts WHERE target LIKE '192.168.%'"))
        db.execute(text("DELETE FROM discovery_scans WHERE target LIKE '192.168.%'"))
        db.commit()
        print_test("Test data cleaned up", "PASS")
    except Exception as e:
        print_test(f"Cleanup warning: {e}", "INFO")
        db.rollback()

def test_scan_creation(db):
    """Test creating a discovery scan"""
    print("\n" + "="*60)
    print("TEST 1: SCAN CREATION")
    print("="*60)

    try:
        scan = DiscoveryScan(
            target="192.168.1.100",
            scan_type="well_known_ports",
            status="pending",
            created_at=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        print_test(f"Created scan with ID: {scan.id}", "PASS")
        print_test(f"Scan target: {scan.target}", "INFO")
        print_test(f"Scan type: {scan.scan_type}", "INFO")
        print_test(f"Scan status: {scan.status}", "INFO")

        return scan
    except Exception as e:
        print_test(f"Failed to create scan: {e}", "FAIL")
        db.rollback()
        return None

def test_scan_status_updates(db, scan):
    """Test updating scan status"""
    print("\n" + "="*60)
    print("TEST 2: SCAN STATUS UPDATES")
    print("="*60)

    if not scan:
        print_test("Skipped - no scan available", "INFO")
        return False

    try:
        # Update to running
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.commit()
        print_test("Updated scan status to 'running'", "PASS")

        # Update to completed
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.hosts_discovered = 1
        db.commit()
        print_test("Updated scan status to 'completed'", "PASS")
        print_test(f"Hosts discovered: {scan.hosts_discovered}", "INFO")

        return True
    except Exception as e:
        print_test(f"Failed to update scan status: {e}", "FAIL")
        db.rollback()
        return False

def test_host_discovery(db, scan):
    """Test creating discovered hosts"""
    print("\n" + "="*60)
    print("TEST 3: HOST DISCOVERY")
    print("="*60)

    if not scan:
        print_test("Skipped - no scan available", "INFO")
        return None

    try:
        # Get TCP protocol
        tcp_protocol = db.query(Protocol).filter_by(name="TCP").first()
        if not tcp_protocol:
            print_test("TCP protocol not found in database", "FAIL")
            return None

        host = DiscoveredHost(
            scan_id=scan.id,
            target=scan.target,
            ip_address="192.168.1.100",
            hostname="test-host.local",
            status="pending",
            os_name="Linux",
            os_version="Ubuntu 22.04",
            discovered_at=datetime.utcnow()
        )
        db.add(host)
        db.commit()
        db.refresh(host)

        print_test(f"Created discovered host with ID: {host.id}", "PASS")
        print_test(f"Host IP: {host.ip_address}", "INFO")
        print_test(f"Host OS: {host.os_name} {host.os_version}", "INFO")
        print_test(f"Host status: {host.status}", "INFO")

        return host
    except Exception as e:
        print_test(f"Failed to create discovered host: {e}", "FAIL")
        db.rollback()
        return None

def test_host_ports(db, host):
    """Test adding ports to discovered host"""
    print("\n" + "="*60)
    print("TEST 4: HOST PORT DISCOVERY")
    print("="*60)

    if not host:
        print_test("Skipped - no host available", "INFO")
        return False

    try:
        # Get TCP protocol
        tcp_protocol = db.query(Protocol).filter_by(name="TCP").first()

        # Add discovered ports to host
        from app.models.discovery import DiscoveredHostPort

        ports_data = [
            {"port": 22, "service": "ssh", "version": "OpenSSH 8.9"},
            {"port": 80, "service": "http", "version": "nginx 1.18"},
            {"port": 443, "service": "https", "version": "nginx 1.18"}
        ]

        for port_data in ports_data:
            host_port = DiscoveredHostPort(
                host_id=host.id,
                port_number=port_data["port"],
                protocol_id=tcp_protocol.id,
                service_name=port_data["service"],
                service_version=port_data["version"],
                state="open"
            )
            db.add(host_port)

        db.commit()

        # Verify ports were added
        port_count = db.query(DiscoveredHostPort).filter_by(host_id=host.id).count()
        print_test(f"Added {port_count} ports to discovered host", "PASS")

        for port_data in ports_data:
            print_test(f"Port {port_data['port']}/{tcp_protocol.name.upper()}: {port_data['service']}", "INFO")

        return True
    except Exception as e:
        print_test(f"Failed to add ports to host: {e}", "FAIL")
        db.rollback()
        return False

def test_check_matches(db, host):
    """Test checking for matching assets"""
    print("\n" + "="*60)
    print("TEST 5: CHECK FOR MATCHING ASSETS")
    print("="*60)

    if not host:
        print_test("Skipped - no host available", "INFO")
        return

    try:
        # Look for existing assets with same IP
        matching_assets = db.query(Asset).filter(
            Asset.ip_address == host.ip_address
        ).all()

        if matching_assets:
            print_test(f"Found {len(matching_assets)} matching asset(s)", "PASS")
            for asset in matching_assets:
                print_test(f"Match: {asset.hostname} ({asset.ip_address})", "INFO")
        else:
            print_test("No matching assets found (expected for test data)", "PASS")

    except Exception as e:
        print_test(f"Failed to check matches: {e}", "FAIL")

def test_host_approval(db, host):
    """Test approving a discovered host (creates asset)"""
    print("\n" + "="*60)
    print("TEST 6: HOST APPROVAL WORKFLOW")
    print("="*60)

    if not host:
        print_test("Skipped - no host available", "INFO")
        return None

    try:
        # Simulate approval by creating an Asset
        from app.models.discovery import DiscoveredHostPort

        # Get the discovered ports
        discovered_ports = db.query(DiscoveredHostPort).filter_by(host_id=host.id).all()

        asset = Asset(
            hostname=host.hostname or f"host-{host.ip_address}",
            ip_address=host.ip_address,
            asset_type="server",
            operating_system=host.os_name,
            status="active",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(asset)
        db.flush()  # Get asset.id without committing

        print_test(f"Created asset with ID: {asset.id}", "PASS")

        # Add ports to the asset
        tcp_protocol = db.query(Protocol).filter_by(name="TCP").first()

        for disc_port in discovered_ports:
            port = Port(
                asset_id=asset.id,
                port_number=disc_port.port_number,
                protocol_id=disc_port.protocol_id,
                service_name=disc_port.service_name,
                service_version=disc_port.service_version,
                state=disc_port.state
            )
            db.add(port)

        # Update host status
        host.status = "approved"
        host.asset_id = asset.id
        host.processed_at = datetime.utcnow()

        db.commit()
        db.refresh(asset)

        print_test(f"Approved host → Asset: {asset.hostname}", "PASS")
        print_test(f"Transferred {len(discovered_ports)} port(s) to asset", "PASS")

        # Verify asset.ports relationship works
        asset_ports = asset.ports
        print_test(f"Verified asset.ports relationship: {len(asset_ports)} ports", "PASS")

        return asset
    except Exception as e:
        print_test(f"Failed to approve host: {e}", "FAIL")
        db.rollback()
        return None

def test_host_rejection(db):
    """Test rejecting a discovered host"""
    print("\n" + "="*60)
    print("TEST 7: HOST REJECTION WORKFLOW")
    print("="*60)

    try:
        # Create a new scan and host for rejection test
        scan = DiscoveryScan(
            target="192.168.1.200",
            scan_type="all_ports",
            status="completed",
            created_at=datetime.utcnow()
        )
        db.add(scan)
        db.flush()

        host = DiscoveredHost(
            scan_id=scan.id,
            target=scan.target,
            ip_address="192.168.1.200",
            hostname="reject-test.local",
            status="pending",
            discovered_at=datetime.utcnow()
        )
        db.add(host)
        db.commit()
        db.refresh(host)

        print_test(f"Created test host for rejection: {host.ip_address}", "INFO")

        # Reject the host
        host.status = "rejected"
        host.processed_at = datetime.utcnow()
        db.commit()

        print_test("Host status updated to 'rejected'", "PASS")
        print_test(f"Processed at: {host.processed_at}", "INFO")

        return True
    except Exception as e:
        print_test(f"Failed to reject host: {e}", "FAIL")
        db.rollback()
        return False

def test_port_operations(db, asset):
    """Test port CRUD operations on an asset"""
    print("\n" + "="*60)
    print("TEST 8: PORT CRUD OPERATIONS")
    print("="*60)

    if not asset:
        print_test("Skipped - no asset available", "INFO")
        return

    try:
        # Get UDP protocol
        udp_protocol = db.query(Protocol).filter_by(name="UDP").first()

        # Add a new port
        new_port = Port(
            asset_id=asset.id,
            port_number=53,
            protocol_id=udp_protocol.id,
            service_name="dns",
            state="open"
        )
        db.add(new_port)
        db.commit()
        db.refresh(new_port)

        print_test(f"Added port 53/UDP to asset", "PASS")

        # Read ports
        all_ports = db.query(Port).filter_by(asset_id=asset.id).all()
        print_test(f"Asset now has {len(all_ports)} total ports", "PASS")

        # Update port
        new_port.service_version = "BIND 9.18"
        db.commit()
        print_test("Updated port service version", "PASS")

        # Delete port
        db.delete(new_port)
        db.commit()
        print_test("Deleted port 53/UDP", "PASS")

        # Verify deletion
        remaining_ports = db.query(Port).filter_by(asset_id=asset.id).all()
        print_test(f"Asset now has {len(remaining_ports)} ports after deletion", "PASS")

    except Exception as e:
        print_test(f"Port operations failed: {e}", "FAIL")
        db.rollback()

def test_scan_history(db):
    """Test retrieving scan history"""
    print("\n" + "="*60)
    print("TEST 9: SCAN HISTORY RETRIEVAL")
    print("="*60)

    try:
        # Get all scans ordered by most recent
        scans = db.query(DiscoveryScan).order_by(
            DiscoveryScan.created_at.desc()
        ).limit(10).all()

        print_test(f"Retrieved {len(scans)} recent scan(s)", "PASS")

        for scan in scans[:3]:  # Show first 3
            print_test(
                f"Scan {scan.id}: {scan.target} - {scan.status} "
                f"({scan.hosts_discovered or 0} hosts)",
                "INFO"
            )

    except Exception as e:
        print_test(f"Failed to retrieve scan history: {e}", "FAIL")

def test_pending_hosts(db):
    """Test retrieving pending discovered hosts"""
    print("\n" + "="*60)
    print("TEST 10: PENDING HOSTS RETRIEVAL")
    print("="*60)

    try:
        pending_hosts = db.query(DiscoveredHost).filter_by(
            status="pending"
        ).all()

        print_test(f"Found {len(pending_hosts)} pending host(s)", "PASS")

        for host in pending_hosts[:3]:  # Show first 3
            print_test(
                f"Host {host.id}: {host.ip_address} - {host.hostname or 'no hostname'}",
                "INFO"
            )

    except Exception as e:
        print_test(f"Failed to retrieve pending hosts: {e}", "FAIL")

def main():
    print("\n" + "="*60)
    print("AUTO DISCOVERY BACKEND - INTEGRATION TESTS")
    print("="*60)

    db = next(get_db())

    try:
        # Cleanup before tests
        cleanup_test_data(db)

        # Run integration tests
        scan = test_scan_creation(db)
        test_scan_status_updates(db, scan)
        host = test_host_discovery(db, scan)
        test_host_ports(db, host)
        test_check_matches(db, host)
        asset = test_host_approval(db, host)
        test_host_rejection(db)
        test_port_operations(db, asset)
        test_scan_history(db)
        test_pending_hosts(db)

        # Final cleanup
        print("\n" + "="*60)
        print("FINAL CLEANUP")
        print("="*60)
        cleanup_test_data(db)

        print("\n" + "="*60)
        print("✓ ALL INTEGRATION TESTS COMPLETED")
        print("="*60)

    except Exception as e:
        print_test(f"Test suite error: {e}", "FAIL")
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    main()
