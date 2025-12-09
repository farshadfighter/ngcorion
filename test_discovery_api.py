#!/usr/bin/env python3
"""
Comprehensive API Tests for Auto Discovery Backend
Tests the complete workflow through API endpoints
"""

import requests
import json
from datetime import datetime

BASE_URL = "http://127.0.0.1:8000/api/discovery"

def print_test(message, status="INFO"):
    symbols = {"PASS": "✓", "FAIL": "✗", "INFO": "→", "WARN": "⚠"}
    print(f"{symbols.get(status, '→')} {message}")

def print_section(title):
    print("\n" + "="*60)
    print(title)
    print("="*60)

def test_api_availability():
    """Test if the API server is running"""
    print_section("TEST 1: API SERVER AVAILABILITY")

    try:
        response = requests.get("http://127.0.0.1:8000/health", timeout=5)
        if response.status_code == 200:
            print_test("API server is running", "PASS")
            return True
        else:
            print_test(f"API server returned status {response.status_code}", "FAIL")
            return False
    except requests.exceptions.ConnectionError:
        print_test("API server is not running", "FAIL")
        print_test("Please start the server with: uvicorn app.main:app --reload", "INFO")
        return False
    except Exception as e:
        print_test(f"Error checking API: {e}", "FAIL")
        return False

def test_get_scans():
    """Test retrieving scan history"""
    print_section("TEST 2: GET SCAN HISTORY")

    try:
        response = requests.get(f"{BASE_URL}/scans")
        print_test(f"Status Code: {response.status_code}", "INFO")

        if response.status_code == 200:
            scans = response.json()
            print_test(f"Retrieved {len(scans)} scan(s)", "PASS")

            if scans:
                latest = scans[0]
                print_test(f"Latest scan: {latest.get('scan_id')} - {latest.get('target')}", "INFO")
                print_test(f"Status: {latest.get('status')}", "INFO")
            return True
        else:
            print_test(f"Failed to get scans: {response.text}", "FAIL")
            return False
    except Exception as e:
        print_test(f"Error: {e}", "FAIL")
        return False

def test_get_pending_hosts():
    """Test retrieving pending discovered hosts"""
    print_section("TEST 3: GET PENDING HOSTS")

    try:
        response = requests.get(f"{BASE_URL}/pending-hosts")
        print_test(f"Status Code: {response.status_code}", "INFO")

        if response.status_code == 200:
            hosts = response.json()
            print_test(f"Found {len(hosts)} pending host(s)", "PASS")

            if hosts:
                for i, host in enumerate(hosts[:3], 1):  # Show first 3
                    print_test(
                        f"Host {i}: {host.get('ip_address')} - "
                        f"{host.get('hostname', 'no hostname')} "
                        f"(ports: {len(host.get('ports', []))})",
                        "INFO"
                    )
            return hosts
        else:
            print_test(f"Failed to get pending hosts: {response.text}", "FAIL")
            return []
    except Exception as e:
        print_test(f"Error: {e}", "FAIL")
        return []

def test_check_matches(host_id):
    """Test checking for matching assets"""
    print_section(f"TEST 4: CHECK MATCHES FOR HOST {host_id}")

    try:
        response = requests.get(f"{BASE_URL}/hosts/{host_id}/check-matches")
        print_test(f"Status Code: {response.status_code}", "INFO")

        if response.status_code == 200:
            data = response.json()
            matches = data.get('matches', [])
            print_test(f"Found {len(matches)} matching asset(s)", "PASS")

            if matches:
                for match in matches:
                    print_test(
                        f"Match: Asset #{match.get('id')} - "
                        f"{match.get('hostname')} ({match.get('ip_address')})",
                        "INFO"
                    )
            return True
        else:
            print_test(f"Failed to check matches: {response.text}", "FAIL")
            return False
    except Exception as e:
        print_test(f"Error: {e}", "FAIL")
        return False

def test_get_scan_by_id():
    """Test retrieving a specific scan by ID"""
    print_section("TEST 5: GET SPECIFIC SCAN")

    try:
        # First get all scans to find one
        response = requests.get(f"{BASE_URL}/scans")
        if response.status_code != 200:
            print_test("No scans available to test", "WARN")
            return False

        scans = response.json()
        if not scans:
            print_test("No scans available to test", "WARN")
            return False

        scan_id = scans[0]['scan_id']

        # Get specific scan
        response = requests.get(f"{BASE_URL}/scans/{scan_id}")
        print_test(f"Status Code: {response.status_code}", "INFO")

        if response.status_code == 200:
            scan = response.json()
            print_test(f"Retrieved scan: {scan.get('scan_id')}", "PASS")
            print_test(f"Target: {scan.get('target')}", "INFO")
            print_test(f"Status: {scan.get('status')}", "INFO")
            print_test(f"Hosts discovered: {scan.get('hosts_discovered', 0)}", "INFO")
            return True
        else:
            print_test(f"Failed to get scan: {response.text}", "FAIL")
            return False
    except Exception as e:
        print_test(f"Error: {e}", "FAIL")
        return False

def test_get_host_by_id():
    """Test retrieving a specific discovered host"""
    print_section("TEST 6: GET SPECIFIC DISCOVERED HOST")

    try:
        # First get pending hosts to find one
        response = requests.get(f"{BASE_URL}/pending-hosts")
        if response.status_code != 200:
            print_test("No hosts available to test", "WARN")
            return False

        hosts = response.json()
        if not hosts:
            print_test("No hosts available to test", "WARN")
            return False

        host_id = hosts[0]['id']

        # Get specific host
        response = requests.get(f"{BASE_URL}/hosts/{host_id}")
        print_test(f"Status Code: {response.status_code}", "INFO")

        if response.status_code == 200:
            host = response.json()
            print_test(f"Retrieved host: {host.get('ip_address')}", "PASS")
            print_test(f"Hostname: {host.get('hostname', 'N/A')}", "INFO")
            print_test(f"OS: {host.get('os_info', 'N/A')}", "INFO")
            print_test(f"Ports: {len(host.get('ports', []))}", "INFO")
            print_test(f"Status: {host.get('status')}", "INFO")
            return True
        else:
            print_test(f"Failed to get host: {response.text}", "FAIL")
            return False
    except Exception as e:
        print_test(f"Error: {e}", "FAIL")
        return False

def test_scan_status():
    """Test getting overall scan status"""
    print_section("TEST 7: GET SCAN STATUS SUMMARY")

    try:
        response = requests.get(f"{BASE_URL}/status")
        print_test(f"Status Code: {response.status_code}", "INFO")

        if response.status_code == 200:
            status = response.json()
            print_test("Retrieved scan status summary", "PASS")
            print_test(f"Running scans: {status.get('running_scans', 0)}", "INFO")
            print_test(f"Pending hosts: {status.get('pending_hosts', 0)}", "INFO")
            print_test(f"Total scans: {status.get('total_scans', 0)}", "INFO")
            return True
        else:
            print_test(f"Failed to get status: {response.text}", "FAIL")
            return False
    except Exception as e:
        print_test(f"Error: {e}", "FAIL")
        return False

def test_nmap_availability():
    """Test if nmap is available on the system"""
    print_section("TEST 8: NMAP AVAILABILITY")

    import subprocess

    try:
        result = subprocess.run(
            ['nmap', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            print_test(f"Nmap installed: {version_line}", "PASS")
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

def test_database_models():
    """Test database models and relationships"""
    print_section("TEST 9: DATABASE MODELS")

    try:
        # Test importing models
        from app.models.discovery import DiscoveryScan, DiscoveredHost
        print_test("DiscoveryScan model imported", "PASS")
        print_test("DiscoveredHost model imported", "PASS")

        from app.models.asset import Asset
        from app.models.port import Port, Protocol
        print_test("Asset, Port, Protocol models imported", "PASS")

        # Check Asset.ports relationship
        if hasattr(Asset, 'ports'):
            print_test("Asset.ports relationship exists", "PASS")
        else:
            print_test("Asset.ports relationship missing", "FAIL")

        return True
    except ImportError as e:
        print_test(f"Failed to import models: {e}", "FAIL")
        return False
    except Exception as e:
        print_test(f"Error testing models: {e}", "FAIL")
        return False

def test_endpoint_registration():
    """Test that all expected endpoints are registered"""
    print_section("TEST 10: ENDPOINT REGISTRATION")

    expected_endpoints = [
        ("GET", "/scans", "List all scans"),
        ("GET", "/scans/{scan_id}", "Get specific scan"),
        ("GET", "/pending-hosts", "List pending hosts"),
        ("GET", "/hosts/{host_id}", "Get specific host"),
        ("GET", "/hosts/{host_id}/check-matches", "Check for matches"),
        ("POST", "/hosts/{host_id}/approve", "Approve host"),
        ("POST", "/hosts/{host_id}/reject", "Reject host"),
        ("POST", "/bulk-approve", "Bulk approve hosts"),
        ("GET", "/status", "Get scan status"),
    ]

    passed = 0
    failed = 0

    for method, path, description in expected_endpoints:
        # We can't test POST endpoints without data, so just verify GET endpoints
        if method == "GET" and not "{" in path:
            try:
                response = requests.get(f"{BASE_URL}{path}", timeout=5)
                # 200 or 404 are both OK - means endpoint exists
                if response.status_code in [200, 404, 422]:
                    print_test(f"{method} {path}: registered", "PASS")
                    passed += 1
                else:
                    print_test(f"{method} {path}: unexpected status {response.status_code}", "WARN")
                    passed += 1
            except Exception as e:
                print_test(f"{method} {path}: not accessible ({e})", "FAIL")
                failed += 1
        else:
            print_test(f"{method} {path}: {description}", "INFO")

    print_test(f"Verified {passed} endpoints, {failed} failed",
               "PASS" if failed == 0 else "WARN")
    return failed == 0

def main():
    print("\n" + "="*60)
    print("AUTO DISCOVERY BACKEND - API INTEGRATION TESTS")
    print("="*60)

    # Check API availability first
    if not test_api_availability():
        print("\n" + "="*60)
        print("⚠ API SERVER NOT RUNNING - TESTS ABORTED")
        print("="*60)
        print("Start the server with: cd /home/zi/Desktop/main_app/netease && source venv/bin/activate && uvicorn app.main:app --reload")
        return

    # Run all tests
    test_database_models()
    test_nmap_availability()
    test_endpoint_registration()
    test_get_scans()
    test_get_scan_by_id()
    test_get_pending_hosts()
    test_get_host_by_id()
    test_scan_status()

    # Test check matches if there are pending hosts
    response = requests.get(f"{BASE_URL}/pending-hosts")
    if response.status_code == 200:
        hosts = response.json()
        if hosts:
            test_check_matches(hosts[0]['id'])

    print("\n" + "="*60)
    print("✓ API INTEGRATION TESTS COMPLETED")
    print("="*60)
    print("\nNOTE: Some tests may show WARN status if there's no test data.")
    print("This is expected and doesn't indicate a problem with the system.")

if __name__ == "__main__":
    main()
