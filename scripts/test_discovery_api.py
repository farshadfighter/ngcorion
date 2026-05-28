#!/usr/bin/env python3
"""
Test script for Auto Discovery APIs
Tests all discovery endpoints with proper authentication
"""

import requests
import json
import time
from typing import Dict, Any

# Configuration
BASE_URL = "http://localhost:8000"
USERNAME = "admin"
PASSWORD = "123456"

# Colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")

def print_success(text: str):
    print(f"{Colors.GREEN}✓ {text}{Colors.RESET}")

def print_error(text: str):
    print(f"{Colors.RED}✗ {text}{Colors.RESET}")

def print_info(text: str):
    print(f"{Colors.BLUE}ℹ {text}{Colors.RESET}")

def print_warning(text: str):
    print(f"{Colors.YELLOW}⚠ {text}{Colors.RESET}")

def print_json(data: Any):
    print(json.dumps(data, indent=2))

class DiscoveryAPITester:
    def __init__(self):
        self.base_url = BASE_URL
        self.token = None
        self.scan_id = None
        self.host_id = None
        self.asset_id = None

    def login(self) -> bool:
        """Login and get access token"""
        print_header("1. Authentication")

        try:
            response = requests.post(
                f"{self.base_url}/auth/login",
                json={
                    "username": USERNAME,
                    "password": PASSWORD
                }
            )

            if response.status_code == 200:
                self.token = response.json()["access_token"]
                print_success(f"Logged in as {USERNAME}")
                print_info(f"Token: {self.token[:20]}...")
                return True
            else:
                print_error(f"Login failed: {response.status_code}")
                print_json(response.json())
                return False

        except Exception as e:
            print_error(f"Login error: {e}")
            return False

    def get_headers(self) -> Dict[str, str]:
        """Get headers with auth token"""
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    def test_start_scan(self):
        """Test POST /api/discovery/scan"""
        print_header("2. Start Network Scan")

        # Test 1: Basic scan with well-known ports
        print_info("Test 2.1: Scanning localhost with well-known ports")
        try:
            payload = {
                "job_name": "Test Scan - Localhost",
                "target": "127.0.0.1",
                "scan_type": "well_known_ports",
                "protocol": "TCP"
            }

            response = requests.post(
                f"{self.base_url}/api/discovery/scan",
                headers=self.get_headers(),
                json=payload
            )

            if response.status_code == 200:
                data = response.json()
                self.scan_id = data.get("scan_id")
                print_success(f"Scan started successfully")
                print_json(data)
            else:
                print_error(f"Scan failed: {response.status_code}")
                print_json(response.json())

        except Exception as e:
            print_error(f"Error: {e}")

    def test_get_scan_status(self):
        """Test GET /api/discovery/scan/{scan_id}"""
        print_header("3. Get Scan Status")

        if not self.scan_id:
            print_warning("No scan_id available, skipping...")
            return

        try:
            # Poll for scan completion
            max_attempts = 30
            attempt = 0

            while attempt < max_attempts:
                response = requests.get(
                    f"{self.base_url}/api/discovery/scan/{self.scan_id}",
                    headers=self.get_headers()
                )

                if response.status_code == 200:
                    data = response.json()
                    status = data.get("status")

                    print_info(f"Attempt {attempt + 1}/{max_attempts}: Status = {status}")

                    if status == "completed":
                        print_success("Scan completed!")
                        print_json(data)

                        # Extract host_id if available
                        if data.get("hosts"):
                            self.host_id = data["hosts"][0].get("id") if data["hosts"] else None

                        break
                    elif status == "failed":
                        print_error("Scan failed!")
                        print_json(data)
                        break

                    time.sleep(2)
                    attempt += 1
                else:
                    print_error(f"Failed to get status: {response.status_code}")
                    print_json(response.json())
                    break

        except Exception as e:
            print_error(f"Error: {e}")

    def test_get_all_scans(self):
        """Test GET /api/discovery/scans"""
        print_header("4. Get All Scans")

        try:
            response = requests.get(
                f"{self.base_url}/api/discovery/scans",
                headers=self.get_headers()
            )

            if response.status_code == 200:
                data = response.json()
                print_success(f"Retrieved {len(data)} scans")
                print_json(data)
            else:
                print_error(f"Failed: {response.status_code}")
                print_json(response.json())

        except Exception as e:
            print_error(f"Error: {e}")

    def test_get_pending_hosts(self):
        """Test GET /api/discovery/pending"""
        print_header("5. Get Pending Hosts")

        try:
            # Test without filter
            print_info("Test 5.1: Get all pending hosts")
            response = requests.get(
                f"{self.base_url}/api/discovery/pending",
                headers=self.get_headers()
            )

            if response.status_code == 200:
                data = response.json()
                print_success(f"Retrieved {data.get('total', 0)} pending hosts")
                print_json(data)

                # Get host_id from pending list if not already set
                if not self.host_id and data.get('pending'):
                    self.host_id = data['pending'][0].get('id')
            else:
                print_error(f"Failed: {response.status_code}")
                print_json(response.json())

            # Test with scan_id filter
            if self.scan_id:
                print_info(f"Test 5.2: Get pending hosts for scan {self.scan_id}")
                response = requests.get(
                    f"{self.base_url}/api/discovery/pending?scan_id={self.scan_id}",
                    headers=self.get_headers()
                )

                if response.status_code == 200:
                    data = response.json()
                    print_success(f"Retrieved {data.get('total', 0)} pending hosts for this scan")
                    print_json(data)
                else:
                    print_error(f"Failed: {response.status_code}")

        except Exception as e:
            print_error(f"Error: {e}")

    def test_check_host_matches(self):
        """Test GET /api/discovery/hosts/{host_id}/check-matches"""
        print_header("6. Check Host Matches")

        if not self.host_id:
            print_warning("No host_id available, skipping...")
            return

        try:
            response = requests.get(
                f"{self.base_url}/api/discovery/hosts/{self.host_id}/check-matches",
                headers=self.get_headers()
            )

            if response.status_code == 200:
                data = response.json()
                print_success(f"Found {data.get('match_count', 0)} matches")
                print_json(data)

                # Store asset_id if there's a match
                if data.get('matches'):
                    self.asset_id = data['matches'][0].get('asset_id')
            else:
                print_error(f"Failed: {response.status_code}")
                print_json(response.json())

        except Exception as e:
            print_error(f"Error: {e}")

    def test_preview_discovery(self):
        """Test GET /api/discovery/hosts/{host_id}/preview"""
        print_header("7. Preview Discovery Application")

        if not self.host_id:
            print_warning("No host_id available, skipping...")
            return

        try:
            # Test without asset_id
            print_info("Test 7.1: Preview without asset comparison")
            response = requests.get(
                f"{self.base_url}/api/discovery/hosts/{self.host_id}/preview",
                headers=self.get_headers()
            )

            if response.status_code == 200:
                data = response.json()
                print_success("Preview generated successfully")
                print_json(data)
            else:
                print_error(f"Failed: {response.status_code}")
                print_json(response.json())

            # Test with asset_id if available
            if self.asset_id:
                print_info(f"Test 7.2: Preview with asset {self.asset_id} comparison")
                response = requests.get(
                    f"{self.base_url}/api/discovery/hosts/{self.host_id}/preview?asset_id={self.asset_id}",
                    headers=self.get_headers()
                )

                if response.status_code == 200:
                    data = response.json()
                    print_success("Preview with comparison generated successfully")
                    print_json(data)
                else:
                    print_error(f"Failed: {response.status_code}")

        except Exception as e:
            print_error(f"Error: {e}")

    def test_approve_host_skip(self):
        """Test POST /api/discovery/hosts/{host_id}/approve - skip action"""
        print_header("8. Approve Host (Skip)")

        if not self.host_id:
            print_warning("No host_id available, skipping...")
            return

        try:
            payload = {
                "action": "skip"
            }

            response = requests.post(
                f"{self.base_url}/api/discovery/hosts/{self.host_id}/approve",
                headers=self.get_headers(),
                json=payload
            )

            if response.status_code == 200:
                data = response.json()
                print_success("Host marked as reviewed (skipped)")
                print_json(data)
            else:
                print_error(f"Failed: {response.status_code}")
                print_json(response.json())

        except Exception as e:
            print_error(f"Error: {e}")

    def test_reject_host(self):
        """Test POST /api/discovery/hosts/{host_id}/reject"""
        print_header("9. Reject Host")

        if not self.host_id:
            print_warning("No host_id available, skipping...")
            return

        try:
            response = requests.post(
                f"{self.base_url}/api/discovery/hosts/{self.host_id}/reject",
                headers=self.get_headers()
            )

            if response.status_code == 200:
                data = response.json()
                print_success("Host rejected successfully")
                print_json(data)
            else:
                print_error(f"Failed: {response.status_code}")
                print_json(response.json())

        except Exception as e:
            print_error(f"Error: {e}")

    def test_find_matching_asset(self):
        """Test GET /api/discovery/match/{ip_address}"""
        print_header("10. Find Matching Asset")

        try:
            test_ip = "127.0.0.1"
            print_info(f"Searching for asset with IP: {test_ip}")

            response = requests.get(
                f"{self.base_url}/api/discovery/match/{test_ip}",
                headers=self.get_headers()
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("found"):
                    print_success("Asset found!")
                else:
                    print_info("No matching asset found")
                print_json(data)
            else:
                print_error(f"Failed: {response.status_code}")
                print_json(response.json())

        except Exception as e:
            print_error(f"Error: {e}")

    def test_delete_scan(self):
        """Test DELETE /api/discovery/scan/{scan_id}"""
        print_header("11. Delete Scan")

        if not self.scan_id:
            print_warning("No scan_id available, skipping...")
            return

        try:
            print_warning(f"Deleting scan: {self.scan_id}")
            response = requests.delete(
                f"{self.base_url}/api/discovery/scan/{self.scan_id}",
                headers=self.get_headers()
            )

            if response.status_code == 200:
                data = response.json()
                print_success("Scan deleted successfully")
                print_json(data)
            else:
                print_error(f"Failed: {response.status_code}")
                print_json(response.json())

        except Exception as e:
            print_error(f"Error: {e}")

    def run_all_tests(self):
        """Run all API tests in sequence"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}")
        print("Auto Discovery API Test Suite")
        print(f"{'='*60}{Colors.RESET}\n")

        # Login
        if not self.login():
            print_error("Login failed, cannot continue tests")
            return

        # Run tests in order
        self.test_start_scan()
        time.sleep(2)  # Give scan time to start

        self.test_get_scan_status()
        self.test_get_all_scans()
        self.test_get_pending_hosts()
        self.test_check_host_matches()
        self.test_preview_discovery()
        self.test_approve_host_skip()
        # self.test_reject_host()  # Skip to avoid marking host as rejected
        self.test_find_matching_asset()
        # self.test_delete_scan()  # Uncomment to clean up

        print_header("Test Suite Completed")
        print_success("All tests executed!")

        # Summary
        print(f"\n{Colors.BOLD}Test Summary:{Colors.RESET}")
        if self.scan_id:
            print_info(f"Scan ID: {self.scan_id}")
        if self.host_id:
            print_info(f"Host ID: {self.host_id}")
        if self.asset_id:
            print_info(f"Asset ID: {self.asset_id}")


if __name__ == "__main__":
    tester = DiscoveryAPITester()
    tester.run_all_tests()
