"""
Nmap Scanner Utility
Handles nmap command building, execution, and XML parsing
"""

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Global registry to track running scan processes
_running_scans: Dict[str, subprocess.Popen] = {}


class NmapScanner:
    """Wrapper for nmap network scanning operations"""

    @staticmethod
    def is_nmap_available() -> bool:
        """Check if nmap is installed and available"""
        return shutil.which("nmap") is not None

    @staticmethod
    def is_root() -> bool:
        """Check if running as root (needed for SYN scan)"""
        try:
            return os.geteuid() == 0
        except AttributeError:
            # Windows doesn't have geteuid
            return False

    @staticmethod
    def is_ip_range(target: str) -> bool:
        """
        Check if target is an IP range (CIDR or dash notation)

        Examples:
            192.168.1.1 -> False (single IP)
            192.168.1.0/24 -> True (CIDR range)
            192.168.1.1-254 -> True (dash range)
            192.168.1.1-192.168.1.254 -> True (full dash range)
        """
        # CIDR notation
        if '/' in target:
            return True
        # Dash notation for ranges
        if '-' in target:
            return True
        return False

    @staticmethod
    def calculate_timeout(target: str, scan_type: str, version_detection: bool) -> int:
        """
        Calculate appropriate timeout based on scan parameters

        Args:
            target: IP address, CIDR, or range
            scan_type: all_ports, well_known_ports, or custom_ports
            version_detection: Whether -sV is enabled

        Returns:
            Timeout in seconds
        """
        # Estimate number of hosts
        num_hosts = 1
        if '/' in target:
            # CIDR notation
            prefix = int(target.split('/')[1])
            num_hosts = 2 ** (32 - prefix) - 2  # Subtract network and broadcast
            num_hosts = max(1, num_hosts)
        elif '-' in target:
            # Range notation like 192.168.1.1-254
            parts = target.split('-')
            if len(parts) == 2:
                try:
                    start = int(parts[0].split('.')[-1])
                    end = int(parts[1])
                    num_hosts = end - start + 1
                except ValueError:
                    num_hosts = 254  # Default assumption

        # Base time per host (in seconds)
        if version_detection:
            time_per_host = 60  # -sV is slow
        else:
            time_per_host = 10  # Without -sV is fast

        # Adjust for scan type
        if scan_type == "all_ports":
            time_per_host *= 3  # 65535 ports takes longer
        elif scan_type == "well_known_ports":
            time_per_host *= 1.5  # 1024 ports
        # custom_ports depends on how many ports, assume moderate

        # Calculate total timeout with buffer
        calculated_timeout = int(num_hosts * time_per_host * 1.2)  # 20% buffer

        # Set reasonable bounds
        min_timeout = 60  # At least 1 minute
        max_timeout = 3600  # Max 1 hour

        return max(min_timeout, min(calculated_timeout, max_timeout))

    @staticmethod
    def build_nmap_command(
        target: str,
        ports: Optional[str] = None,
        protocol: str = "TCP",
        scan_type: str = "well_known_ports",
        version_detection: bool = False
    ) -> List[str]:
        """
        Build nmap command based on parameters

        Args:
            target: IP address, CIDR, or range
            ports: Port specification (e.g., "80,443", "1-1000")
            protocol: TCP, UDP, or BOTH
            scan_type: all_ports, well_known_ports, or custom_ports
            version_detection: Enable service version detection (-sV) - much slower

        Returns:
            List of command arguments

        Examples:
            all_ports: nmap -sT -Pn -p- 192.168.1.0/24
            well_known_ports: nmap -sT -Pn -p 1-1024 192.168.1.0/24
            with version: nmap -sT -sV -Pn -p 1-1024 192.168.1.1
        """
        if not NmapScanner.is_nmap_available():
            raise FileNotFoundError("nmap is not installed or not in PATH")

        cmd = ["nmap", "-oX", "-"]  # XML output to stdout

        # Always use -v (verbose), -sT (TCP connect scan), -Pn (skip host discovery)
        cmd.extend(["-v", "-sT", "-Pn"])

        # Only add -sV if explicitly requested (it's MUCH slower)
        if version_detection:
            cmd.append("-sV")

        # Determine port range based on scan type
        if scan_type == "all_ports":
            cmd.append("-p-")  # All 65535 ports
        elif scan_type == "well_known_ports":
            cmd.extend(["-p", "1-1024"])  # Well-known ports (1-1024)
        elif scan_type == "custom_ports":
            if ports:
                # Custom ports: "80,443" or "1-1000" or specific port
                cmd.extend(["-p", ports])
            else:
                # Default to well-known if no custom ports specified
                cmd.extend(["-p", "1-1024"])
        else:
            # Default to well-known ports
            cmd.extend(["-p", "1-1024"])

        # Adjust scan settings based on whether target is a single IP or a range
        is_range = NmapScanner.is_ip_range(target)

        if is_range:
            if version_detection:
                # With version detection on ranges - need more time per host
                cmd.extend([
                    "--max-retries=2",
                    "--host-timeout=120s",  # 120 seconds per host with -sV
                    "--min-rate=100",
                    "-T4"  # Aggressive timing
                ])
                logger.info(f"Target '{target}' is IP range with version detection, using balanced settings")
            else:
                # Without version detection - increased timeout for slow-responding hosts
                cmd.extend([
                    "--max-retries=2",
                    "--host-timeout=60s",  # Increased from 30s to 60s for slow hosts
                    "--min-rate=150",  # Slightly reduced packet rate for reliability
                    "-T4"  # Aggressive timing
                ])
                logger.info(f"Target '{target}' is IP range without version detection, using reliable settings")
        else:
            # Single IP - can be aggressive
            if version_detection:
                cmd.extend([
                    "--max-retries=2",
                    "--host-timeout=60s",  # More time for version detection
                    "--min-rate=100",
                    "-T4"
                ])
            else:
                cmd.extend([
                    "--max-retries=1",
                    "--host-timeout=20s",
                    "--min-rate=200",
                    "-T4"
                ])

        cmd.append(target)
        return cmd

    @staticmethod
    def execute_scan(cmd: List[str], timeout: int = 600, scan_id: Optional[str] = None) -> Tuple[int, Optional[str], Optional[str]]:
        """
        Execute nmap command and return results

        Args:
            cmd: Command list from build_nmap_command
            timeout: Maximum execution time in seconds
            scan_id: Optional scan ID to track the process for cancellation

        Returns:
            Tuple of (returncode, stdout, stderr)
            returncode: 0 for success, -1 for timeout, -9 for cancelled, >0 for error
            stdout: XML output from nmap
            stderr: Error messages if any
        """
        process = None
        try:
            logger.info(f"Executing nmap: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Register the process if scan_id is provided
            if scan_id:
                _running_scans[scan_id] = process
                logger.info(f"Registered scan {scan_id} with PID {process.pid}")

            try:
                stdout, stderr = process.communicate(timeout=timeout)
                returncode = process.returncode

                logger.info(f"Nmap completed with return code: {returncode}")
                return returncode, stdout, stderr

            except subprocess.TimeoutExpired:
                logger.error(f"Nmap scan timeout after {timeout} seconds")
                process.kill()
                process.communicate()  # Clean up
                return -1, None, f"Scan timeout exceeded ({timeout}s)"

        except Exception as e:
            logger.exception("Nmap execution failed")
            if process:
                try:
                    process.kill()
                    process.communicate()
                except:
                    pass
            return 1, None, str(e)

        finally:
            # Unregister the process
            if scan_id and scan_id in _running_scans:
                del _running_scans[scan_id]
                logger.info(f"Unregistered scan {scan_id}")

    @staticmethod
    def cancel_scan(scan_id: str) -> bool:
        """
        Cancel a running scan by scan_id

        Args:
            scan_id: The scan ID to cancel

        Returns:
            True if scan was found and terminated, False otherwise
        """
        if scan_id not in _running_scans:
            logger.warning(f"Cannot cancel scan {scan_id}: not found in running scans")
            return False

        process = _running_scans[scan_id]
        try:
            logger.info(f"Cancelling scan {scan_id} with PID {process.pid}")
            process.terminate()  # Send SIGTERM first
            try:
                process.wait(timeout=5)  # Wait up to 5 seconds
            except subprocess.TimeoutExpired:
                logger.warning(f"Scan {scan_id} didn't terminate gracefully, killing it")
                process.kill()  # Send SIGKILL if SIGTERM didn't work
                process.wait()

            logger.info(f"Successfully cancelled scan {scan_id}")
            return True

        except Exception as e:
            logger.exception(f"Failed to cancel scan {scan_id}: {e}")
            return False

    @staticmethod
    def is_scan_running(scan_id: str) -> bool:
        """
        Check if a scan is currently running

        Args:
            scan_id: The scan ID to check

        Returns:
            True if scan is running, False otherwise
        """
        if scan_id not in _running_scans:
            return False

        process = _running_scans[scan_id]
        # Check if process is still running
        return process.poll() is None

    @staticmethod
    def parse_nmap_xml(xml_text: str) -> List[Dict[str, Any]]:
        """
        Parse nmap XML output into structured data

        Args:
            xml_text: XML output from nmap

        Returns:
            List of host dictionaries with structure:
            {
                "ip": "192.168.1.100",
                "mac": "00:11:22:33:44:55",
                "hostname": "server01.local",
                "state": "up",
                "os": {
                    "name": "Linux 5.10",
                    "accuracy": 95,
                    "all_matches": [...]
                },
                "ports": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "product": "nginx",
                        "version": "1.18.0",
                        "extrainfo": None
                    }
                ]
            }
        """
        if not xml_text:
            return []

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            logger.error(f"XML parse error: {e}")
            raise ValueError(f"Invalid XML from nmap: {e}")

        hosts = []

        for host in root.findall("host"):
            host_data = {
                "ip": None,
                "mac": None,
                "hostname": None,
                "state": None,
                "os": {"name": None, "accuracy": None, "all_matches": []},
                "os_guessed": None,  # OS guessed from service detection (-sV)
                "ports": []
            }

            # Host status
            status = host.find("status")
            if status is not None:
                host_data["state"] = status.get("state")

            # Addresses (IP and MAC)
            for addr in host.findall("address"):
                addr_type = addr.get("addrtype")
                addr_value = addr.get("addr")

                if addr_type in ("ipv4", "ipv6"):
                    host_data["ip"] = addr_value
                elif addr_type == "mac":
                    host_data["mac"] = addr_value

            # Hostnames
            hostnames_elem = host.find("hostnames")
            if hostnames_elem is not None:
                hostname_list = []
                for hostname_elem in hostnames_elem.findall("hostname"):
                    name = hostname_elem.get("name")
                    if name:
                        hostname_list.append(name)
                if hostname_list:
                    host_data["hostname"] = hostname_list[0]  # Use first hostname

            # OS Detection
            os_elem = host.find("os")
            if os_elem is not None:
                best_match = None
                best_accuracy = 0

                for osmatch in os_elem.findall("osmatch"):
                    name = osmatch.get("name")
                    try:
                        accuracy = int(osmatch.get("accuracy", 0))
                    except (ValueError, TypeError):
                        accuracy = 0

                    os_match = {"name": name, "accuracy": accuracy}
                    host_data["os"]["all_matches"].append(os_match)

                    if accuracy > best_accuracy:
                        best_accuracy = accuracy
                        best_match = os_match

                if best_match:
                    host_data["os"]["name"] = best_match["name"]
                    host_data["os"]["accuracy"] = best_match["accuracy"]

            # Ports and Services
            ports_elem = host.find("ports")
            os_types_found = set()  # Collect OS types from service detection

            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    try:
                        port_id = int(port.get("portid"))
                    except (ValueError, TypeError):
                        continue

                    # Skip Ident/Auth port - filtered from discovery results
                    if port_id == 113:
                        continue

                    protocol = port.get("protocol", "tcp")

                    state_elem = port.find("state")
                    state = state_elem.get("state") if state_elem is not None else "unknown"

                    service_elem = port.find("service")
                    service_info = {
                        "service": None,
                        "product": None,
                        "version": None,
                        "extrainfo": None,
                        "ostype": None
                    }

                    if service_elem is not None:
                        service_info["service"] = service_elem.get("name")
                        service_info["product"] = service_elem.get("product")
                        service_info["version"] = service_elem.get("version")
                        service_info["extrainfo"] = service_elem.get("extrainfo")
                        # Extract OS type from service detection (-sV)
                        ostype = service_elem.get("ostype")
                        if ostype:
                            service_info["ostype"] = ostype
                            os_types_found.add(ostype)

                    host_data["ports"].append({
                        "port": port_id,
                        "protocol": protocol,
                        "state": state,
                        **service_info
                    })

            # Set os_guessed from service detection if available
            if os_types_found:
                # Use the most common OS type found, or first one if all unique
                host_data["os_guessed"] = list(os_types_found)[0]
                if len(os_types_found) > 1:
                    # If multiple OS types detected, store all of them
                    host_data["os_guessed"] = ", ".join(sorted(os_types_found))

                # If -sV found OS info and there's no OS from -O detection,
                # assign the service-detected OS to the main OS field
                if not host_data["os"]["name"]:
                    host_data["os"]["name"] = host_data["os_guessed"]
                    host_data["os"]["accuracy"] = 50  # Lower confidence for service-based detection

            # Only include hosts that were actually discovered (have an IP)
            if host_data["ip"]:
                hosts.append(host_data)

        logger.info(f"Parsed {len(hosts)} hosts from nmap XML")
        return hosts

    @staticmethod
    def scan_and_parse(
        target: str,
        ports: Optional[str] = None,
        protocol: str = "TCP",
        scan_type: str = "well_known_ports",
        timeout: Optional[int] = None,
        version_detection: bool = False,
        scan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Convenience method: build, execute, and parse in one call

        Args:
            target: IP address, CIDR, or range
            ports: Port specification
            protocol: TCP, UDP, or BOTH
            scan_type: all_ports, well_known_ports, or custom_ports
            timeout: Maximum execution time (auto-calculated if None)
            version_detection: Enable service version detection (-sV)
            scan_id: Optional scan ID to track the process for cancellation

        Returns:
            Dictionary with:
            {
                "success": bool,
                "returncode": int,
                "command": str,
                "hosts": List[Dict],
                "error": Optional[str],
                "timeout_used": int,
                "cancelled": bool
            }
        """
        result = {
            "success": False,
            "returncode": None,
            "command": None,
            "hosts": [],
            "error": None,
            "timeout_used": None,
            "cancelled": False
        }

        try:
            # Build command
            cmd = NmapScanner.build_nmap_command(target, ports, protocol, scan_type, version_detection)
            result["command"] = " ".join(cmd)

            # Calculate timeout if not provided
            if timeout is None:
                timeout = NmapScanner.calculate_timeout(target, scan_type, version_detection)
            result["timeout_used"] = timeout
            logger.info(f"Using timeout: {timeout}s for target '{target}'")

            # Execute scan
            returncode, stdout, stderr = NmapScanner.execute_scan(cmd, timeout, scan_id)
            result["returncode"] = returncode

            # Check if scan was cancelled (process terminated by signal)
            if returncode and returncode < 0:
                result["cancelled"] = True
                result["error"] = "Scan was cancelled"
                return result

            if returncode != 0:
                result["error"] = stderr or f"Nmap failed with code {returncode}"
                return result

            # Parse results
            if stdout:
                result["hosts"] = NmapScanner.parse_nmap_xml(stdout)
                result["success"] = True
            else:
                result["error"] = "No output from nmap"

        except Exception as e:
            logger.exception("Scan and parse failed")
            result["error"] = str(e)

        return result


# Helper function for quick testing
def test_scan(target: str = "127.0.0.1"):
    """Quick test function"""
    print(f"Testing nmap scan on {target}...")
    result = NmapScanner.scan_and_parse(
        target=target,
        ports="80,443",
        protocol="TCP",
        scan_type="custom_ports"
    )

    print(f"Success: {result['success']}")
    print(f"Command: {result['command']}")
    print(f"Hosts found: {len(result['hosts'])}")
    if result['error']:
        print(f"Error: {result['error']}")

    for host in result['hosts']:
        print(f"\n  IP: {host['ip']}")
        print(f"  State: {host['state']}")
        print(f"  Hostname: {host['hostname']}")
        print(f"  Ports: {len(host['ports'])}")


if __name__ == "__main__":
    # Run test if executed directly
    test_scan()
