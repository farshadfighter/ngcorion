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
    def build_nmap_command(
        target: str,
        ports: Optional[str] = None,
        protocol: str = "TCP",
        scan_type: str = "well_known_ports"
    ) -> List[str]:
        """
        Build nmap command based on parameters

        Args:
            target: IP address, CIDR, or range
            ports: Port specification (e.g., "80,443", "1-1000")
            protocol: TCP, UDP, or BOTH
            scan_type: all_ports, well_known_ports, or custom_ports

        Returns:
            List of command arguments

        Examples:
            all_ports: nmap -sT -sV -Pn -p- 192.168.1.0/24
            well_known_ports: nmap -sT -sV -Pn -p 1-1024 192.168.1.0/24
            custom_ports: nmap -sT -sV -Pn -p 80,443,8080 192.168.1.0/24
        """
        if not NmapScanner.is_nmap_available():
            raise FileNotFoundError("nmap is not installed or not in PATH")

        cmd = ["nmap", "-oX", "-"]  # XML output to stdout

        # Always use -sT (TCP connect scan), -sV (version detection), -Pn (skip host discovery)
        cmd.extend(["-sT", "-sV", "-Pn"])

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

        # Additional options
        cmd.extend([
            "--max-retries=2",  # Reduce retries for faster scan
            "--host-timeout=300s"  # Max time per host
        ])

        cmd.append(target)
        return cmd

    @staticmethod
    def execute_scan(cmd: List[str], timeout: int = 600) -> Tuple[int, Optional[str], Optional[str]]:
        """
        Execute nmap command and return results

        Args:
            cmd: Command list from build_nmap_command
            timeout: Maximum execution time in seconds

        Returns:
            Tuple of (returncode, stdout, stderr)
            returncode: 0 for success, -1 for timeout, >0 for error
            stdout: XML output from nmap
            stderr: Error messages if any
        """
        try:
            logger.info(f"Executing nmap: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            logger.info(f"Nmap completed with return code: {result.returncode}")
            return result.returncode, result.stdout, result.stderr

        except subprocess.TimeoutExpired:
            logger.error(f"Nmap scan timeout after {timeout} seconds")
            return -1, None, f"Scan timeout exceeded ({timeout}s)"

        except Exception as e:
            logger.exception("Nmap execution failed")
            return 1, None, str(e)

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
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    try:
                        port_id = int(port.get("portid"))
                    except (ValueError, TypeError):
                        continue

                    protocol = port.get("protocol", "tcp")

                    state_elem = port.find("state")
                    state = state_elem.get("state") if state_elem is not None else "unknown"

                    service_elem = port.find("service")
                    service_info = {
                        "service": None,
                        "product": None,
                        "version": None,
                        "extrainfo": None
                    }

                    if service_elem is not None:
                        service_info["service"] = service_elem.get("name")
                        service_info["product"] = service_elem.get("product")
                        service_info["version"] = service_elem.get("version")
                        service_info["extrainfo"] = service_elem.get("extrainfo")

                    host_data["ports"].append({
                        "port": port_id,
                        "protocol": protocol,
                        "state": state,
                        **service_info
                    })

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
        timeout: int = 600
    ) -> Dict[str, Any]:
        """
        Convenience method: build, execute, and parse in one call

        Args:
            target: IP address, CIDR, or range
            ports: Port specification
            protocol: TCP, UDP, or BOTH
            scan_type: all_ports, well_known_ports, or custom_ports
            timeout: Maximum execution time

        Returns:
            Dictionary with:
            {
                "success": bool,
                "returncode": int,
                "command": str,
                "hosts": List[Dict],
                "error": Optional[str]
            }
        """
        result = {
            "success": False,
            "returncode": None,
            "command": None,
            "hosts": [],
            "error": None
        }

        try:
            # Build command
            cmd = NmapScanner.build_nmap_command(target, ports, protocol, scan_type)
            result["command"] = " ".join(cmd)

            # Execute scan
            returncode, stdout, stderr = NmapScanner.execute_scan(cmd, timeout)
            result["returncode"] = returncode

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
