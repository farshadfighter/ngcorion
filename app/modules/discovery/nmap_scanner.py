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
    def calculate_timeout(target: str, scan_type: str, version_detection: bool, protocol: str = "TCP") -> int:
        """
        Calculate appropriate timeout based on scan parameters.

        Returns:
            Timeout in seconds (subprocess-level wall-clock limit)
        """
        import math

        # Estimate number of hosts
        num_hosts = 1
        if '/' in target:
            prefix = int(target.split('/')[1])
            num_hosts = max(1, 2 ** (32 - prefix) - 2)
        elif '-' in target:
            parts = target.split('-')
            if len(parts) == 2:
                try:
                    start = int(parts[0].split('.')[-1])
                    end = int(parts[1])
                    num_hosts = max(1, end - start + 1)
                except ValueError:
                    num_hosts = 254

        # Realistic base time per single host with -T4 (measured in practice)
        if scan_type == "all_ports":
            # 65535 ports: ~15 min without -sV, ~60 min with -sV
            time_per_host = 3600 if version_detection else 900
        elif scan_type == "well_known_ports":
            # ~1036 ports: ~5 min without -sV, ~10 min with -sV
            time_per_host = 600 if version_detection else 300
        else:
            # custom_ports: conservative middle estimate
            time_per_host = 300 if version_detection else 120

        # UDP scans are rate-limited by nmap and run far slower than TCP.
        # Give them substantially more headroom (BOTH runs TCP+UDP back to back).
        if (protocol or "TCP").upper() in ("UDP", "BOTH"):
            time_per_host *= 2

        if num_hosts <= 1:
            calculated_timeout = time_per_host
        else:
            # nmap scans range hosts in parallel — scale sublinearly with sqrt
            scale = math.sqrt(num_hosts)
            calculated_timeout = int(time_per_host * scale)

        # 20% safety buffer
        calculated_timeout = int(calculated_timeout * 1.2)

        # Bounds: at least 2 min, at most 2 hours
        return max(120, min(calculated_timeout, 7200))

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

        # Scan technique depends on the requested protocol:
        #   TCP  -> -sT (TCP connect, no privileges required)
        #   UDP  -> -sU (requires root / raw sockets)
        #   BOTH -> -sT -sU (combined TCP + UDP in a single run)
        proto = (protocol or "TCP").upper()
        if proto == "UDP":
            scan_flags = ["-sU"]
        elif proto == "BOTH":
            scan_flags = ["-sT", "-sU"]
        else:
            scan_flags = ["-sT"]

        # UDP scanning needs raw-socket privileges. Fail early with a clear message
        # rather than letting nmap abort mid-run (or silently return nothing).
        if "-sU" in scan_flags and not NmapScanner.is_root():
            raise PermissionError(
                "UDP scanning requires root privileges. "
                "Run the backend as root (or grant CAP_NET_RAW), or use protocol 'TCP'."
            )

        # Core flags: skip host discovery, no DNS resolution.
        # Note: -v is intentionally omitted — verbose output on some nmap versions
        # goes to stdout and corrupts the XML stream.
        cmd.extend(scan_flags)
        cmd.extend(["-Pn", "-n"])

        # Only add -sV if explicitly requested (it's MUCH slower)
        if version_detection:
            cmd.append("-sV")

        # Determine port range based on scan type
        if scan_type == "all_ports":
            cmd.append("-p-")  # All 65535 ports
        elif scan_type == "well_known_ports":
            cmd.extend(["-p", "1-1024,1433,1521,3306,3389,5432,5900,8080,8443,8888,9090,27017"])
        elif scan_type == "custom_ports":
            if ports:
                # Custom ports: "80,443" or "1-1000" or specific port
                cmd.extend(["-p", ports])
            else:
                cmd.extend(["-p", "1-1024"])
        else:
            cmd.extend(["-p", "1-1024"])

        # Aggressive timing (matches `nmap -T4` used manually by operators)
        cmd.append("-T4")

        # For range scans add a per-host ceiling so one dead host cannot stall the whole scan.
        # Single-IP scans let T4 timing run to completion naturally.
        is_range = NmapScanner.is_ip_range(target)
        if is_range:
            if "-sU" in scan_flags:
                # UDP per-host scans are much slower; allow more time per host.
                host_timeout = "900s" if version_detection else "600s"
            else:
                host_timeout = "300s" if version_detection else "120s"
            cmd.append(f"--host-timeout={host_timeout}")
            logger.info(f"Range scan '{target}': host-timeout={host_timeout}, protocol={proto}, version_detection={version_detection}")
        else:
            logger.info(f"Single-IP scan '{target}': using T4 defaults, protocol={proto}, version_detection={version_detection}")

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
                if returncode != 0:
                    logger.error(f"Nmap stderr: {stderr[:500] if stderr else '(empty)'}")
                elif not stdout:
                    logger.warning("Nmap returned 0 but stdout is empty")
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

        # Strip any non-XML content that may precede the XML declaration.
        # On some nmap versions/configs, verbose messages appear on stdout before
        # the XML, which would break the parser.
        xml_start = xml_text.find("<?xml")
        if xml_start < 0:
            xml_start = xml_text.find("<nmaprun")
        if xml_start > 0:
            logger.warning(f"Stripped {xml_start} bytes of non-XML prefix from nmap stdout")
            xml_text = xml_text[xml_start:]
        elif xml_start < 0:
            logger.error("No XML content found in nmap output")
            logger.debug(f"nmap stdout (first 500 chars): {xml_text[:500]}")
            raise ValueError("No XML content found in nmap output")

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            logger.error(f"XML parse error: {e}")
            logger.debug(f"nmap stdout (first 500 chars): {xml_text[:500]}")
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

                    # Skip TCP 113 (ident) — noisy, unreliable, no security value
                    if port_id == 113 and protocol == "tcp":
                        continue

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

            # Only include hosts with an IP and at least one port result
            if host_data["ip"] and host_data["ports"]:
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
                timeout = NmapScanner.calculate_timeout(target, scan_type, version_detection, protocol)
            result["timeout_used"] = timeout
            logger.info(f"Using timeout: {timeout}s for target '{target}'")

            # Execute scan
            returncode, stdout, stderr = NmapScanner.execute_scan(cmd, timeout, scan_id)
            result["returncode"] = returncode

            # returncode -1  → our own timeout (subprocess.TimeoutExpired)
            # returncode < -1 → killed by external signal (user cancel: SIGTERM=-15, SIGKILL=-9)
            if returncode == -1:
                result["timed_out"] = True
                result["error"] = (
                    stderr
                    or f"Scan timed out after {timeout}s. "
                       f"Try a smaller port range (e.g. well_known_ports instead of all_ports) "
                       f"or reduce the number of target hosts."
                )
                return result
            elif returncode and returncode < 0:
                result["cancelled"] = True
                result["error"] = "Scan was cancelled by user"
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
