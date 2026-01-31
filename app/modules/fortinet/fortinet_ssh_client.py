"""
FortiGate SSH Client

Provides SSH connection management for FortiGate devices with:
- VDOM context switching
- Connection pooling for parallel operations
- Command caching for performance
- Automatic pagination handling (--More--)
"""

import re
import time
from typing import Dict, List, Optional, Tuple
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException


class ConnectionPool:
    """Thread-safe connection pool for parallel VDOM processing"""

    def __init__(self, host: str, username: str, password: str, port: int = 22, max_connections: int = 4):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.max_connections = max_connections
        self._connections: List[ConnectHandler] = []

    def get_connection(self) -> ConnectHandler:
        """Get or create a connection"""
        if self._connections:
            return self._connections.pop()
        return self._create_connection()

    def return_connection(self, conn: ConnectHandler) -> None:
        """Return connection to pool"""
        if len(self._connections) < self.max_connections:
            self._connections.append(conn)
        else:
            try:
                conn.disconnect()
            except Exception:
                pass

    def _create_connection(self) -> ConnectHandler:
        """Create new connection"""
        base = dict(
            host=self.host,
            username=self.username,
            password=self.password,
            port=self.port,
            fast_cli=False,
            global_delay_factor=1
        )
        for device_type in ("fortinet", "fortigate"):
            try:
                params = dict(base)
                params["device_type"] = device_type
                return ConnectHandler(**params)
            except Exception as e:
                last_error = e
        raise last_error if 'last_error' in locals() else RuntimeError("Unable to connect to FortiGate")

    def close_all(self) -> None:
        """Close all pooled connections"""
        for conn in self._connections:
            try:
                conn.disconnect()
            except Exception:
                pass
        self._connections.clear()


class FortiGateSSHClient:
    """
    SSH client for FortiGate devices with advanced features.

    Features:
    - VDOM context management
    - Command output caching (5-minute TTL)
    - Automatic --More-- pagination handling
    - Batch command execution
    """

    def __init__(self, host: str, username: str, password: str, port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self._connection: Optional[ConnectHandler] = None
        self._cmd_cache: Dict[str, Tuple[str, float]] = {}
        self._cache_ttl = 300  # 5 minutes
        self._current_vdom: Optional[str] = None

    def connect(self) -> None:
        """Establish SSH connection to FortiGate"""
        if self._connection:
            return

        base = dict(
            host=self.host,
            username=self.username,
            password=self.password,
            port=self.port,
            fast_cli=False,
            global_delay_factor=1
        )

        last_error = None
        for device_type in ("fortinet", "fortigate"):
            try:
                params = dict(base)
                params["device_type"] = device_type
                self._connection = ConnectHandler(**params)
                return
            except Exception as e:
                last_error = e

        raise last_error if last_error else RuntimeError("Unable to connect to FortiGate")

    def disconnect(self) -> None:
        """Close SSH connection"""
        if self._connection:
            try:
                self._connection.disconnect()
            except Exception:
                pass
            finally:
                self._connection = None
                self._current_vdom = None

    def send_command(self, command: str, use_cache: bool = True) -> str:
        """
        Execute command and return output.

        Args:
            command: FortiGate CLI command
            use_cache: Use cached result if available

        Returns:
            Command output as string
        """
        if not self._connection:
            raise RuntimeError("Not connected. Call connect() first.")

        # Check cache
        cache_key = f"{self._current_vdom}:{command}" if self._current_vdom else command
        if use_cache and cache_key in self._cmd_cache:
            cached_out, timestamp = self._cmd_cache[cache_key]
            if time.time() - timestamp < self._cache_ttl:
                return cached_out

        # Execute command
        output = self._connection.send_command_timing(
            command,
            strip_prompt=False,
            strip_command=False
        )

        # Handle pagination (--More--)
        while re.search(r"--More--", output or "", flags=re.IGNORECASE):
            output = re.sub(r"--More--", "", output, flags=re.IGNORECASE)
            output += self._connection.send_command_timing(
                " ",
                strip_prompt=False,
                strip_command=False
            )

        # Cache result
        if use_cache:
            self._cmd_cache[cache_key] = (output, time.time())

        return output

    def send_commands(self, commands: List[str]) -> Dict[str, str]:
        """
        Execute multiple commands in batch.

        Args:
            commands: List of FortiGate CLI commands

        Returns:
            Dictionary mapping command to output
        """
        results = {}
        for cmd in commands:
            try:
                results[cmd] = self.send_command(cmd)
            except Exception as e:
                results[cmd] = f"__ERROR__: {e}"
        return results

    def enter_vdom(self, vdom: str) -> bool:
        """
        Enter VDOM context.

        Args:
            vdom: VDOM name

        Returns:
            True if successful, False otherwise
        """
        if not self._connection:
            raise RuntimeError("Not connected. Call connect() first.")

        try:
            out1 = self._connection.send_command_timing(
                "config vdom",
                strip_prompt=False,
                strip_command=False
            )
            out2 = self._connection.send_command_timing(
                f"edit {vdom}",
                strip_prompt=False,
                strip_command=False
            )

            combined = (out1 or "") + "\n" + (out2 or "")
            success = self._is_command_ok(combined)

            if success:
                self._current_vdom = vdom

            return success

        except Exception:
            return False

    def exit_vdom(self) -> None:
        """Exit VDOM context"""
        if not self._connection:
            return

        try:
            self._connection.send_command_timing(
                "end",
                strip_prompt=False,
                strip_command=False
            )
            self._current_vdom = None
        except Exception:
            pass

    def discover_vdoms(self) -> List[str]:
        """
        Discover all VDOMs on the device.

        Returns:
            List of VDOM names
        """
        commands = [
            "get system vdom-property",
            "diagnose sys vdom list",
            "show vdom"
        ]

        vdoms: List[str] = []

        for cmd in commands:
            output = self.send_command(cmd)
            if not self._is_command_ok(output):
                continue

            # Try different parsing patterns
            if "vdom-property" in cmd:
                for m in re.finditer(
                    r"^\s*(?:name|VDOM name)\s*:\s*([A-Za-z0-9._-]+)\s*$",
                    output,
                    flags=re.MULTILINE
                ):
                    vdoms.append(m.group(1))

            elif "diagnose" in cmd:
                for m in re.finditer(
                    r"^\s*name\s*=\s*([A-Za-z0-9._-]+)\b",
                    output,
                    flags=re.MULTILINE | re.IGNORECASE
                ):
                    vdoms.append(m.group(1))

            elif "show vdom" in cmd:
                for m in re.finditer(
                    r'^\s*edit\s+"?([A-Za-z0-9._-]+)"?\s*$',
                    output,
                    flags=re.MULTILINE | re.IGNORECASE
                ):
                    vdoms.append(m.group(1))

        # Remove duplicates while preserving order
        seen = set()
        unique_vdoms = []
        for v in vdoms:
            if v not in seen:
                seen.add(v)
                unique_vdoms.append(v)

        return unique_vdoms

    def get_system_status(self) -> Dict[str, str]:
        """
        Get system status information.

        Returns:
            Dictionary with version, hostname, serial, model, etc.
        """
        output = self.send_command("get system status")
        meta = {"fortios_version": "0.0.0"}

        # Parse version
        m_ver = re.search(r"^\s*Version:\s*(.+)\s*$", output, flags=re.MULTILINE | re.IGNORECASE)
        if m_ver:
            meta["version_line"] = m_ver.group(1).strip()

            # Extract FortiOS version
            mv = re.search(r"\bv(\d+\.\d+(?:\.\d+)?)\b", meta["version_line"])
            if mv:
                meta["fortios_version"] = mv.group(1)

            # Extract build number
            mb = re.search(r"\bbuild(\d+)\b", meta["version_line"])
            if mb:
                meta["build"] = mb.group(1)

            # Extract model
            mm = re.search(r"^(.+?)\s+v\d+\.\d+", meta["version_line"])
            if mm:
                meta["model"] = mm.group(1).strip()

        # Parse hostname
        m_hn = re.search(r"^\s*Hostname:\s*(.+)\s*$", output, flags=re.MULTILINE | re.IGNORECASE)
        if m_hn:
            meta["hostname"] = m_hn.group(1).strip()

        # Parse serial number
        m_sn = re.search(r"^\s*Serial-Number:\s*(.+)\s*$", output, flags=re.MULTILINE | re.IGNORECASE)
        if m_sn:
            meta["serial"] = m_sn.group(1).strip()

        # Check VDOM status
        m_vdom = re.search(
            r"Virtual\s+domain\s+configuration:\s*(enable|disable)",
            output,
            flags=re.IGNORECASE
        )
        if m_vdom:
            meta["vdom_enabled"] = (m_vdom.group(1).lower() == "enable")

        return meta

    @staticmethod
    def _is_command_ok(output: str) -> bool:
        """Check if command executed successfully"""
        if (output or "").startswith("__ERROR__"):
            return False

        low = (output or "").lower()
        bad_patterns = [
            "command fail",
            "parse error",
            "unknown command",
            "unknown action",
            "invalid",
            "not found",
            "permission denied",
        ]

        return not any(pattern in low for pattern in bad_patterns)

    def clear_cache(self) -> None:
        """Clear command output cache"""
        self._cmd_cache.clear()

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
