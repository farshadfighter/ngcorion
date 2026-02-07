"""
SSH Exception Hierarchy

Provides categorized exception classes for SSH connection errors.
Each exception includes error type, user-friendly message, device IP,
resolution suggestions, and serialization support for API responses.
"""

from typing import List, Optional, Any, Dict
import re


class SSHConnectionError(Exception):
    """
    Base class for all SSH connection errors.

    Provides structured error information for API responses.
    """

    error_type: str = "ssh_error"
    http_status: int = 502

    def __init__(
        self,
        message: str,
        device_ip: str,
        suggestions: Optional[List[str]] = None,
        original_error: Optional[Exception] = None
    ):
        """
        Initialize SSH connection error.

        Args:
            message: User-friendly error message
            device_ip: Target device IP address
            suggestions: List of resolution suggestions
            original_error: Original exception for debugging
        """
        super().__init__(message)
        self.message = message
        self.device_ip = device_ip
        self.suggestions = suggestions or []
        self.original_error = original_error

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize exception for API response.

        Returns:
            Dict with error_type, message, device_ip, suggestions, original_error
        """
        return {
            "error_type": self.error_type,
            "message": self.message,
            "device_ip": self.device_ip,
            "suggestions": self.suggestions,
            "original_error": str(self.original_error) if self.original_error else None
        }

    def __str__(self) -> str:
        return self.message


class SSHAuthenticationError(SSHConnectionError):
    """
    Raised when SSH authentication fails.

    Common causes:
    - Wrong username or password
    - Account locked or disabled
    - SSH authentication not enabled on device
    """

    error_type: str = "authentication_error"
    http_status: int = 401

    def __init__(
        self,
        device_ip: str,
        original_error: Optional[Exception] = None,
        message: Optional[str] = None
    ):
        super().__init__(
            message=message or f"Authentication failed for {device_ip}",
            device_ip=device_ip,
            suggestions=[
                "Verify the username and password are correct",
                "Check if the account is locked or disabled on the device",
                "Ensure SSH authentication is enabled on the device",
                "Verify the user has appropriate privileges for SSH access"
            ],
            original_error=original_error
        )


class SSHConnectionTimeoutError(SSHConnectionError):
    """
    Raised when SSH connection times out.

    Common causes:
    - Device is slow to respond
    - Network latency issues
    - Device under heavy load
    - Firewall dropping packets
    """

    error_type: str = "timeout_error"
    http_status: int = 504

    def __init__(
        self,
        device_ip: str,
        original_error: Optional[Exception] = None,
        message: Optional[str] = None
    ):
        super().__init__(
            message=message or f"Connection timed out to {device_ip}",
            device_ip=device_ip,
            suggestions=[
                "Verify the device is powered on and responsive",
                "Check network connectivity to the device",
                "Increase the connection timeout if the device is slow",
                "Check if a firewall is blocking or rate-limiting SSH connections"
            ],
            original_error=original_error
        )


class SSHNetworkError(SSHConnectionError):
    """
    Raised when the device is unreachable or connection is refused.

    Common causes:
    - Device is offline
    - Wrong IP address
    - SSH service not running
    - Firewall blocking port 22
    - Network routing issues
    """

    error_type: str = "connection_error"
    http_status: int = 503

    def __init__(
        self,
        device_ip: str,
        original_error: Optional[Exception] = None,
        message: Optional[str] = None
    ):
        super().__init__(
            message=message or f"Cannot connect to {device_ip}",
            device_ip=device_ip,
            suggestions=[
                "Verify the IP address is correct",
                "Check if the device is powered on and reachable (try ping)",
                "Ensure SSH service is running on the device",
                "Check if a firewall is blocking port 22",
                "Verify network routing to the device"
            ],
            original_error=original_error
        )


class SSHAlgorithmMismatchError(SSHConnectionError):
    """
    Raised when SSH key exchange or encryption algorithm negotiation fails.

    Common causes:
    - Device running outdated SSH version
    - Incompatible cipher suites
    - Legacy SSH configuration on device
    """

    error_type: str = "algorithm_mismatch"
    http_status: int = 502

    def __init__(
        self,
        device_ip: str,
        original_error: Optional[Exception] = None,
        message: Optional[str] = None
    ):
        super().__init__(
            message=message or f"SSH algorithm negotiation failed with {device_ip}",
            device_ip=device_ip,
            suggestions=[
                "The device may be running an outdated SSH version",
                "Check if the device supports modern SSH algorithms",
                "Consider upgrading the device's SSH implementation",
                "Enable legacy SSH algorithms on the management server if needed"
            ],
            original_error=original_error
        )


class SSHHostKeyError(SSHConnectionError):
    """
    Raised when SSH host key verification fails.

    Common causes:
    - Host key changed (device replaced or reinstalled)
    - Man-in-the-middle attack (unlikely but possible)
    - Known hosts file mismatch
    """

    error_type: str = "host_key_error"
    http_status: int = 502

    def __init__(
        self,
        device_ip: str,
        original_error: Optional[Exception] = None,
        message: Optional[str] = None
    ):
        super().__init__(
            message=message or f"Host key verification failed for {device_ip}",
            device_ip=device_ip,
            suggestions=[
                "The device's SSH host key may have changed",
                "If the device was recently reinstalled, clear the old host key",
                "Verify you are connecting to the correct device",
                "Check for potential network security issues"
            ],
            original_error=original_error
        )


def map_ssh_exception(error: Exception, device_ip: str) -> SSHConnectionError:
    """
    Map low-level SSH exceptions to our exception hierarchy.

    Analyzes the exception type and error message to return the most
    appropriate SSHConnectionError subclass.

    Args:
        error: The original exception
        device_ip: Target device IP address

    Returns:
        Appropriate SSHConnectionError subclass
    """
    error_str = str(error).lower()
    error_type = type(error).__name__

    # Handle Netmiko exceptions
    if "NetmikoAuthenticationException" in error_type or "AuthenticationException" in error_type:
        return SSHAuthenticationError(device_ip, original_error=error)

    if "NetmikoTimeoutException" in error_type or "NetMikoTimeoutException" in error_type:
        return SSHConnectionTimeoutError(device_ip, original_error=error)

    # Handle Paramiko exceptions
    if "IncompatiblePeer" in error_type:
        return SSHAlgorithmMismatchError(device_ip, original_error=error)

    if "BadHostKeyException" in error_type:
        return SSHHostKeyError(device_ip, original_error=error)

    if "NoValidConnectionsError" in error_type:
        return SSHNetworkError(device_ip, original_error=error)

    if "SSHException" in error_type:
        # Analyze SSHException message for more specific categorization
        if "authentication" in error_str or "auth" in error_str:
            return SSHAuthenticationError(device_ip, original_error=error)
        if "algorithm" in error_str or "cipher" in error_str or "key exchange" in error_str:
            return SSHAlgorithmMismatchError(device_ip, original_error=error)
        if "host key" in error_str:
            return SSHHostKeyError(device_ip, original_error=error)

    # Handle socket errors
    if "OSError" in error_type or "socket" in error_type.lower() or "ConnectionError" in error_type:
        # Check errno if available
        if hasattr(error, 'errno'):
            errno = error.errno
            if errno == 110:  # ETIMEDOUT
                return SSHConnectionTimeoutError(device_ip, original_error=error)
            if errno in (111, 113):  # ECONNREFUSED, EHOSTUNREACH
                return SSHNetworkError(device_ip, original_error=error)

        # Fallback to message analysis
        if "timed out" in error_str or "timeout" in error_str:
            return SSHConnectionTimeoutError(device_ip, original_error=error)
        if "refused" in error_str or "unreachable" in error_str or "no route" in error_str:
            return SSHNetworkError(device_ip, original_error=error)

    # Analyze error message as fallback
    if "authentication" in error_str or "password" in error_str or "credential" in error_str:
        return SSHAuthenticationError(device_ip, original_error=error)

    if "timeout" in error_str or "timed out" in error_str:
        return SSHConnectionTimeoutError(device_ip, original_error=error)

    if "refused" in error_str or "unreachable" in error_str or "no route" in error_str:
        return SSHNetworkError(device_ip, original_error=error)

    if "algorithm" in error_str or "cipher" in error_str or "key exchange" in error_str or "incompatible" in error_str:
        return SSHAlgorithmMismatchError(device_ip, original_error=error)

    if "host key" in error_str:
        return SSHHostKeyError(device_ip, original_error=error)

    # Default: return base SSHConnectionError
    return SSHConnectionError(
        message=f"SSH connection failed to {device_ip}: {str(error)}",
        device_ip=device_ip,
        suggestions=[
            "Check network connectivity to the device",
            "Verify SSH credentials are correct",
            "Ensure SSH is enabled on the device",
            "Check firewall rules allow SSH access"
        ],
        original_error=error
    )
