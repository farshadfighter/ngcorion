"""
WinRM endpoint helper.

The default WinRM listener port is 5985, which speaks **HTTP**; 5986 is the
optional HTTPS listener. Both clients in this package used to hardcode
``https://`` regardless of the port, so pointing them at 5985 produced a TLS
handshake against a plaintext listener instead of a working connection.

Keeping the mapping here means the audit client and the hardening executor
cannot drift apart, and an explicit HTTPS deployment on 5986 (or any other
port) keeps working.
"""

# IANA/Microsoft defaults for the two WinRM listeners.
WINRM_HTTP_PORT = 5985
WINRM_HTTPS_PORT = 5986

# Product-wide default for Windows Server auditing and hardening.
DEFAULT_WINRM_PORT = WINRM_HTTP_PORT


def winrm_use_ssl(port: int) -> bool:
    """True when this port should be reached over HTTPS.

    Only the plaintext listener port is treated as HTTP; every other port —
    5986 included, and any custom HTTPS listener an operator configures —
    stays on TLS, so an explicit HTTPS setup is never silently downgraded.
    """
    return int(port) != WINRM_HTTP_PORT


def winrm_endpoint(ip: str, port: int) -> str:
    """Full ``/wsman`` URL for a host, with the scheme implied by the port."""
    scheme = "https" if winrm_use_ssl(port) else "http"
    return f"{scheme}://{ip}:{port}/wsman"
