"""
Apache Hardening Parameter Metadata

Defines UI metadata for hardening parameters and maps checks to their required parameters.
Used for:
- Generating dynamic forms in the frontend
- Categorizing checks by fixability (auto-fixable vs needs-params vs not-supported)
- Providing CIS default values for auto-hardening

IMPORTANT: Every check that has a template in command_templates.py must be
present in APACHE_CHECK_PARAMETER_MAP or it will be classified as
"not_supported" by the categorize function.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class ParameterMetadata:
    """Metadata for a single hardening parameter."""
    name: str                           # Parameter name (matches {PARAM} in commands)
    input_type: str                     # password, text, textarea, number, select, ip
    label: str                          # UI display label
    description: str                    # Help text / tooltip
    required: bool = True
    default: Optional[str] = None       # CIS default value (if available)
    placeholder: Optional[str] = None
    validation: Optional[str] = None    # e.g., "min_length:8"
    options: Optional[List[str]] = None # For select type
    min_value: Optional[int] = None
    max_value: Optional[int] = None


# ==================== PARAMETER REGISTRY ====================

APACHE_PARAMETER_REGISTRY: Dict[str, ParameterMetadata] = {
    "SSL_PROTOCOLS": ParameterMetadata(
        name="SSL_PROTOCOLS",
        input_type="text",
        label="SSL/TLS Protocols",
        description="SSLProtocol value. 'all -SSLv3 -TLSv1 -TLSv1.1' disables the insecure protocol versions (CIS 7.4).",
        required=False,
        default="all -SSLv3 -TLSv1 -TLSv1.1",
        placeholder="all -SSLv3 -TLSv1 -TLSv1.1"
    ),
    "SSL_CIPHER_SUITE": ParameterMetadata(
        name="SSL_CIPHER_SUITE",
        input_type="text",
        label="SSL Cipher Suite",
        description="SSLCipherSuite value excluding weak/medium ciphers with forward secrecy only (CIS 7.5 / 7.8 / 7.12).",
        required=False,
        default=(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "!aNULL:!eNULL:!EXP:!LOW:!RC4:!3DES:!IDEA"
        ),
        placeholder="ECDHE-ECDSA-AES128-GCM-SHA256:..."
    ),
    "HSTS_MAX_AGE": ParameterMetadata(
        name="HSTS_MAX_AGE",
        input_type="number",
        label="HSTS Max Age (seconds)",
        description="HTTP Strict Transport Security max-age directive in seconds. 31536000 = 1 year (CIS 7.11).",
        required=False,
        default="31536000",
        min_value=86400,
        max_value=63072000
    ),
    "X_FRAME_OPTIONS": ParameterMetadata(
        name="X_FRAME_OPTIONS",
        input_type="select",
        label="X-Frame-Options Value",
        description="Controls whether the site can be framed. SAMEORIGIN allows same-origin framing, DENY blocks all (CIS 5.14).",
        required=False,
        default="SAMEORIGIN",
        options=["SAMEORIGIN", "DENY"]
    ),
    "SSL_CERT_FILE": ParameterMetadata(
        name="SSL_CERT_FILE",
        input_type="text",
        label="SSL Certificate File",
        description="Absolute path to the PEM certificate issued by a trusted CA, already uploaded to the server (CIS 7.2).",
        required=True,
        placeholder="/etc/ssl/certs/server.crt"
    ),
    "SSL_KEY_FILE": ParameterMetadata(
        name="SSL_KEY_FILE",
        input_type="text",
        label="SSL Private Key File",
        description="Absolute path to the certificate's private key, already uploaded to the server (CIS 7.2).",
        required=True,
        placeholder="/etc/ssl/private/server.key"
    ),
    "RESTRICTED_EXTENSIONS": ParameterMetadata(
        name="RESTRICTED_EXTENSIONS",
        input_type="text",
        label="Restricted File Extensions",
        description="Pipe-separated extensions to deny (used inside a FilesMatch regex) — backup/source/config files (CIS 5.11).",
        required=False,
        default="bak|old|orig|save|inc|sql|ini|log|sh",
        placeholder="bak|old|orig|save|inc|sql|ini|log|sh"
    ),
    "LISTEN_IP": ParameterMetadata(
        name="LISTEN_IP",
        input_type="ip",
        label="Listen IP Address",
        description="The specific IP address Apache should listen on; bare 'Listen <port>' directives are rewritten to it (CIS 5.13).",
        required=True,
        placeholder="10.0.0.5"
    ),
}


# ==================== CHECK-TO-PARAMETER MAP ====================

# Maps each CIS check ID to the list of parameters it requires.
# If a check has no parameters (or all its parameters carry defaults), it can
# be auto-fixed. If a check is not in this map, it's not supported for
# hardening.

APACHE_CHECK_PARAMETER_MAP: Dict[str, List[str]] = {
    # Section 2: Modules (no params)
    "APACHE-L1-2.2": [],                    # Enable log_config
    "APACHE-L1-2.3": [],                    # Disable WebDAV
    "APACHE-L1-2.4": [],                    # Disable status
    "APACHE-L1-2.5": [],                    # Disable autoindex
    "APACHE-L1-2.6": [],                    # Disable proxy
    "APACHE-L1-2.7": [],                    # Disable userdir
    "APACHE-L1-2.8": [],                    # Disable info
    "APACHE-L2-2.9": [],                    # Disable basic/digest auth

    # Section 3: Permissions and ownership (no params)
    "APACHE-L1-3.2": [],                    # Invalid shell
    "APACHE-L1-3.3": [],                    # Lock account
    "APACHE-L1-3.4": [],                    # Owner root
    "APACHE-L1-3.5": [],                    # Group root
    "APACHE-L1-3.6": [],                    # No other-write
    "APACHE-L1-3.11": [],                   # No group-write
    "APACHE-L1-3.12": [],                   # No group-write on docroot

    # Section 4: Access control (no params)
    "APACHE-L1-4.1": [],                    # Root dir denied
    "APACHE-L1-4.3": [],                    # OverRide None for root dir
    "APACHE-L1-4.4": [],                    # OverRide None everywhere

    # Section 5: Features, content and options
    "APACHE-L1-5.1": [],                    # Options None for root dir
    "APACHE-L1-5.2": [],                    # Web root options restricted
    "APACHE-L1-5.4": [],                    # Remove default HTML content
    "APACHE-L1-5.5": [],                    # Remove printenv
    "APACHE-L1-5.6": [],                    # Remove test-cgi
    "APACHE-L1-5.8": [],                    # Disable TRACE
    "APACHE-L1-5.10": [],                   # Restrict .ht* files
    "APACHE-L1-5.11": ["RESTRICTED_EXTENSIONS"],  # Restrict extensions (has default)
    "APACHE-L2-5.13": ["LISTEN_IP"],        # Explicit Listen IPs (required)
    "APACHE-L1-5.14": ["X_FRAME_OPTIONS"],  # Framing (has default)

    # Section 6: Logging, monitoring, maintenance
    "APACHE-L1-6.1": [],                    # Error log + level
    "APACHE-L1-6.3": [],                    # Access log
    "APACHE-L1-6.4": [],                    # Log rotation
    "APACHE-L1-6.5": [],                    # Apply patches
    "APACHE-L2-6.6": [],                    # ModSecurity
    "APACHE-L2-6.7": [],                    # OWASP CRS

    # Section 7: SSL/TLS
    "APACHE-L1-7.1": [],                            # Enable mod_ssl
    "APACHE-L1-7.2": ["SSL_CERT_FILE", "SSL_KEY_FILE"],  # Install cert (required)
    "APACHE-L1-7.3": [],                            # Protect private key
    "APACHE-L1-7.4": ["SSL_PROTOCOLS"],             # Protocols (has default)
    "APACHE-L1-7.5": ["SSL_CIPHER_SUITE"],          # Weak ciphers (has default)
    "APACHE-L1-7.6": [],                            # Insecure renegotiation off
    "APACHE-L1-7.7": [],                            # SSL compression off
    "APACHE-L1-7.8": ["SSL_CIPHER_SUITE"],          # Medium ciphers (has default)
    "APACHE-L1-7.10": [],                           # OCSP stapling
    "APACHE-L1-7.11": ["HSTS_MAX_AGE"],             # HSTS (has default)
    "APACHE-L2-7.12": ["SSL_CIPHER_SUITE"],         # Forward secrecy (has default)

    # Section 8: Information leakage
    "APACHE-L1-8.1": [],                    # ServerTokens Prod
    "APACHE-L1-8.2": [],                    # ServerSignature Off
    "APACHE-L1-8.3": [],                    # Remove default content
    "APACHE-L1-8.4": [],                    # FileETag None

    # Section 9: DoS mitigations
    "APACHE-L1-9.1": [],                    # Timeout 10
    "APACHE-L1-9.2": [],                    # KeepAlive On
    "APACHE-L1-9.3": [],                    # MaxKeepAliveRequests 100
    "APACHE-L1-9.4": [],                    # KeepAliveTimeout 15
    "APACHE-L1-9.5": [],                    # Header read timeout
    "APACHE-L1-9.6": [],                    # Body read timeout

    # Section 10: Request limits
    "APACHE-L1-10.1": [],                   # LimitRequestLine 512
    "APACHE-L1-10.2": [],                   # LimitRequestFields 100
    "APACHE-L1-10.3": [],                   # LimitRequestFieldSize 1024
    "APACHE-L1-10.4": [],                   # LimitRequestBody 102400

    # Section 11: SELinux (RHEL)
    "APACHE-L2-11.1": [],                   # Enforcing mode

    # Section 12: AppArmor (Debian)
    "APACHE-L2-12.1": [],                   # Framework enabled
    "APACHE-L2-12.3": [],                   # Profile in enforce mode

    # Not auto-fixable via SSH (site-specific decisions / manual review):
    # 3.1 run-as user, 3.7-3.10 runtime file locations, 5.3 per-dir Options,
    # 5.7 method limits, 5.9/5.12 rewrite policies, 6.2 syslog facility,
    # 7.9 HTTPS redirects, 11.2/11.3 SELinux contexts, and all Manual controls
    # (1.1-1.3, 2.1, 3.13, 4.2, 11.4, 12.2).
}


# ==================== HELPER FUNCTIONS ====================

def get_apache_parameters_for_check(check_number: str) -> List[ParameterMetadata]:
    """
    Get parameter metadata for a specific check.

    Args:
        check_number: CIS check ID (e.g., "APACHE-L1-7.4")

    Returns:
        List of ParameterMetadata objects for the check's parameters
    """
    param_names = APACHE_CHECK_PARAMETER_MAP.get(check_number, [])
    return [
        APACHE_PARAMETER_REGISTRY[name]
        for name in param_names
        if name in APACHE_PARAMETER_REGISTRY
    ]


def is_apache_check_auto_fixable(check_number: str) -> bool:
    """
    Check if a check can be auto-fixed (no params or all params have defaults).

    Args:
        check_number: CIS check ID

    Returns:
        True if the check can be auto-fixed with CIS defaults
    """
    if check_number not in APACHE_CHECK_PARAMETER_MAP:
        return False  # Not supported

    params = get_apache_parameters_for_check(check_number)
    if not params:
        return True  # No parameters needed

    # All parameters have defaults
    return all(p.default is not None for p in params)


def get_apache_check_defaults(check_number: str) -> Dict[str, str]:
    """
    Get default parameter values for a check.

    Args:
        check_number: CIS check ID

    Returns:
        Dict of parameter names to their default values
    """
    params = get_apache_parameters_for_check(check_number)
    return {p.name: p.default for p in params if p.default is not None}


def categorize_apache_checks_by_fixability(check_numbers: List[str]) -> Dict[str, List[str]]:
    """
    Categorize checks into auto_fixable, needs_params, and not_supported.

    Args:
        check_numbers: List of CIS check IDs to categorize

    Returns:
        Dict with keys: auto_fixable, needs_params, not_supported
    """
    auto_fixable = []
    needs_params = []
    not_supported = []

    for check_number in check_numbers:
        if check_number not in APACHE_CHECK_PARAMETER_MAP:
            not_supported.append(check_number)
        elif is_apache_check_auto_fixable(check_number):
            auto_fixable.append(check_number)
        else:
            needs_params.append(check_number)

    return {
        "auto_fixable": auto_fixable,
        "needs_params": needs_params,
        "not_supported": not_supported
    }


def aggregate_apache_parameters_for_checks(check_numbers: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate unique parameters needed for a set of checks (for UI form generation).

    Args:
        check_numbers: List of CIS check IDs

    Returns:
        Dict of parameter name -> metadata dict (for JSON serialization)
    """
    aggregated: Dict[str, Dict[str, Any]] = {}

    for check_number in check_numbers:
        params = get_apache_parameters_for_check(check_number)
        for param in params:
            if param.name not in aggregated:
                aggregated[param.name] = {
                    "type": param.input_type,
                    "label": param.label,
                    "description": param.description,
                    "required": param.required and param.default is None,
                    "default": param.default,
                    "placeholder": param.placeholder,
                    "validation": param.validation,
                    "options": param.options,
                    "min_value": param.min_value,
                    "max_value": param.max_value,
                    "checks": [check_number]
                }
            else:
                # Parameter already added, just track which checks use it
                if check_number not in aggregated[param.name]["checks"]:
                    aggregated[param.name]["checks"].append(check_number)

    return aggregated


def get_apache_auto_fix_preview(check_numbers: List[str]) -> List[Dict[str, Any]]:
    """
    Generate preview of what will be auto-fixed with CIS defaults.

    Args:
        check_numbers: List of CIS check IDs to preview

    Returns:
        List of dicts with check_number and defaults that will be applied
    """
    preview = []

    for check_number in check_numbers:
        if is_apache_check_auto_fixable(check_number):
            defaults = get_apache_check_defaults(check_number)
            preview.append({
                "check_number": check_number,
                "defaults": defaults,
                "has_defaults": bool(defaults)
            })

    return preview


def get_all_supported_checks() -> List[str]:
    """Get list of all check IDs that have hardening support."""
    return list(APACHE_CHECK_PARAMETER_MAP.keys())


def get_parameter_form_data(check_numbers: List[str]) -> Dict[str, Any]:
    """
    Get complete form data for frontend UI generation.

    Args:
        check_numbers: List of failed check IDs

    Returns:
        Dict with parameters, categorization, and metadata
    """
    categorized = categorize_apache_checks_by_fixability(check_numbers)
    parameters = aggregate_apache_parameters_for_checks(
        categorized["needs_params"] + categorized["auto_fixable"]
    )

    return {
        "total_failed": len(check_numbers),
        "categorized_checks": categorized,
        "parameters": parameters,
        "auto_fixable_count": len(categorized["auto_fixable"]),
        "needs_params_count": len(categorized["needs_params"]),
        "not_supported_count": len(categorized["not_supported"])
    }
