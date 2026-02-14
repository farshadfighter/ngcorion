"""
Apache Hardening Parameter Metadata

Defines UI metadata for hardening parameters and maps checks to their required parameters.
Used for:
- Generating dynamic forms in the frontend
- Categorizing checks by fixability (auto-fixable vs needs-params vs not-supported)
- Providing CIS default values for auto-hardening
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class ParameterMetadata:
    """Metadata for a single hardening parameter."""
    name: str                           # Parameter name (matches {PARAM} in commands)
    input_type: str                     # password, text, textarea, number, select
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
        description="SSL protocol configuration. Use 'all -SSLv3 -TLSv1 -TLSv1.1' to disable insecure protocols.",
        required=False,
        default="all -SSLv3 -TLSv1 -TLSv1.1",
        placeholder="all -SSLv3 -TLSv1 -TLSv1.1"
    ),
    "SSL_CIPHER_SUITE": ParameterMetadata(
        name="SSL_CIPHER_SUITE",
        input_type="text",
        label="SSL Cipher Suite",
        description="Strong cipher suite configuration for Apache SSL.",
        required=False,
        default="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
        placeholder="ECDHE-ECDSA-AES128-GCM-SHA256:..."
    ),
    "HSTS_MAX_AGE": ParameterMetadata(
        name="HSTS_MAX_AGE",
        input_type="number",
        label="HSTS Max Age (seconds)",
        description="HTTP Strict Transport Security max-age directive in seconds. 31536000 = 1 year.",
        required=False,
        default="31536000",
        min_value=86400,
        max_value=63072000
    ),
    "X_FRAME_OPTIONS": ParameterMetadata(
        name="X_FRAME_OPTIONS",
        input_type="select",
        label="X-Frame-Options Value",
        description="Controls whether the page can be displayed in frames. SAMEORIGIN allows same-origin framing, DENY blocks all.",
        required=False,
        default="SAMEORIGIN",
        options=["SAMEORIGIN", "DENY"]
    ),
}


# ==================== CHECK-TO-PARAMETER MAP ====================

# Maps each CIS check ID to the list of parameters it requires
# If a check has no parameters, it can be auto-fixed
# If a check is not in this map, it's not supported for hardening

APACHE_CHECK_PARAMETER_MAP: Dict[str, List[str]] = {
    # Section 2: Modules
    "APACHE-L1-2.5": [],                    # Disable mod_info (no params)
    "APACHE-L1-2.6": [],                    # Disable mod_userdir (no params)
    "APACHE-L1-2.7": [],                    # Disable autoindex (no params)

    # Section 5: Features
    "APACHE-L1-5.8": [],                    # Disable TRACE (no params)

    # Section 6: Logging
    "APACHE-L1-6.1": [],                    # Configure error logging (no params)

    # Section 7: Request Limits
    "APACHE-L1-7.1": [],                    # Configure Timeout (no params)

    # Section 8: SSL/TLS
    "APACHE-L1-8.1": [],                    # Enable SSL module (no params)
    "APACHE-L1-8.3": ["SSL_PROTOCOLS"],     # SSL protocols (has default)
    "APACHE-L1-8.4": ["SSL_CIPHER_SUITE"],  # SSL ciphers (has default)
    "APACHE-L1-8.5": [],                    # SSLHonorCipherOrder (no params)
    "APACHE-L1-8.6": [],                    # SSLCompression off (no params)
    "APACHE-L1-8.8": ["HSTS_MAX_AGE"],      # HSTS header (has default)

    # Section 9: Information Leakage
    "APACHE-L1-9.1": [],                    # ServerTokens Prod (no params)
    "APACHE-L1-9.2": [],                    # ServerSignature Off (no params)

    # Section 10: HTTP Configuration
    "APACHE-L1-10.5": [],                   # X-Content-Type-Options (no params)
    "APACHE-L1-10.6": ["X_FRAME_OPTIONS"],  # X-Frame-Options (has default)
}


# ==================== HELPER FUNCTIONS ====================

def get_apache_parameters_for_check(check_number: str) -> List[ParameterMetadata]:
    """
    Get parameter metadata for a specific check.

    Args:
        check_number: CIS check ID (e.g., "APACHE-L1-8.3")

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
