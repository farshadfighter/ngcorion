"""
MongoDB Hardening Parameter Metadata

UI metadata for each hardening parameter used in MongoDB command templates.
Drives dynamic form generation in the frontend.

IMPORTANT: Every check in MONGODB_CHECK_PARAMETER_MAP must be present or
it will be classified as "not_supported" by the categorize function.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .command_templates import (
    get_mongodb_hardening_template,
    get_mongodb_template_commands,
    get_mongodb_verify_commands,
)


@dataclass
class ParameterMetadata:
    """Metadata for a single hardening parameter."""
    name: str
    input_type: str  # text, number, ip, select, textarea
    label: str
    description: str
    required: bool = True
    default: Optional[str] = None
    placeholder: Optional[str] = None
    validation: Optional[str] = None
    options: Optional[List[str]] = None
    min_value: Optional[int] = None
    max_value: Optional[int] = None


# ===================================================================
# Parameter registry
# ===================================================================

MONGODB_PARAMETER_REGISTRY: Dict[str, ParameterMetadata] = {

    "MONGO_SERVICE_USER": ParameterMetadata(
        name="MONGO_SERVICE_USER",
        input_type="text",
        label="MongoDB Service User",
        description="OS user account under which mongod runs",
        required=False,
        default="mongod",
        placeholder="mongod",
    ),

    "MONGO_PORT": ParameterMetadata(
        name="MONGO_PORT",
        input_type="number",
        label="MongoDB Port",
        description="TCP port MongoDB listens on (CIS recommends a non-default port)",
        required=True,
        placeholder="27017",
        min_value=1024,
        max_value=65535,
    ),

    "MONGO_BIND_IP": ParameterMetadata(
        name="MONGO_BIND_IP",
        input_type="ip",
        label="MongoDB Bind IP",
        description="IP address MongoDB binds to (use 127.0.0.1 to restrict to localhost)",
        required=False,
        default="127.0.0.1",
        placeholder="127.0.0.1",
    ),

    "TLS_CERT_FILE": ParameterMetadata(
        name="TLS_CERT_FILE",
        input_type="text",
        label="TLS Certificate Key File",
        description="Absolute path to the PEM file containing the server TLS certificate and key",
        required=True,
        placeholder="/etc/ssl/mongodb/mongod.pem",
    ),

    "TLS_CA_FILE": ParameterMetadata(
        name="TLS_CA_FILE",
        input_type="text",
        label="TLS CA File",
        description="Absolute path to the PEM file containing the Certificate Authority certificate",
        required=True,
        placeholder="/etc/ssl/mongodb/ca.pem",
    ),

    "TLS_MODE": ParameterMetadata(
        name="TLS_MODE",
        input_type="select",
        label="TLS Mode",
        description="TLS enforcement mode for incoming connections",
        required=False,
        options=["requireTLS", "allowTLS", "preferTLS"],
        default="requireTLS",
    ),

    "DISABLED_PROTOCOLS": ParameterMetadata(
        name="DISABLED_PROTOCOLS",
        input_type="text",
        label="Disabled TLS Protocols",
        description="Comma-separated TLS protocol versions to disable (e.g. TLS1_0,TLS1_1)",
        required=False,
        default="TLS1_0,TLS1_1",
        placeholder="TLS1_0,TLS1_1",
    ),

    "AUDIT_LOG_PATH": ParameterMetadata(
        name="AUDIT_LOG_PATH",
        input_type="text",
        label="Audit Log Path",
        description="Absolute path where the MongoDB audit log will be written",
        required=False,
        default="/var/log/mongodb/auditLog.json",
        placeholder="/var/log/mongodb/auditLog.json",
    ),

    "AUDIT_FORMAT": ParameterMetadata(
        name="AUDIT_FORMAT",
        input_type="select",
        label="Audit Log Format",
        description="Output format for the MongoDB audit log",
        required=False,
        options=["JSON", "BSON"],
        default="JSON",
    ),

    "PROFILING_MODE": ParameterMetadata(
        name="PROFILING_MODE",
        input_type="select",
        label="Profiling Mode",
        description="MongoDB operation profiling level",
        required=False,
        options=["slowOp", "all", "off"],
        default="slowOp",
    ),

    "SLOW_OP_MS": ParameterMetadata(
        name="SLOW_OP_MS",
        input_type="number",
        label="Slow Op Threshold (ms)",
        description="Operations slower than this threshold (ms) are logged when profiling is enabled",
        required=False,
        default="100",
        min_value=1,
        max_value=10000,
    ),

    "KEYFILE_PATH": ParameterMetadata(
        name="KEYFILE_PATH",
        input_type="text",
        label="Keyfile Path",
        description="Absolute path for the internal authentication keyfile",
        required=True,
        placeholder="/etc/mongodb/keyfile",
    ),

    "ENABLE_IPV6": ParameterMetadata(
        name="ENABLE_IPV6",
        input_type="select",
        label="Enable IPv6",
        description="Whether MongoDB should accept IPv6 connections",
        required=False,
        options=["true", "false"],
        default="false",
    ),
}


# ===================================================================
# Check → parameter mapping
# ===================================================================
# Every check that has (or could have) a hardening template must appear here.
# Checks with [] are auto-fixable with no user input.
# Checks with parameter names require at least one value before execution.

MONGODB_CHECK_PARAMETER_MAP: Dict[str, List[str]] = {
    # Parameterized
    "MONGO-L1-002": ["MONGO_SERVICE_USER"],
    "MONGO-L1-008": ["MONGO_PORT"],
    "MONGO-L1-010": ["MONGO_BIND_IP"],
    "MONGO-L1-014": ["TLS_CERT_FILE", "TLS_CA_FILE", "TLS_MODE"],
    "MONGO-L2-017": ["DISABLED_PROTOCOLS"],
    "MONGO-L2-018": ["AUDIT_LOG_PATH", "AUDIT_FORMAT"],
    "MONGO-L1-019": ["PROFILING_MODE", "SLOW_OP_MS"],
    "MONGO-L1-021": ["KEYFILE_PATH"],
    "MONGO-L1-024": ["ENABLE_IPV6"],

    # Auto-fixable (no required params)
    "MONGO-L1-003": [],
    "MONGO-L1-004": [],
    "MONGO-L1-005": [],
    "MONGO-L1-006": [],
    "MONGO-L1-007": [],
    "MONGO-L1-009": [],
    "MONGO-L1-011": [],
    "MONGO-L1-015": [],
    "MONGO-L2-016": [],
    "MONGO-L1-020": [],
    "MONGO-L1-023": [],
    "MONGO-L2-022": [],
    "MONGO-L1-025": [],

    # Manual / not auto-fixable via SSH (mongosh or manual review required)
    # MONGO-L1-001: running as root — OS-level, covered by MONGO-L1-002
    # MONGO-L1-012: user root roles — requires mongosh + manual review
    # MONGO-L2-013: any-database roles — requires mongosh + manual review
}


# ===================================================================
# Helper functions  (mirror Linux parameter_metadata helpers)
# ===================================================================

def get_mongodb_parameter_metadata(param_name: str) -> Optional[ParameterMetadata]:
    """Return metadata for a parameter by name."""
    return MONGODB_PARAMETER_REGISTRY.get(param_name)


def get_mongodb_parameters_for_check(check_id: str) -> List[ParameterMetadata]:
    """Return all ParameterMetadata objects for the given check."""
    param_names = MONGODB_CHECK_PARAMETER_MAP.get(check_id, [])
    return [
        MONGODB_PARAMETER_REGISTRY[name]
        for name in param_names
        if name in MONGODB_PARAMETER_REGISTRY
    ]


def is_mongodb_check_auto_fixable(check_id: str) -> bool:
    """
    Return True if the check can be fixed without any user-supplied values.

    A check is auto-fixable when:
    - It exists in MONGODB_CHECK_PARAMETER_MAP, AND
    - It has no parameters, OR all its parameters have default values.
    """
    if check_id not in MONGODB_CHECK_PARAMETER_MAP:
        return False
    params = get_mongodb_parameters_for_check(check_id)
    if not params:
        return True
    return all(p.default is not None for p in params)


def get_mongodb_check_defaults(check_id: str) -> Dict[str, str]:
    """Return a dict of {param_name: default_value} for all params with defaults."""
    params = get_mongodb_parameters_for_check(check_id)
    return {p.name: p.default for p in params if p.default is not None}


def aggregate_mongodb_parameters_for_checks(check_ids: List[str]) -> Dict[str, Any]:
    """
    Aggregate unique parameters needed across multiple checks.

    Returns a dict keyed by parameter name with metadata and which checks use it.
    """
    aggregated: Dict[str, Any] = {}

    for check_id in check_ids:
        for param in get_mongodb_parameters_for_check(check_id):
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
                    "checks": [check_id],
                }
            else:
                if check_id not in aggregated[param.name]["checks"]:
                    aggregated[param.name]["checks"].append(check_id)

    return aggregated


def categorize_mongodb_checks_by_fixability(check_ids: List[str]) -> Dict[str, List[str]]:
    """
    Split a list of check IDs into auto_fixable, needs_params, and not_supported.
    """
    auto_fixable: List[str] = []
    needs_params: List[str] = []
    not_supported: List[str] = []

    for check_id in check_ids:
        if check_id not in MONGODB_CHECK_PARAMETER_MAP:
            not_supported.append(check_id)
        elif is_mongodb_check_auto_fixable(check_id):
            auto_fixable.append(check_id)
        else:
            needs_params.append(check_id)

    return {
        "auto_fixable": auto_fixable,
        "needs_params": needs_params,
        "not_supported": not_supported,
    }


def get_mongodb_auto_fix_preview(check_ids: List[str]) -> List[Dict[str, Any]]:
    """Return preview items for auto-fixable checks with their default parameter values."""
    preview = []
    for check_id in check_ids:
        if is_mongodb_check_auto_fixable(check_id):
            defaults = get_mongodb_check_defaults(check_id)
            preview.append({
                "check_id": check_id,
                # Same value under the key the Apache/Linux previews use, so
                # the shared UI can read either shape.
                "check_number": check_id,
                "defaults": defaults,
                "has_defaults": bool(defaults),
            })
    return preview
