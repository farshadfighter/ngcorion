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
        description="TCP port MongoDB listens on (CIS 6.2 recommends a non-default port)",
        required=True,
        placeholder="27018",
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
        description="TLS enforcement mode for incoming connections (CIS 4.1 requires requireTLS)",
        required=False,
        options=["requireTLS", "allowTLS", "preferTLS"],
        default="requireTLS",
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

    "AUDIT_FILTER": ParameterMetadata(
        name="AUDIT_FILTER",
        input_type="textarea",
        label="Audit Filter Expression",
        description=(
            "auditLog.filter document scoping the audit trail to relevant "
            "events (single quotes only — the value is wrapped in double "
            "quotes inside mongod.conf)"
        ),
        required=False,
        default=(
            "{ atype: { $in: [ 'authenticate', 'createUser', 'dropUser', "
            "'createRole', 'dropRole', 'createCollection', 'dropCollection', "
            "'dropDatabase' ] } }"
        ),
    ),

    "KEYFILE_PATH": ParameterMetadata(
        name="KEYFILE_PATH",
        input_type="text",
        label="Keyfile Path",
        description="Absolute path for the internal authentication keyfile",
        required=True,
        placeholder="/etc/mongodb/keyfile",
    ),
}


# ===================================================================
# Check → parameter mapping
# ===================================================================
# Every check that has (or could have) a hardening template must appear here.
# Checks with [] are auto-fixable with no user input.
# Checks whose parameters all carry defaults are also auto-fixable.

MONGODB_CHECK_PARAMETER_MAP: Dict[str, List[str]] = {
    # Parameterized
    "MONGO-L1-004": ["KEYFILE_PATH"],                                 # 2.3 cluster auth keyfile
    "MONGO-L1-007": ["MONGO_BIND_IP"],                                # 3.2 bind interfaces
    "MONGO-L1-008": ["MONGO_SERVICE_USER"],                           # 3.3 service account
    "MONGO-L1-012": ["TLS_CERT_FILE", "TLS_CA_FILE", "TLS_MODE"],     # 4.1 TLS in transit
    "MONGO-L1-015": ["AUDIT_LOG_PATH", "AUDIT_FORMAT"],               # 5.1 audit logging
    "MONGO-L2-016": ["AUDIT_FILTER"],                                 # 5.2 audit filter
    "MONGO-L2-020": ["MONGO_PORT"],                                   # 6.2 non-default port

    # Auto-fixable (no required params)
    "MONGO-L1-002": [],   # 2.1 authorization enabled
    "MONGO-L1-003": [],   # 2.2 localhost bypass disabled
    "MONGO-L1-005": [],   # 2.4 SCRAM-SHA-256
    "MONGO-L1-017": [],   # 5.3 systemLog.quiet false
    "MONGO-L1-018": [],   # 5.4 logAppend true
    "MONGO-L1-019": [],   # 6.1 HTTP status interface off
    "MONGO-L1-021": [],   # 6.3 OS resource limits
    "MONGO-L2-022": [],   # 6.4 server-side JS disabled
    "MONGO-L1-023": [],   # 6.5 HTTP interface off
    "MONGO-L1-024": [],   # 6.6 JSONP off
    "MONGO-L1-025": [],   # 6.7 REST API off
    "MONGO-L1-026": [],   # 7.1 keyfile permissions
    "MONGO-L1-027": [],   # 7.2 dbPath permissions

    # Not auto-fixable via SSH (manual review / migration / mongosh work):
    # MONGO-L1-001 (1.1 version upgrade), MONGO-L1-006 (3.1 RBAC users),
    # MONGO-L2-009 (3.4), MONGO-L2-010 (3.5), MONGO-L2-011 (3.6),
    # MONGO-L2-013 (4.2 encryption at rest), MONGO-L2-014 (4.3 FIPS)
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
