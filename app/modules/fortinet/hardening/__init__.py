"""
Fortinet Hardening Module

Device hardening operations for FortiGate devices.
"""
from .router import router
from .service import (
    FortiGateHardeningService,
    FortiGateCheckAlreadyPassingError,
    FortiGateMissingParametersError,
    FortiGateNotAutoFixableError
)
from .ssh_executor import (
    FortiGateHardeningExecutor,
    redact_fortigate_secrets,
    FortiGateHardeningExecutionError
)
from .command_parser import FortiGateRemediationParser, apply_fortigate_defaults
from .command_templates import FORTIGATE_COMMAND_TEMPLATES, has_fortigate_template
from .parameter_metadata import FORTIGATE_PARAMETER_REGISTRY

__all__ = [
    "router",
    "FortiGateHardeningService",
    "FortiGateCheckAlreadyPassingError",
    "FortiGateMissingParametersError",
    "FortiGateNotAutoFixableError",
    "FortiGateHardeningExecutor",
    "redact_fortigate_secrets",
    "FortiGateHardeningExecutionError",
    "FortiGateRemediationParser",
    "apply_fortigate_defaults",
    "FORTIGATE_COMMAND_TEMPLATES",
    "has_fortigate_template",
    "FORTIGATE_PARAMETER_REGISTRY",
]
