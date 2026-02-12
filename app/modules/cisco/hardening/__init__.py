"""
Cisco Hardening Module

Device hardening operations for Cisco IOS/IOS-XE devices.
"""
from .router import router
from .service import HardeningService, CheckAlreadyPassingError, MissingParametersError
from .ssh_executor import CiscoHardeningExecutor, redact_secrets_in_output
from .command_parser import RemediationParser, apply_defaults
from .command_templates import COMMAND_TEMPLATES, has_template, get_template
from .parameter_metadata import PARAMETER_REGISTRY, ParameterMetadata

__all__ = [
    "router",
    "HardeningService",
    "CheckAlreadyPassingError",
    "MissingParametersError",
    "CiscoHardeningExecutor",
    "redact_secrets_in_output",
    "RemediationParser",
    "apply_defaults",
    "COMMAND_TEMPLATES",
    "has_template",
    "get_template",
    "PARAMETER_REGISTRY",
    "ParameterMetadata",
]
