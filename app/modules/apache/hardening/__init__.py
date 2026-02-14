"""
Apache Hardening Module

Remediation of failed CIS checks for Apache HTTP Server 2.4.x
Supports Ubuntu/Debian (apache2) and RHEL/Rocky (httpd)
"""

from .router import router
from .service import ApacheHardeningService
from .ssh_executor import ApacheSSHExecutor, ApacheHardeningBatchExecutor, ApacheHardeningExecutionResult
from .command_templates import (
    APACHE_HARDENING_TEMPLATES,
    get_apache_hardening_template,
    get_apache_template_commands_for_distro,
    get_apache_verify_commands_for_distro,
    ApacheHardeningTemplate
)
from .parameter_metadata import (
    APACHE_CHECK_PARAMETER_MAP,
    APACHE_PARAMETER_REGISTRY,
    aggregate_apache_parameters_for_checks,
    categorize_apache_checks_by_fixability,
    get_apache_auto_fix_preview,
    get_apache_check_defaults,
    get_apache_parameters_for_check,
    is_apache_check_auto_fixable
)

__all__ = [
    "router",
    "ApacheHardeningService",
    "ApacheSSHExecutor",
    "ApacheHardeningBatchExecutor",
    "ApacheHardeningExecutionResult",
    "APACHE_HARDENING_TEMPLATES",
    "get_apache_hardening_template",
    "get_apache_template_commands_for_distro",
    "get_apache_verify_commands_for_distro",
    "ApacheHardeningTemplate",
    "APACHE_CHECK_PARAMETER_MAP",
    "APACHE_PARAMETER_REGISTRY",
    "aggregate_apache_parameters_for_checks",
    "categorize_apache_checks_by_fixability",
    "get_apache_auto_fix_preview",
    "get_apache_check_defaults",
    "get_apache_parameters_for_check",
    "is_apache_check_auto_fixable",
]
