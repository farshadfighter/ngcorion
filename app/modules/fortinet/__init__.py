"""
FortiGate Security Audit Module

This module provides comprehensive security auditing for FortiGate firewalls,
following CIS benchmarks and enterprise best practices.

Components:
- fortinet_ssh_client: SSH connection management with VDOM support
- fortinet_rules: CIS benchmark control catalog (120+ checks)
- fortinet_service: Audit orchestration and analytics
- fortinet_router: FastAPI API endpoints
- fortinet_cis_map: CIS benchmark mapping
"""

from .fortinet_ssh_client import FortiGateSSHClient, ConnectionPool
from .fortinet_service import FortinetAuditService

__all__ = [
    "FortiGateSSHClient",
    "ConnectionPool",
    "FortinetAuditService",
]
