"""
Apache HTTP Server Module

CIS compliance auditing and hardening for Apache HTTP Server 2.4.x
Supports:
- Ubuntu/Debian (apache2)
- RHEL/Rocky/CentOS (httpd)
"""
from .audit import router as audit_router
from .audit import ApacheAuditService

__all__ = [
    "audit_router",
    "ApacheAuditService",
]
