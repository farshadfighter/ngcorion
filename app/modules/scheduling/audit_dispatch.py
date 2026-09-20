"""
Per-technology dispatch for scheduled Audit jobs.

Each tech's AuditService.execute_*_audit has its own kwargs (different
credential field names, different tech-specific options - see each
module's audit/schemas.py request class), so a scheduled audit job stores
exactly that tech's kwargs (minus asset_id/user_id, which the job already
carries) as one encrypted JSON blob (app/core/credential_crypto.py) and this
module maps job.technology -> the right service call.

Adding a technology here later just needs one more entry - the dispatch
table, not a schema change, is what stays in sync with the seven audit
modules.
"""
from typing import Callable
from sqlalchemy.orm import Session

SUPPORTED_TECHNOLOGIES = (
    "cisco", "fortinet", "linux", "apache", "mongodb", "mssql", "windows",
)


def _dispatch_cisco(db: Session, asset_id: int, user_id: int, params: dict):
    from app.modules.cisco.audit.service import AuditService
    return AuditService.execute_cisco_audit(db=db, asset_id=asset_id, user_id=user_id, **params)


def _dispatch_fortinet(db: Session, asset_id: int, user_id: int, params: dict):
    from app.modules.fortinet.audit.service import FortinetAuditService
    return FortinetAuditService.execute_fortinet_audit(db=db, asset_id=asset_id, user_id=user_id, **params)


def _dispatch_linux(db: Session, asset_id: int, user_id: int, params: dict):
    from app.modules.linux.audit.service import LinuxAuditService
    return LinuxAuditService.execute_linux_audit(db=db, asset_id=asset_id, user_id=user_id, **params)


def _dispatch_apache(db: Session, asset_id: int, user_id: int, params: dict):
    from app.modules.apache.audit.service import ApacheAuditService
    return ApacheAuditService.execute_apache_audit(db=db, asset_id=asset_id, user_id=user_id, **params)


def _dispatch_mongodb(db: Session, asset_id: int, user_id: int, params: dict):
    from app.modules.mongodb.audit.service import MongoDBSHAuditService
    return MongoDBSHAuditService.execute_mongodb_audit(db=db, asset_id=asset_id, user_id=user_id, **params)


def _dispatch_mssql(db: Session, asset_id: int, user_id: int, params: dict):
    from app.modules.mssql.audit.service import MSSQLAuditService
    return MSSQLAuditService.execute_mssql_audit(db=db, asset_id=asset_id, user_id=user_id, **params)


def _dispatch_windows(db: Session, asset_id: int, user_id: int, params: dict):
    from app.modules.windows.audit.service import WindowsAuditService
    return WindowsAuditService.execute_windows_audit(db=db, asset_id=asset_id, user_id=user_id, **params)


_DISPATCH_TABLE: dict[str, Callable] = {
    "cisco": _dispatch_cisco,
    "fortinet": _dispatch_fortinet,
    "linux": _dispatch_linux,
    "apache": _dispatch_apache,
    "mongodb": _dispatch_mongodb,
    "mssql": _dispatch_mssql,
    "windows": _dispatch_windows,
}

# Required (non-optional) param keys per technology, for a fast, precise
# validation error at job-creation time rather than a TypeError deep inside
# the scheduler loop days later when the job actually fires.
REQUIRED_PARAMS = {
    "cisco": {"ssh_username", "ssh_password"},
    "fortinet": {"ssh_username", "ssh_password"},
    "linux": {"ssh_username", "ssh_password"},
    "apache": {"ssh_username", "ssh_password"},
    "mongodb": {"ssh_username", "ssh_password"},
    "mssql": {"mssql_username", "mssql_password"},
    "windows": {"windows_username", "windows_password"},
}


def run_audit(technology: str, db: Session, asset_id: int, user_id: int, params: dict):
    """Execute the audit for `technology`. Raises KeyError for an unknown
    technology - callers validate against SUPPORTED_TECHNOLOGIES first."""
    return _DISPATCH_TABLE[technology](db, asset_id, user_id, params)
