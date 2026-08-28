"""
Per-family adapters for Harden All.

Each device family already has a battle-tested hardening service. This module is
the only place that knows how those services differ: how to look up a template,
how to categorize fixability, what credentials they take, how their batch-execute
is called, and what their result dict looks like.

Everything above this module works in the unified contract only.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from app.models.audit import DeviceType
from app.modules.windows.winrm_endpoint import DEFAULT_WINRM_PORT

from .contract import CredentialField, PlanCapabilities


# ============================================================
# Credential field sets
# ============================================================

def _ssh_fields(*, sudo: bool = False, secret: bool = False, vdom: bool = False) -> List[CredentialField]:
    fields = [
        CredentialField(name="ssh_username", label="SSH Username", type="text", required=True),
        CredentialField(name="ssh_password", label="SSH Password", type="password", required=True),
        CredentialField(name="ssh_port", label="SSH Port", type="number", default="22"),
    ]
    if sudo:
        fields.append(CredentialField(
            name="sudo_password", label="Sudo Password", type="password",
            help="Leave empty to reuse the SSH password",
        ))
    if secret:
        fields.append(CredentialField(
            name="ssh_secret", label="Enable Secret", type="password",
            help="Required if the device drops into user EXEC mode on login",
        ))
    if vdom:
        fields.append(CredentialField(
            name="vdom", label="VDOM", type="text",
            help="Leave empty to use each finding's own VDOM",
        ))
    return fields


# ============================================================
# Result normalization
# ============================================================

def _norm_count_style(raw: Dict[str, Any]) -> Dict[str, int]:
    """Counts from either family dialect (successful/failed vs fixed_count/...)."""
    return {
        "successful": raw.get("successful", raw.get("fixed_count", 0)) or 0,
        "failed": raw.get("failed", raw.get("failed_count", 0)) or 0,
        "skipped": raw.get("skipped_count", 0) or 0,
    }


def _normalize_status_rows(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Cisco/FortiGate: results[] carry an explicit `status` string."""
    rows = []
    for r in raw.get("results") or []:
        status = str(r.get("status") or "").lower()
        if status not in ("success", "failed", "skipped"):
            status = "success" if r.get("success") else "failed"
        rows.append({
            "check_number": r.get("check_number") or r.get("check_id") or "",
            "check_title": r.get("check_title"),
            "vdom": r.get("vdom"),
            "status": status,
            "detail": (
                r.get("reason")
                or r.get("error")
                or r.get("error_message")
                or r.get("verification_evidence")
                or r.get("verification_result")
            ),
            "commands": r.get("commands") or [],
        })
    return rows


def _normalize_success_rows(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Linux/Apache/MongoDB/MSSQL/Windows: results[] carry a boolean `success`."""
    rows = []
    for r in raw.get("results") or []:
        if raw.get("dry_run"):
            status = "skipped" if r.get("error_message") else "success"
        else:
            status = "success" if r.get("success") else "failed"
        rows.append({
            "check_number": r.get("check_id") or r.get("check_number") or "",
            "check_title": r.get("check_title"),
            "vdom": None,
            "status": status,
            "detail": r.get("error_message") or r.get("verification_result") or r.get("message"),
            "commands": r.get("commands") or [],
        })
    for check_id in raw.get("skipped") or []:
        rows.append({
            "check_number": check_id if isinstance(check_id, str) else str(check_id),
            "check_title": None,
            "vdom": None,
            "status": "skipped",
            "detail": "Not auto-fixable",
            "commands": [],
        })
    return rows


# ============================================================
# Family spec
# ============================================================

@dataclass(frozen=True)
class FamilySpec:
    key: str
    label: str
    device_type: DeviceType

    has_template: Callable[[str], bool]
    categorize: Callable[[List[str]], Dict[str, List[str]]]
    aggregate: Callable[[List[str]], Dict[str, Dict[str, Any]]]

    # execute(ctx) -> raw family result dict. See service.execute_plan for `ctx`.
    execute: Callable[["ExecutionContext"], Dict[str, Any]]
    normalize_rows: Callable[[Dict[str, Any]], List[Dict[str, Any]]]

    credential_fields: List[CredentialField] = field(default_factory=list)
    capabilities: PlanCapabilities = field(default_factory=PlanCapabilities)


@dataclass
class ExecutionContext:
    """Normalized inputs handed to a family's execute adapter."""
    db: Any
    session: Any
    asset: Any
    user_id: int
    credentials: Dict[str, str]
    # Cisco/FortiGate execute by AuditResult id with one shared parameter dict.
    result_ids: List[int]
    parameters: Dict[str, str]
    # The other families execute by check number with per-check parameters.
    checks: List[Dict[str, Any]]
    create_backup: bool = False
    dry_run: bool = False

    def cred(self, name: str, default: Optional[str] = None) -> Optional[str]:
        value = self.credentials.get(name)
        if value is None or value == "":
            return default
        return value

    def int_cred(self, name: str, default: int) -> int:
        try:
            return int(self.cred(name) or default)
        except (TypeError, ValueError):
            return default


# ============================================================
# Adapters
# ============================================================

def _build_registry() -> Dict[str, FamilySpec]:
    # Imported lazily inside the builder so importing this module stays cheap and
    # a broken family module cannot take down the whole app at import time.
    from app.modules.cisco.hardening.service import HardeningService as CiscoService
    from app.modules.cisco.hardening.command_templates import has_template as cisco_has_template
    from app.modules.cisco.hardening.parameter_metadata import (
        aggregate_parameters_for_checks as cisco_aggregate,
        categorize_checks_by_fixability as cisco_categorize,
    )

    from app.modules.fortinet.hardening.service import FortiGateHardeningService
    from app.modules.fortinet.hardening.command_templates import has_fortigate_template as fg_has_template
    from app.modules.fortinet.hardening.parameter_metadata import (
        aggregate_fortigate_parameters_for_checks as fg_aggregate,
        categorize_fortigate_checks_by_fixability as fg_categorize,
    )

    from app.modules.linux.hardening.service import LinuxHardeningService
    from app.modules.linux.hardening.command_templates import get_linux_hardening_template
    from app.modules.linux.hardening.parameter_metadata import (
        aggregate_linux_parameters_for_checks as linux_aggregate,
        categorize_linux_checks_by_fixability as linux_categorize,
    )

    from app.modules.apache.hardening.service import ApacheHardeningService
    from app.modules.apache.hardening.command_templates import get_apache_hardening_template
    from app.modules.apache.hardening.parameter_metadata import (
        aggregate_apache_parameters_for_checks as apache_aggregate,
        categorize_apache_checks_by_fixability as apache_categorize,
    )

    from app.modules.mongodb.hardening.service import MongoDBHardeningService
    from app.modules.mongodb.hardening.command_templates import get_mongodb_hardening_template
    from app.modules.mongodb.hardening.parameter_metadata import (
        aggregate_mongodb_parameters_for_checks as mongo_aggregate,
        categorize_mongodb_checks_by_fixability as mongo_categorize,
    )

    from app.modules.mssql.hardening.service import MSSQLHardeningService
    from app.modules.mssql.hardening.command_templates import get_mssql_hardening_template
    from app.modules.mssql.hardening.parameter_metadata import (
        aggregate_mssql_parameters_for_checks as mssql_aggregate,
        categorize_mssql_checks_by_fixability as mssql_categorize,
    )

    from app.modules.windows.hardening.service import WindowsHardeningService
    from app.modules.windows.hardening.command_templates import get_windows_hardening_template
    from app.modules.windows.hardening.parameter_metadata import (
        aggregate_windows_parameters_for_checks as windows_aggregate,
        categorize_windows_checks_by_fixability as windows_categorize,
    )

    # ---- execute adapters -------------------------------------------------

    def cisco_execute(ctx: ExecutionContext) -> Dict[str, Any]:
        return CiscoService.batch_execute_selected(
            db=ctx.db,
            audit_session_id=ctx.session.id,
            user_id=ctx.user_id,
            check_ids=ctx.result_ids,
            parameters=ctx.parameters,
            ssh_username=ctx.cred("ssh_username"),
            ssh_password=ctx.cred("ssh_password"),
            ssh_secret=ctx.cred("ssh_secret"),
            skip_backup=not ctx.create_backup,
            ssh_port=ctx.int_cred("ssh_port", 22),
        )

    def fortinet_execute(ctx: ExecutionContext) -> Dict[str, Any]:
        return FortiGateHardeningService.batch_execute_selected(
            db=ctx.db,
            audit_session_id=ctx.session.id,
            user_id=ctx.user_id,
            check_ids=ctx.result_ids,
            parameters=ctx.parameters,
            ssh_username=ctx.cred("ssh_username"),
            ssh_password=ctx.cred("ssh_password"),
            vdom=ctx.cred("vdom"),
            skip_backup=not ctx.create_backup,
            ssh_port=ctx.int_cred("ssh_port", 22),
        )

    def linux_execute(ctx: ExecutionContext) -> Dict[str, Any]:
        return LinuxHardeningService.batch_execute_selected(
            db=ctx.db,
            session_id=ctx.session.id,
            asset_id=ctx.asset.id,
            ssh_username=ctx.cred("ssh_username"),
            ssh_password=ctx.cred("ssh_password"),
            sudo_password=ctx.cred("sudo_password"),
            checks=ctx.checks,
            ssh_port=ctx.int_cred("ssh_port", 22),
            dry_run=ctx.dry_run,
            create_backup=ctx.create_backup,
            user_id=ctx.user_id,
        )

    def apache_execute(ctx: ExecutionContext) -> Dict[str, Any]:
        return ApacheHardeningService.batch_execute_selected(
            db=ctx.db,
            session_id=ctx.session.id,
            asset_id=ctx.asset.id,
            ssh_username=ctx.cred("ssh_username"),
            ssh_password=ctx.cred("ssh_password"),
            ssh_port=ctx.int_cred("ssh_port", 22),
            sudo_password=ctx.cred("sudo_password"),
            checks=ctx.checks,
            create_backup=ctx.create_backup,
            user_id=ctx.user_id,
        )

    def mongo_execute(ctx: ExecutionContext) -> Dict[str, Any]:
        return MongoDBHardeningService.batch_execute_selected(
            db=ctx.db,
            session_id=ctx.session.id,
            asset_id=ctx.asset.id,
            ssh_username=ctx.cred("ssh_username"),
            ssh_password=ctx.cred("ssh_password"),
            checks=ctx.checks,
            ssh_port=ctx.int_cred("ssh_port", 22),
            sudo_password=ctx.cred("sudo_password"),
            create_backup=ctx.create_backup,
            user_id=ctx.user_id,
        )

    def mssql_execute(ctx: ExecutionContext) -> Dict[str, Any]:
        return MSSQLHardeningService.batch_execute_selected(
            db=ctx.db,
            session_id=ctx.session.id,
            asset_id=ctx.asset.id,
            mssql_username=ctx.cred("mssql_username"),
            mssql_password=ctx.cred("mssql_password"),
            checks=ctx.checks,
            mssql_port=ctx.int_cred("mssql_port", 1433),
            create_backup=ctx.create_backup,
            user_id=ctx.user_id,
        )

    def windows_execute(ctx: ExecutionContext) -> Dict[str, Any]:
        return WindowsHardeningService.batch_execute_selected(
            db=ctx.db,
            session_id=ctx.session.id,
            asset_id=ctx.asset.id,
            windows_username=ctx.cred("windows_username"),
            windows_password=ctx.cred("windows_password"),
            checks=ctx.checks,
            winrm_port=ctx.int_cred("winrm_port", DEFAULT_WINRM_PORT),
            transport=ctx.cred("transport", "ntlm"),
            create_backup=ctx.create_backup,
            user_id=ctx.user_id,
        )

    return {
        "cisco": FamilySpec(
            key="cisco",
            label="Cisco Router/Switch",
            device_type=DeviceType.CISCO,
            has_template=cisco_has_template,
            categorize=cisco_categorize,
            aggregate=cisco_aggregate,
            execute=cisco_execute,
            normalize_rows=_normalize_status_rows,
            credential_fields=_ssh_fields(secret=True),
            capabilities=PlanCapabilities(backup=True, dry_run=False),
        ),
        "fortinet": FamilySpec(
            key="fortinet",
            label="FortiGate Firewall",
            device_type=DeviceType.FORTINET,
            has_template=fg_has_template,
            categorize=fg_categorize,
            aggregate=fg_aggregate,
            execute=fortinet_execute,
            normalize_rows=_normalize_status_rows,
            credential_fields=_ssh_fields(vdom=True),
            capabilities=PlanCapabilities(backup=True, dry_run=False),
        ),
        "linux": FamilySpec(
            key="linux",
            label="Linux Server",
            device_type=DeviceType.LINUX,
            has_template=lambda cn: get_linux_hardening_template(cn) is not None,
            categorize=linux_categorize,
            aggregate=linux_aggregate,
            execute=linux_execute,
            normalize_rows=_normalize_success_rows,
            credential_fields=_ssh_fields(sudo=True),
            capabilities=PlanCapabilities(backup=True, dry_run=True),
        ),
        "apache": FamilySpec(
            key="apache",
            label="Apache Web Server",
            device_type=DeviceType.APACHE,
            has_template=lambda cn: get_apache_hardening_template(cn) is not None,
            categorize=apache_categorize,
            aggregate=apache_aggregate,
            execute=apache_execute,
            normalize_rows=_normalize_success_rows,
            credential_fields=_ssh_fields(sudo=True),
            capabilities=PlanCapabilities(backup=True),
        ),
        "mongodb": FamilySpec(
            key="mongodb",
            label="MongoDB",
            device_type=DeviceType.MONGODB,
            has_template=lambda cn: get_mongodb_hardening_template(cn) is not None,
            categorize=mongo_categorize,
            aggregate=mongo_aggregate,
            execute=mongo_execute,
            normalize_rows=_normalize_success_rows,
            credential_fields=_ssh_fields(sudo=True),
            capabilities=PlanCapabilities(backup=True),
        ),
        "mssql": FamilySpec(
            key="mssql",
            label="SQL Server",
            device_type=DeviceType.MSSQL,
            has_template=lambda cn: get_mssql_hardening_template(cn) is not None,
            categorize=mssql_categorize,
            aggregate=mssql_aggregate,
            execute=mssql_execute,
            normalize_rows=_normalize_success_rows,
            credential_fields=[
                CredentialField(name="mssql_username", label="SQL Server Login", type="text", required=True),
                CredentialField(name="mssql_password", label="SQL Server Password", type="password", required=True),
                CredentialField(name="mssql_port", label="Port", type="number", default="1433"),
            ],
            capabilities=PlanCapabilities(backup=True),
        ),
        "windows": FamilySpec(
            key="windows",
            label="Windows Server",
            device_type=DeviceType.WINDOWS,
            has_template=lambda cn: get_windows_hardening_template(cn) is not None,
            categorize=windows_categorize,
            aggregate=windows_aggregate,
            execute=windows_execute,
            normalize_rows=_normalize_success_rows,
            credential_fields=[
                CredentialField(name="windows_username", label="Windows Username", type="text", required=True),
                CredentialField(name="windows_password", label="Windows Password", type="password", required=True),
                CredentialField(name="winrm_port", label="WinRM Port", type="number",
                                default=str(DEFAULT_WINRM_PORT)),
                CredentialField(
                    name="transport", label="Transport", type="select", default="ntlm",
                    options=["ntlm", "kerberos", "credssp", "basic"],
                ),
            ],
            capabilities=PlanCapabilities(backup=True),
        ),
    }


_REGISTRY: Optional[Dict[str, FamilySpec]] = None


def get_family(device_type: DeviceType) -> FamilySpec:
    """Resolve the adapter for an audit session's device type."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = _build_registry()

    key = device_type.value if isinstance(device_type, DeviceType) else str(device_type)
    spec = _REGISTRY.get(key)
    if spec is None:
        raise ValueError(f"Harden All does not support device type '{key}'")
    return spec


def counts_from_raw(raw: Dict[str, Any]) -> Dict[str, int]:
    return _norm_count_style(raw)
