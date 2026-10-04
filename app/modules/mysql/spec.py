"""The MySQL 8 module's declaration for the benchmark engine."""

import re
from typing import Optional

from app.models.audit import DeviceType
from app.modules.benchmark.spec import ModuleSpec
from app.modules.shared.hardening_backup import build_file_bundle_command, bundle_header
from app.modules.software.hooks import save_single

from . import collect as C
from . import rules as R
from .hardening import TEMPLATES

MYSQL_OPTION_FILES = ["/etc/my.cnf", "/etc/mysql/my.cnf", "/etc/mysql/conf.d/*.cnf", "/etc/mysql/mysql.conf.d/*.cnf",
                      "/etc/my.cnf.d/*.cnf"]


def _backup(conn) -> str:
    """Option files (password values blanked), the settings SET PERSIST
    changes, and file ownership/modes - what a hardening run can change."""
    files = C.redact_option_files(conn.run(build_file_bundle_command(MYSQL_OPTION_FILES)))
    persisted = conn.run("SQL:SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.persisted_variables")
    modes = conn.run(C.FILES)
    return (bundle_header("mysql", getattr(conn, "ip", None)) + files + "\n"
            "##### Persisted variables before hardening (SET PERSIST) #####\n" + persisted + "\n"
            "##### Ownership and modes before hardening (FILES) #####\n" + modes + "\n")


def collect_software(conn) -> Optional[dict]:
    """The MySQL server version as a software item for the inventory, or None."""
    m = re.match(r"^(\d+\.\d+\.\d+)", conn.run(C.SQL_COMMANDS["MYSQL_VERSION"]).strip())
    if not m:
        return None
    return {"name": "MySQL Server", "version": m.group(1), "arch": None, "source": "service", "origin": None,
            "publisher": "Oracle Corporation", "kind": "service", "source_package": None, "vkind": "svc"}


def save_software(db, asset_id, raw, *, audit_session_id=None, user_id=None):
    return save_single(db, asset_id, "mysql", raw, audit_session_id=audit_session_id, user_id=user_id)


SPEC = ModuleSpec(
    key="mysql",
    label="MySQL 8",
    device_type=DeviceType.MYSQL,
    log_module="mysql_cis",
    connector="ssh_mysql",
    benchmark="CIS Oracle MySQL Community Server 8.0 Benchmark",
    collect=C.collect,
    rules_for=R.rules_for,
    all_rules=R.all_rules,
    templates=TEMPLATES,
    json_sections=R.JSON_SECTIONS,
    redact=C.redact_option_files,
    describe=R.describe,
    collect_software=collect_software,
    save_software=save_software,
    backup=_backup,
    backup_device_type="mysql",
    tags_audit=["Audit - MySQL 8"],
    tags_hardening=["Hardening - MySQL 8"],
)
