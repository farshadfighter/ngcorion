"""The nginx module's declaration for the benchmark engine."""

import re
from typing import Optional

from app.models.audit import DeviceType
from app.modules.benchmark.spec import ModuleSpec
from app.modules.shared.hardening_backup import bundle_header
from app.modules.software.hooks import save_single

from . import collect as C
from . import rules as R
from .hardening import TEMPLATES


def _backup(conn) -> str:
    """Every configuration file nginx reads (from nginx -T, secrets masked),
    the logrotate file and ownership/modes. Each configuration edit also
    keeps the unmasked files it changes on the host, in
    /var/backups/ngcorion-nginx/<time>/."""
    return (bundle_header("nginx", getattr(conn, "ip", None))
            + "##### Configuration before hardening (nginx -T) #####\n" + C.redact(conn.run(C.COMMANDS["NGINX_T"]))
            + "\n##### /etc/logrotate.d/nginx #####\n" + conn.run(C.COMMANDS["LOGROTATE"])
            + "\n##### Ownership and modes before hardening (FILES) #####\n" + conn.run(C.COMMANDS["FILES"]) + "\n")


def collect_software(conn) -> Optional[dict]:
    m = re.search(r"nginx version: nginx/(\d+\.\d+\.\d+)", conn.run("nginx -v 2>&1"))
    if not m:
        return None
    return {"name": "nginx", "version": m.group(1), "arch": None, "source": "service", "origin": None,
            "publisher": "F5, Inc.", "kind": "service", "source_package": None, "vkind": "svc"}


def save_software(db, asset_id, raw, *, audit_session_id=None, user_id=None):
    return save_single(db, asset_id, "nginx", raw, audit_session_id=audit_session_id, user_id=user_id)


SPEC = ModuleSpec(
    key="nginx",
    label="NGINX",
    device_type=DeviceType.NGINX,
    log_module="nginx_cis",
    connector="ssh_nginx",
    benchmark="CIS NGINX Benchmark",
    collect=C.collect,
    rules_for=R.rules_for,
    all_rules=R.all_rules,
    templates=TEMPLATES,
    redact=C.redact,
    describe=R.describe,
    collect_software=collect_software,
    save_software=save_software,
    backup=_backup,
    backup_device_type="nginx",
    tags_audit=["Audit - NGINX"],
    tags_hardening=["Hardening - NGINX"],
)
