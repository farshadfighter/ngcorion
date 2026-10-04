"""The Docker module's declaration for the benchmark engine."""

import re
from typing import Optional

from app.models.audit import DeviceType
from app.modules.benchmark.spec import ModuleSpec
from app.modules.shared.hardening_backup import build_file_bundle_command, bundle_header
from app.modules.software.hooks import save_single

from . import collect as C
from . import rules as R
from .hardening import TEMPLATES

# What a Docker hardening run can change, saved before it runs.
DOCKER_BACKUP_PATHS = [
    "/etc/docker/daemon.json",
    "/etc/audit/rules.d/docker.rules",
    "/etc/profile.d/docker-content-trust.sh",
    "/etc/default/docker",
    "/etc/sysconfig/docker",
]

_SECRET_ASSIGNMENT = re.compile(
    r"\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*=)(\"[^\"]*\"|'[^']*'|\S+)", re.I)
_URL_CREDENTIALS = re.compile(r"(\w+://)[^/\s:@\"]+:[^@\s\"]+@")


def redact(dump: str) -> str:
    """Build arguments in image history and proxy URLs in `docker info` can
    carry credentials; keep the names, drop the values."""
    return _URL_CREDENTIALS.sub(r"\1***@", _SECRET_ASSIGNMENT.sub(r"\1***", dump))


def _backup(conn) -> str:
    files = conn.run(build_file_bundle_command(DOCKER_BACKUP_PATHS))
    modes = conn.run(C.FILES)
    return (bundle_header("docker", getattr(conn, "ip", None)) + files + "\n"
            "##### Ownership and modes before hardening (FILES) #####\n" + modes + "\n")


def collect_software(conn) -> Optional[dict]:
    out = conn.run("docker version --format '{{.Server.Version}}'").strip()
    m = re.match(r"^(\d+\.\d+\.\d+)", out)
    if not m:
        return None
    return {"name": "Docker Engine", "version": m.group(1), "arch": None, "source": "service", "origin": None,
            "publisher": "Docker Inc.", "kind": "service", "source_package": None, "vkind": "svc"}


def save_software(db, asset_id, raw, *, audit_session_id=None, user_id=None):
    return save_single(db, asset_id, "docker", raw, audit_session_id=audit_session_id, user_id=user_id)


SPEC = ModuleSpec(
    key="docker",
    label="Docker",
    device_type=DeviceType.DOCKER,
    log_module="docker_cis",
    connector="ssh",
    benchmark="CIS Docker Benchmark",
    collect=C.collect,
    rules_for=R.rules_for,
    all_rules=R.all_rules,
    templates=TEMPLATES,
    json_sections=R.JSON_SECTIONS,
    redact=redact,
    describe=R.describe,
    collect_software=collect_software,
    save_software=save_software,
    backup=_backup,
    backup_device_type="docker",
    tags_audit=["Audit - Docker"],
    tags_hardening=["Hardening - Docker"],
)
