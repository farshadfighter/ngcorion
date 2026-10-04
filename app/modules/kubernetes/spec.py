"""The Kubernetes module's declaration for the benchmark engine."""

import re
from typing import Optional

from app.models.audit import DeviceType
from app.modules.benchmark.spec import ModuleSpec
from app.modules.shared.hardening_backup import build_file_bundle_command, bundle_header
from app.modules.software.hooks import save_single

from . import collect as C
from . import rules as R
from .hardening import TEMPLATES

# What a Kubernetes hardening run can change on the node, saved before it runs.
# Kubeconfigs and keys are not copied: their modes are in the FILES listing.
K8S_BACKUP_PATHS = [
    "/etc/kubernetes/manifests/kube-apiserver.yaml",
    "/etc/kubernetes/manifests/kube-controller-manager.yaml",
    "/etc/kubernetes/manifests/kube-scheduler.yaml",
    "/etc/kubernetes/manifests/etcd.yaml",
    "/var/lib/kubelet/config.yaml",
]


def _backup(conn) -> str:
    files = conn.run(build_file_bundle_command(K8S_BACKUP_PATHS))
    modes = conn.run(C.FILES)
    return (bundle_header("kubernetes", getattr(conn, "ip", None)) + files + "\n"
            "##### Ownership and modes before hardening (FILES) #####\n" + modes + "\n")


def collect_software(conn) -> Optional[dict]:
    """The kubelet version as a software item for the inventory, or None."""
    out = conn.run("kubelet --version 2>/dev/null").strip()
    m = re.search(r"v(\d+\.\d+\.\d+)", out)
    if not m:
        return None
    return {"name": "Kubernetes", "version": m.group(1), "arch": None, "source": "service", "origin": None,
            "publisher": "The Kubernetes Authors", "kind": "service", "source_package": None, "vkind": "svc"}


def save_software(db, asset_id, raw, *, audit_session_id=None, user_id=None):
    return save_single(db, asset_id, "kubernetes", raw, audit_session_id=audit_session_id, user_id=user_id)


SPEC = ModuleSpec(
    key="kubernetes",
    label="Kubernetes",
    device_type=DeviceType.KUBERNETES,
    log_module="kubernetes_cis",
    connector="ssh",
    benchmark="CIS Kubernetes Benchmark",
    collect=C.collect,
    rules_for=R.rules_for,
    all_rules=R.all_rules,
    templates=TEMPLATES,
    json_sections=R.JSON_SECTIONS,
    describe=R.describe,
    collect_software=collect_software,
    save_software=save_software,
    backup=_backup,
    backup_device_type="kubernetes",
    tags_audit=["Audit - Kubernetes"],
    tags_hardening=["Hardening - Kubernetes"],
)
