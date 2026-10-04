"""
Read-only collection for a Kubernetes audit, over SSH to a node (as root via
sudo). Written for kubeadm-built clusters, the layout the benchmark
describes.

Node data: the command lines of the running components (kube-apiserver,
controller-manager, scheduler, etcd, kubelet), the static pod manifests (the
source of truth for the control plane, and the fallback when a component is
not running), the kubelet configuration file, and ownership/modes of the
files the benchmark names.

Cluster data (section 5) comes from kubectl with the node's admin kubeconfig
(control-plane nodes): RBAC objects, namespaces, service accounts, network
policies, admission webhooks and pods. Pod specs are cut down here, on this
side, to the security-relevant fields before anything is stored: environment
variable values, ConfigMap/Secret contents and annotations are never kept,
and Secret objects are never read. The encryption configuration is reduced
on the node to its provider names - its keys never leave the host.
"""

import json
from typing import Any, Dict, List

from app.modules.benchmark.rules import assemble, parse_json

COMPONENTS = ("kube-apiserver", "kube-controller-manager", "kube-scheduler", "etcd", "kubelet", "kube-proxy")
MANIFEST_DIR = "/etc/kubernetes/manifests"
MANIFESTS = {
    "kube-apiserver": f"{MANIFEST_DIR}/kube-apiserver.yaml",
    "kube-controller-manager": f"{MANIFEST_DIR}/kube-controller-manager.yaml",
    "kube-scheduler": f"{MANIFEST_DIR}/kube-scheduler.yaml",
    "etcd": f"{MANIFEST_DIR}/etcd.yaml",
}
ADMIN_KUBECONFIG = "/etc/kubernetes/admin.conf"
NO_KUBERNETES = "NO_KUBERNETES"

_PROC = "ps -eo args= | grep -E '^(\\S*/)?{name}( |$)' | head -1"


def _flag_value(component: str, flag: str, default: str) -> str:
    """Shell: the value of --flag on the running component, else in its manifest, else the default."""
    manifest = MANIFESTS.get(component, "")
    from_manifest = (f" || grep -oE -- '--{flag}=[^\" ]+' {manifest} 2>/dev/null | head -1 | cut -d= -f2-"
                     if manifest else "")
    return (f"$( {{ {_PROC.format(name=component)} | grep -oE -- '--{flag}=[^ ]+' | head -1 | cut -d= -f2- | grep .{from_manifest}; }}"
            f" | grep . || echo {default})")


KUBELET_CONFIG_PATH = _flag_value("kubelet", "config", "/var/lib/kubelet/config.yaml")
KUBELET_KUBECONFIG = _flag_value("kubelet", "kubeconfig", "/etc/kubernetes/kubelet.conf")
ETCD_DATA_DIR = _flag_value("etcd", "data-dir", "/var/lib/etcd")
AUDIT_POLICY_PATH = _flag_value("kube-apiserver", "audit-policy-file", "NONE")
ENCRYPTION_CONFIG_PATH = _flag_value("kube-apiserver", "encryption-provider-config", "NONE")

NODE = (
    "if ! command -v kubelet >/dev/null 2>&1 && [ ! -d /etc/kubernetes ]; then echo " + NO_KUBERNETES + "; exit 0; fi; "
    "echo \"kubelet_version=$(kubelet --version 2>/dev/null | awk '{print $2}')\"; "
    f"echo \"control_plane=$([ -f {MANIFESTS['kube-apiserver']} ] || ps -eo args= | grep -qE '^(\\S*/)?kube-apiserver( |$)' "
    "&& echo yes || echo no)\"; "
    f"echo \"admin_kubeconfig=$([ -f {ADMIN_KUBECONFIG} ] && echo yes || echo no)\"; "
    "echo \"hostname=$(hostname)\""
)

PROCS = "; ".join(f"echo \"### {c}\"; {_PROC.format(name=c)}" for c in COMPONENTS)

MANIFEST_FILES = "; ".join(
    f"echo \"### {c}\"; cat {path} 2>/dev/null || echo MISSING" for c, path in MANIFESTS.items())

KUBELET_CONFIG = f"f={KUBELET_CONFIG_PATH}; if [ -f \"$f\" ]; then echo \"# $f\"; cat \"$f\"; else echo MISSING; fi"

KUBELET_SERVICE = (
    "u=$(systemctl show -p FragmentPath --value kubelet.service 2>/dev/null | grep . || "
    "for f in /etc/systemd/system/kubelet.service /usr/lib/systemd/system/kubelet.service "
    "/lib/systemd/system/kubelet.service; do [ -e $f ] && echo $f && break; done); "
    "for f in $u /etc/systemd/system/kubelet.service.d/*.conf /usr/lib/systemd/system/kubelet.service.d/*.conf "
    "/lib/systemd/system/kubelet.service.d/*.conf; do [ -e \"$f\" ] && echo \"$f\"; done | sort -u"
)

# Shell expressions for the file groups the benchmark names (also used by the fixes).
FILE_GROUPS = {
    "apiserver_manifest": MANIFESTS["kube-apiserver"],
    "controller_manager_manifest": MANIFESTS["kube-controller-manager"],
    "scheduler_manifest": MANIFESTS["kube-scheduler"],
    "etcd_manifest": MANIFESTS["etcd"],
    "cni": "$(find /etc/cni/net.d -maxdepth 1 -type f 2>/dev/null)",
    "etcd_data": ETCD_DATA_DIR,
    "admin_conf": "/etc/kubernetes/admin.conf /etc/kubernetes/super-admin.conf",
    "scheduler_conf": "/etc/kubernetes/scheduler.conf",
    "controller_manager_conf": "/etc/kubernetes/controller-manager.conf",
    "pki_all": "$(find /etc/kubernetes/pki 2>/dev/null)",
    "pki_crt": "$(find /etc/kubernetes/pki -type f -name '*.crt' 2>/dev/null)",
    "pki_key": "$(find /etc/kubernetes/pki -type f -name '*.key' 2>/dev/null)",
    "kubelet_service": f"$({KUBELET_SERVICE})",
    "kubelet_kubeconfig": KUBELET_KUBECONFIG,
    "kubelet_ca": ("$({ " + _PROC.format(name="kubelet") + " | grep -oE -- '--client-ca-file=[^ ]+' | cut -d= -f2-; "
                   f"grep -E '^[[:space:]]+clientCAFile:' {KUBELET_CONFIG_PATH} 2>/dev/null | awk '{{print $2}}' "
                   "| tr -d '\"'; } | grep . | head -1)"),
    "kubelet_config": KUBELET_CONFIG_PATH,
}

FILES = (
    "st() { tag=$1; shift; for f in \"$@\"; do [ -n \"$f\" ] || continue; "
    "if [ -e \"$f\" ]; then printf '%s|' \"$tag\"; stat -c '%n|%U|%G|%a|%F' \"$f\"; "
    "else echo \"$tag|$f|-|-|-|missing\"; fi; done; }; "
    + "; ".join(f"st {tag} {expr}" for tag, expr in FILE_GROUPS.items())
    + "; echo END"
)

AUDIT_POLICY = (f"f={AUDIT_POLICY_PATH}; if [ \"$f\" = NONE ]; then echo NONE; "
                "elif [ -f \"$f\" ]; then cat \"$f\"; else echo \"MISSING $f\"; fi")
# Provider names only: the file's secrets never leave the host.
ENCRYPTION = (f"f={ENCRYPTION_CONFIG_PATH}; if [ \"$f\" = NONE ]; then echo NONE; "
              "elif [ -f \"$f\" ]; then grep -oE '^[[:space:]]*-?[[:space:]]*(aescbc|aesgcm|secretbox|kms|identity):' "
              "\"$f\" | tr -d ' -:' | tr '\\n' ' '; echo; else echo \"MISSING $f\"; fi")

CNI = "ls /etc/cni/net.d 2>/dev/null | tr '\\n' ' '; echo"

_KUBECTL = f"kubectl --kubeconfig {ADMIN_KUBECONFIG} --request-timeout=30s"
_NEED_ADMIN = f"[ -f {ADMIN_KUBECONFIG} ] || {{ echo 'CMD_ERROR: no admin kubeconfig on this node ({ADMIN_KUBECONFIG}); run the audit against a control-plane node for the cluster checks'; exit 0; }}; "


def _kubectl(what: str) -> str:
    return _NEED_ADMIN + f"{_KUBECTL} get {what} -o json"


CLUSTER_COMMANDS = {
    "K8S_RBAC": _kubectl("clusterroles,clusterrolebindings,roles,rolebindings -A"),
    "K8S_NAMESPACES": _kubectl("namespaces"),
    "K8S_SERVICEACCOUNTS": _kubectl("serviceaccounts -A"),
    "K8S_NETPOL": _kubectl("networkpolicies -A"),
    "K8S_WEBHOOKS": _kubectl("validatingwebhookconfigurations,mutatingwebhookconfigurations"),
    "K8S_PODS": _kubectl("pods -A"),
    "K8S_DEFAULT_NS": _kubectl("deployments,statefulsets,daemonsets,jobs,cronjobs,services,configmaps -n default"),
    # NONE when the cluster has no kube-proxy (e.g. a CNI that replaces it).
    "K8S_PROXY_CONFIG": (_NEED_ADMIN + f"out=$({_KUBECTL} -n kube-system get configmap kube-proxy "
                         "-o jsonpath='{.data.config\\.conf}' 2>&1); rc=$?; "
                         "if [ $rc -eq 0 ]; then echo \"${out:-NONE}\"; "
                         "elif echo \"$out\" | grep -q NotFound; then echo NONE; "
                         "else echo \"CMD_ERROR: $out\" | head -1; fi"),
}


def kubernetes_commands() -> Dict[str, str]:
    """Section name -> read-only shell command of the Kubernetes audit dump (node role, processes,
    manifests, kubelet and proxy configuration, file permissions, and cluster objects through
    kubectl when an admin kubeconfig is available).
    """
    cmds = {
        "OS_RELEASE": "cat /etc/os-release 2>/dev/null || uname -sr",
        "NODE": NODE,
        "PROCS": PROCS,
        "MANIFESTS": MANIFEST_FILES,
        "KUBELET_CONFIG": KUBELET_CONFIG,
        "FILES": FILES,
        "AUDIT_POLICY": AUDIT_POLICY,
        "ENCRYPTION": ENCRYPTION,
        "CNI": CNI,
    }
    cmds.update(CLUSTER_COMMANDS)
    return cmds


# ── what is kept of the cluster objects ───────────────────────────────────

def _meta(o: Dict[str, Any], labels=()) -> Dict[str, Any]:
    m = o.get("metadata") or {}
    out = {"name": m.get("name"), "namespace": m.get("namespace")}
    if labels:
        out["labels"] = {k: v for k, v in (m.get("labels") or {}).items() if k in labels or k.startswith(labels)}
    return out


def _items(raw: str) -> List[Dict[str, Any]]:
    data = parse_json(raw)
    return [i for i in (data or {}).get("items") or [] if isinstance(i, dict)] if isinstance(data, dict) else []


def slim_rbac(raw: str) -> str:
    """RBAC objects reduced to what the rules read (kind, name, rules, roleRef, subjects), as one
    compact JSON array.
    """
    out = []
    for o in _items(raw):
        if "kind" not in o:
            continue
        item = {"kind": o["kind"], **_meta(o, labels=("kubernetes.io/bootstrapping",))}
        if o["kind"] in ("ClusterRole", "Role"):
            item["rules"] = [{k: r.get(k) for k in ("apiGroups", "resources", "verbs", "resourceNames")}
                             for r in o.get("rules") or [] if isinstance(r, dict)]
            item["aggregated"] = bool(o.get("aggregationRule"))
        else:
            item["roleRef"] = (o.get("roleRef") or {}).get("name")
            item["roleKind"] = (o.get("roleRef") or {}).get("kind")
            item["subjects"] = [{k: s.get(k) for k in ("kind", "name", "namespace")}
                                for s in o.get("subjects") or [] if isinstance(s, dict)]
        out.append(item)
    return json.dumps(out, separators=(",", ":"))


def slim_namespaces(raw: str) -> str:
    return json.dumps([_meta(o, labels=("pod-security.kubernetes.io/",)) for o in _items(raw)], separators=(",", ":"))


def slim_serviceaccounts(raw: str) -> str:
    return json.dumps([{**_meta(o), "automount": o.get("automountServiceAccountToken")} for o in _items(raw)],
                      separators=(",", ":"))


def slim_names(raw: str) -> str:
    return json.dumps([{"kind": o.get("kind"), **_meta(o)} for o in _items(raw)], separators=(",", ":"))


_SEC_KEYS = ("privileged", "allowPrivilegeEscalation", "runAsNonRoot", "runAsUser", "capabilities",
             "seccompProfile", "windowsOptions", "readOnlyRootFilesystem")


def _container(c: Dict[str, Any]) -> Dict[str, Any]:
    sc = c.get("securityContext") or {}
    env_secrets = [e.get("name") for e in c.get("env") or []
                   if isinstance(e, dict) and ((e.get("valueFrom") or {}).get("secretKeyRef"))]
    env_from_secrets = [(e.get("secretRef") or {}).get("name") for e in c.get("envFrom") or []
                        if isinstance(e, dict) and e.get("secretRef")]
    return {
        "name": c.get("name"),
        "image": c.get("image"),
        "securityContext": {k: sc.get(k) for k in _SEC_KEYS if k in sc},
        "hostPorts": [p.get("hostPort") for p in c.get("ports") or [] if isinstance(p, dict) and p.get("hostPort")],
        "secretEnv": env_secrets,
        "secretEnvFrom": env_from_secrets,
    }


def slim_pods(raw: str) -> str:
    """Pods reduced to their security-relevant fields (host namespaces, privileges, capabilities,
    users, host paths, names of secrets used as environment) as one compact JSON array; values of
    environment variables are never kept.
    """
    out = []
    for o in _items(raw):
        spec = o.get("spec") or {}
        psc = spec.get("securityContext") or {}
        out.append({
            **_meta(o),
            "serviceAccount": spec.get("serviceAccountName") or "default",
            "automount": spec.get("automountServiceAccountToken"),
            "hostPID": bool(spec.get("hostPID")), "hostIPC": bool(spec.get("hostIPC")),
            "hostNetwork": bool(spec.get("hostNetwork")),
            "securityContext": {k: psc.get(k) for k in ("runAsNonRoot", "runAsUser", "seccompProfile", "windowsOptions")
                                if k in psc},
            "hostPaths": [(v.get("hostPath") or {}).get("path") for v in spec.get("volumes") or []
                          if isinstance(v, dict) and v.get("hostPath")],
            "containers": [_container(c) for c in (spec.get("initContainers") or []) + (spec.get("containers") or [])
                           + (spec.get("ephemeralContainers") or []) if isinstance(c, dict)],
            "phase": (o.get("status") or {}).get("phase"),
            "owner": next((r.get("kind") for r in (o.get("metadata") or {}).get("ownerReferences") or []), None),
        })
    return json.dumps(out, separators=(",", ":"))


SLIM = {
    "K8S_RBAC": slim_rbac, "K8S_NAMESPACES": slim_namespaces, "K8S_SERVICEACCOUNTS": slim_serviceaccounts,
    "K8S_NETPOL": slim_names, "K8S_WEBHOOKS": slim_names, "K8S_PODS": slim_pods, "K8S_DEFAULT_NS": slim_names,
}


def _slim(name: str, text: str) -> str:
    if name not in SLIM or text.lstrip().startswith(("CMD_ERROR", "SSH_ERROR")):
        return text
    data = parse_json(text)
    if isinstance(data, list):        # already reduced (stored output, simulated host)
        return text
    return SLIM[name](text) if isinstance(data, dict) else text


def collect(conn) -> str:
    """Collect the Kubernetes audit dump; a host without Kubernetes yields a dump saying so."""
    cmds = kubernetes_commands()
    node = conn.run(cmds["NODE"])
    if node.strip() == NO_KUBERNETES:
        return assemble({"NODE": NO_KUBERNETES})
    out = {"NODE": node}
    for name, script in cmds.items():
        if name != "NODE":
            out[name] = _slim(name, conn.run(script))
    return assemble(out)
