"""
Kubernetes rules after the CIS Kubernetes Benchmark (v1.9 layout, kubeadm):
1 control plane components (configuration files, API server, controller
manager, scheduler), 2 etcd, 3 control plane configuration, 4 worker nodes
(kubelet files, kubelet, kube-proxy), 5 policies (RBAC and service
accounts, pod security, network policies, secrets, admission control,
general).

Sections 1-3 apply to control-plane nodes, section 2 only where etcd runs
on the node; section 4 to every node; section 5 to the cluster (read with
the node's admin kubeconfig). A component's settings come from its running
command line, or from its static pod manifest when it is not running. Pod
checks leave kube-system out: the control plane's own pods need host
access by design. Item numbers follow the benchmark's content rather than a
specific edition's PDF and can differ slightly from the edition in use.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

import yaml

from app.modules.benchmark.rules import BenchmarkRule, json_section, section

from .collect import NO_KUBERNETES

JSON_SECTIONS = frozenset({"K8S_RBAC", "K8S_NAMESPACES", "K8S_SERVICEACCOUNTS", "K8S_NETPOL", "K8S_WEBHOOKS",
                           "K8S_PODS", "K8S_DEFAULT_NS"})
SYSTEM_NAMESPACES = ("kube-system", "kube-public", "kube-node-lease")
BUILTIN_ROLES = ("cluster-admin", "admin", "edit", "view")
DEFAULT_ADMIN_GROUPS = ("system:masters", "kubeadm:cluster-admins")
WEAK_CIPHER = re.compile(r"(_CBC_|RC4|3DES|_NULL_|_EXPORT_)", re.I)
POLICY_ENGINES = re.compile(r"kyverno|gatekeeper|kubewarden|polaris|jspolicy", re.I)


# ── node data ────────────────────────────────────────────────────────────

def node(d) -> Dict[str, str]:
    out = {}
    for line in section(d, "NODE").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _blocks(d, name) -> Dict[str, str]:
    out, cur, buf = {}, None, []
    for line in section(d, name).split("\n"):
        if line.startswith("### "):
            if cur:
                out[cur] = "\n".join(buf).strip()
            cur, buf = line[4:].strip(), []
        else:
            buf.append(line)
    if cur:
        out[cur] = "\n".join(buf).strip()
    return out


def manifest(d, comp) -> Dict[str, Any]:
    text = _blocks(d, "MANIFESTS").get(comp, "")
    if not text or text == "MISSING":
        return {}
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _argv(d, comp) -> Tuple[List[str], Optional[str]]:
    line = _blocks(d, "PROCS").get(comp, "").strip()
    if line:
        return line.split()[1:], "running process"
    containers = ((manifest(d, comp).get("spec") or {}).get("containers") or [])
    if containers:
        c = containers[0]
        return [str(x) for x in (c.get("command") or [])[1:] + (c.get("args") or [])], "static pod manifest"
    return [], None


def args(d, comp) -> Dict[str, str]:
    out: Dict[str, str] = {}
    argv, _src = _argv(d, comp)
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            if "=" in a:
                k, v = a[2:].split("=", 1)
            elif i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                k, v = a[2:], argv[i + 1]
                i += 1
            else:
                k, v = a[2:], "true"
            out[k] = v
        i += 1
    return out


def present(d, comp) -> bool:
    return _argv(d, comp)[1] is not None


def source(d, comp) -> str:
    return _argv(d, comp)[1] or "not found"


def kubelet_config(d) -> Dict[str, Any]:
    text = section(d, "KUBELET_CONFIG")
    if not text or text.strip() == "MISSING":
        return {}
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _dig(obj, path):
    for key in path.split("."):
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return obj


def kubelet(d, flag, config_path, config_default=None, flag_default=None):
    """A kubelet setting: the command-line flag wins, then the config file, then the default."""
    a = args(d, "kubelet")
    if flag in a:
        return a[flag]
    cfg = kubelet_config(d)
    value = _dig(cfg, config_path)
    if value is not None:
        return value
    return config_default if cfg else flag_default


def _s(v) -> str:
    return str(v).lower() if isinstance(v, bool) else str(v)


def files(d) -> Dict[str, List[Tuple[str, str, str, str, str]]]:
    out: Dict[str, List[Tuple[str, str, str, str, str]]] = {}
    for line in section(d, "FILES").splitlines():
        parts = line.split("|")
        if len(parts) == 6:
            out.setdefault(parts[0], []).append(tuple(parts[1:]))
    return out


def _mode_ok(mode: str, maximum: int) -> bool:
    try:
        return int(mode, 8) & ~maximum & 0o7777 == 0
    except ValueError:
        return False


def proxy_config(d) -> Optional[Dict[str, Any]]:
    text = section(d, "K8S_PROXY_CONFIG").strip()
    if not text or text == "NONE":
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


# ── cluster data ─────────────────────────────────────────────────────────

def _list(d, name) -> List[Dict[str, Any]]:
    v = json_section(d, name)
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def rbac(d):
    return _list(d, "K8S_RBAC")


def roles(d):
    return [r for r in rbac(d) if r.get("kind") in ("ClusterRole", "Role")]


def bindings(d):
    return [b for b in rbac(d) if b.get("kind") in ("ClusterRoleBinding", "RoleBinding")]


def builtin(role) -> bool:
    name = str(role.get("name") or "")
    return (name.startswith("system:") or name in BUILTIN_ROLES or role.get("aggregated")
            or (role.get("labels") or {}).get("kubernetes.io/bootstrapping") == "rbac-defaults")


def custom_roles(d):
    return [r for r in roles(d) if not builtin(r)]


def _label(role) -> str:
    return f"{role.get('kind')} {role.get('namespace') + '/' if role.get('namespace') else ''}{role.get('name')}"


def grants(role, resources, verbs, group="") -> bool:
    """Whether a role allows any of `verbs` on any of `resources` in API group `group`."""
    for rule in role.get("rules") or []:
        groups = rule.get("apiGroups") or [""]
        res = rule.get("resources") or []
        vb = rule.get("verbs") or []
        if (("*" in groups or group in groups) and ("*" in res or any(r in res for r in resources))
                and ("*" in vb or any(v in vb for v in verbs))):
            return True
    return False


def namespaces(d):
    return _list(d, "K8S_NAMESPACES")


def workload_pods(d):
    return [p for p in _list(d, "K8S_PODS") if p.get("namespace") != "kube-system"
            and p.get("phase") not in ("Succeeded", "Failed")]


def pod_name(p) -> str:
    return f"{p.get('namespace')}/{p.get('name')}"


def _names(items, limit=15) -> str:
    items = list(items)
    if not items:
        return "none"
    return ", ".join(str(i) for i in items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def psa_level(ns) -> Optional[str]:
    return (ns.get("labels") or {}).get("pod-security.kubernetes.io/enforce")


def _containers(p):
    return p.get("containers") or []


def _csc(c):
    return c.get("securityContext") or {}


def runs_as_root(p, c) -> bool:
    psc, csc = p.get("securityContext") or {}, _csc(c)
    non_root = csc.get("runAsNonRoot", psc.get("runAsNonRoot"))
    user = csc.get("runAsUser", psc.get("runAsUser"))
    return not (non_root is True or (isinstance(user, int) and user > 0))


def drops(c, cap) -> bool:
    dropped = [str(x).upper() for x in ((_csc(c).get("capabilities") or {}).get("drop") or [])]
    return "ALL" in dropped or cap in dropped


def seccomp_ok(p) -> bool:
    good = ("RuntimeDefault", "Localhost")
    pod_type = ((p.get("securityContext") or {}).get("seccompProfile") or {}).get("type")
    return all((((_csc(c).get("seccompProfile") or {}).get("type")) or pod_type) in good for c in _containers(p))


# ── rule builders ────────────────────────────────────────────────────────

def _rule(rules, sec, title, severity, check, evidence, remediation, sections, level="L1", manual=False,
          unavailable=None):
    rules.append(BenchmarkRule(
        id=f"K8S-{sec}", section=sec, title=title, severity=severity, level=level,
        check_fn=check, evidence_fn=evidence, remediation=remediation, description=title,
        manual=manual, data_sections=list(sections), source="CIS", unavailable_fn=unavailable))


def _manual(rules, sec, title, severity, guidance, evidence=None, level="L1", sections=()):
    _rule(rules, sec, title, severity, lambda d: False, evidence or (lambda d: "Review on the cluster."),
          guidance, sections, level=level, manual=True)


def _file_rule(rules, sec, tag, label, owner=None, mode=None, severity="medium"):
    def entries(d):
        return [e for e in files(d).get(tag, []) if e[4] != "missing"]

    def bad(d):
        out = []
        for path, o, g, m, _kind in entries(d):
            if owner and f"{o}:{g}" != owner:
                out.append(f"{path} ({o}:{g})")
            if mode is not None and not _mode_ok(m, mode):
                out.append(f"{path} ({m})")
        return out

    title = (f"Ensure that the {label} ownership is set to {owner}" if owner
             else f"Ensure that the {label} permissions are set to {mode:o} or more restrictive")
    _rule(rules, sec, title, severity, lambda d: not bad(d),
          lambda d: (f"Not compliant: {_names(bad(d))}" if bad(d)
                     else f"Compliant: {_names(e[0] for e in entries(d))}" if entries(d) else f"{label}: not present on this node"),
          f"chown {owner} <file>" if owner else f"chmod {mode:o} <file>", ["FILES"])


def _arg_rule(rules, sec, comp, title, severity, ok, remediation, level="L1", shown=()):
    def evidence(d):
        a = args(d, comp)
        keys = shown or ()
        vals = ", ".join(f"--{k}={a[k]}" if k in a else f"--{k} not set" for k in keys)
        return f"{comp} ({source(d, comp)}): {vals}"
    _rule(rules, sec, title, severity, lambda d: ok(args(d, comp)), evidence, remediation, ["PROCS", "MANIFESTS"],
          level=level)


def _flag_is(comp, flag, value):
    return lambda a: a.get(flag) == value


def _plugins(a) -> List[str]:
    return [p for p in a.get("enable-admission-plugins", "").split(",") if p]


def _disabled(a) -> List[str]:
    return [p for p in a.get("disable-admission-plugins", "").split(",") if p]


def _authz(a) -> List[str]:
    return [m for m in a.get("authorization-mode", "AlwaysAllow").split(",") if m]


def _strong_ciphers(value) -> bool:
    items = value if isinstance(value, list) else [x for x in str(value or "").split(",") if x]
    return bool(items) and not any(WEAK_CIPHER.search(x) for x in items)


def _role_rule(rules, sec, title, severity, grants_any, remediation, level="L1"):
    """grants_any: (resources, verbs, api group) triples; one match is enough."""
    def offenders(d):
        return [_label(r) for r in custom_roles(d) if any(grants(r, res, vb, g) for res, vb, g in grants_any)]
    _rule(rules, sec, title, severity, lambda d: not offenders(d),
          lambda d: "Custom roles granting it: " + _names(offenders(d)), remediation, ["K8S_RBAC"], level=level)


def _pod_rule(rules, sec, title, severity, bad, describe, remediation, level="L1"):
    def offenders(d):
        return [p for p in workload_pods(d) if bad(p)]

    def evidence(d):
        enforced = [f"{n['name']}={psa_level(n)}" for n in namespaces(d)
                    if psa_level(n) and n.get("name") not in SYSTEM_NAMESPACES]
        return (f"{len(workload_pods(d))} pods outside kube-system; not compliant: "
                + _names(f"{pod_name(p)} ({describe(p)})" for p in offenders(d))
                + f". Namespaces enforcing Pod Security: {_names(enforced)}")
    _rule(rules, sec, title, severity, lambda d: not offenders(d), evidence, remediation,
          ["K8S_PODS"], level=level)


# ── the benchmark ────────────────────────────────────────────────────────

CONTROL_PLANE_FILES = (
    ("1.1.1", "apiserver_manifest", "API server pod specification file", None, 0o600),
    ("1.1.2", "apiserver_manifest", "API server pod specification file", "root:root", None),
    ("1.1.3", "controller_manager_manifest", "controller manager pod specification file", None, 0o600),
    ("1.1.4", "controller_manager_manifest", "controller manager pod specification file", "root:root", None),
    ("1.1.5", "scheduler_manifest", "scheduler pod specification file", None, 0o600),
    ("1.1.6", "scheduler_manifest", "scheduler pod specification file", "root:root", None),
    ("1.1.7", "etcd_manifest", "etcd pod specification file", None, 0o600),
    ("1.1.8", "etcd_manifest", "etcd pod specification file", "root:root", None),
    ("1.1.9", "cni", "Container Network Interface file", None, 0o600),
    ("1.1.10", "cni", "Container Network Interface file", "root:root", None),
    ("1.1.11", "etcd_data", "etcd data directory", None, 0o700),
    ("1.1.12", "etcd_data", "etcd data directory", "etcd:etcd", None),
    ("1.1.13", "admin_conf", "default administrative credential file (admin.conf, super-admin.conf)", None, 0o600),
    ("1.1.14", "admin_conf", "default administrative credential file (admin.conf, super-admin.conf)", "root:root", None),
    ("1.1.15", "scheduler_conf", "scheduler.conf file", None, 0o600),
    ("1.1.16", "scheduler_conf", "scheduler.conf file", "root:root", None),
    ("1.1.17", "controller_manager_conf", "controller-manager.conf file", None, 0o600),
    ("1.1.18", "controller_manager_conf", "controller-manager.conf file", "root:root", None),
    ("1.1.19", "pki_all", "Kubernetes PKI directory and file", "root:root", None),
    ("1.1.20", "pki_crt", "Kubernetes PKI certificate file", None, 0o600),
    ("1.1.21", "pki_key", "Kubernetes PKI key file", None, 0o600),
)
NODE_FILES = (
    ("4.1.1", "kubelet_service", "kubelet service file", None, 0o600),
    ("4.1.2", "kubelet_service", "kubelet service file", "root:root", None),
    ("4.1.5", "kubelet_kubeconfig", "kubelet kubeconfig file (kubelet.conf)", None, 0o600),
    ("4.1.6", "kubelet_kubeconfig", "kubelet kubeconfig file (kubelet.conf)", "root:root", None),
    ("4.1.7", "kubelet_ca", "certificate authorities file", None, 0o600),
    ("4.1.8", "kubelet_ca", "client certificate authorities file", "root:root", None),
    ("4.1.9", "kubelet_config", "kubelet configuration file (config.yaml)", None, 0o600),
    ("4.1.10", "kubelet_config", "kubelet configuration file (config.yaml)", "root:root", None),
)


def _control_plane_rules(r: List[BenchmarkRule]) -> None:
    for sec, tag, label, owner, mode in CONTROL_PLANE_FILES:
        _file_rule(r, sec, tag, label, owner, mode, "high" if tag in ("admin_conf", "pki_key") else "medium")

    A = "kube-apiserver"
    _arg_rule(r, "1.2.1", A, "Ensure that the --anonymous-auth argument is set to false", "medium",
              _flag_is(A, "anonymous-auth", "false"),
              "Set --anonymous-auth=false (keep the liveness probes working: they then need credentials).",
              shown=("anonymous-auth",))
    _arg_rule(r, "1.2.2", A, "Ensure that the --token-auth-file parameter is not set", "high",
              lambda a: "token-auth-file" not in a, "Remove --token-auth-file; use another authentication method.",
              shown=("token-auth-file",))
    _arg_rule(r, "1.2.3", A, "Ensure that the --DenyServiceExternalIPs is set", "medium",
              lambda a: "DenyServiceExternalIPs" in _plugins(a), "Add DenyServiceExternalIPs to --enable-admission-plugins.",
              shown=("enable-admission-plugins",))
    _arg_rule(r, "1.2.4", A, "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
              "high", lambda a: bool(a.get("kubelet-client-certificate") and a.get("kubelet-client-key")),
              "Set --kubelet-client-certificate and --kubelet-client-key.",
              shown=("kubelet-client-certificate", "kubelet-client-key"))
    _arg_rule(r, "1.2.5", A, "Ensure that the --kubelet-certificate-authority argument is set as appropriate", "high",
              lambda a: bool(a.get("kubelet-certificate-authority")),
              "Set --kubelet-certificate-authority to the CA that signs the kubelet serving certificates.",
              shown=("kubelet-certificate-authority",))
    _arg_rule(r, "1.2.6", A, "Ensure that the --authorization-mode argument is not set to AlwaysAllow", "high",
              lambda a: "AlwaysAllow" not in _authz(a), "Set --authorization-mode=Node,RBAC.", shown=("authorization-mode",))
    _arg_rule(r, "1.2.7", A, "Ensure that the --authorization-mode argument includes Node", "high",
              lambda a: "Node" in _authz(a), "Include Node in --authorization-mode.", shown=("authorization-mode",))
    _arg_rule(r, "1.2.8", A, "Ensure that the --authorization-mode argument includes RBAC", "high",
              lambda a: "RBAC" in _authz(a), "Include RBAC in --authorization-mode.", shown=("authorization-mode",))
    _arg_rule(r, "1.2.9", A, "Ensure that the admission control plugin EventRateLimit is set", "medium",
              lambda a: "EventRateLimit" in _plugins(a),
              "Add EventRateLimit with an --admission-control-config-file.", shown=("enable-admission-plugins",))
    _arg_rule(r, "1.2.10", A, "Ensure that the admission control plugin AlwaysAdmit is not set", "high",
              lambda a: "AlwaysAdmit" not in _plugins(a), "Remove AlwaysAdmit from --enable-admission-plugins.",
              shown=("enable-admission-plugins",))
    _arg_rule(r, "1.2.11", A, "Ensure that the admission control plugin AlwaysPullImages is set", "medium",
              lambda a: "AlwaysPullImages" in _plugins(a), "Add AlwaysPullImages to --enable-admission-plugins.",
              shown=("enable-admission-plugins",))
    _arg_rule(r, "1.2.12", A, "Ensure that the admission control plugin ServiceAccount is set", "high",
              lambda a: "ServiceAccount" not in _disabled(a), "Remove ServiceAccount from --disable-admission-plugins.",
              shown=("disable-admission-plugins",))
    _arg_rule(r, "1.2.13", A, "Ensure that the admission control plugin NamespaceLifecycle is set", "medium",
              lambda a: "NamespaceLifecycle" not in _disabled(a),
              "Remove NamespaceLifecycle from --disable-admission-plugins.", shown=("disable-admission-plugins",))
    _arg_rule(r, "1.2.14", A, "Ensure that the admission control plugin NodeRestriction is set", "high",
              lambda a: "NodeRestriction" in _plugins(a), "Add NodeRestriction to --enable-admission-plugins.",
              shown=("enable-admission-plugins",))
    _arg_rule(r, "1.2.15", A, "Ensure that the --profiling argument is set to false", "low",
              _flag_is(A, "profiling", "false"), "Set --profiling=false.", shown=("profiling",))
    _arg_rule(r, "1.2.16", A, "Ensure that the --audit-log-path argument is set", "medium",
              lambda a: bool(a.get("audit-log-path")),
              "Set --audit-log-path (with a hostPath volume for the log directory) and --audit-policy-file.",
              shown=("audit-log-path",))
    for sec, flag, minimum in (("1.2.17", "audit-log-maxage", 30), ("1.2.18", "audit-log-maxbackup", 10),
                               ("1.2.19", "audit-log-maxsize", 100)):
        _arg_rule(r, sec, A, f"Ensure that the --{flag} argument is set to {minimum} or as appropriate", "low",
                  (lambda a, f=flag, m=minimum: str(a.get(f, "")).isdigit() and int(a[f]) >= m),
                  f"Set --{flag}={minimum}.", shown=(flag,))
    _manual(r, "1.2.20", "Ensure that the --request-timeout argument is set as appropriate", "low",
            "Leave the default (60s) unless large requests need longer.",
            lambda d: f"--request-timeout = {args(d, A).get('request-timeout', '60s (default)')}", sections=["PROCS"])
    _arg_rule(r, "1.2.21", A, "Ensure that the --service-account-lookup argument is set to true", "medium",
              lambda a: a.get("service-account-lookup", "true") != "false", "Set --service-account-lookup=true.",
              shown=("service-account-lookup",))
    _arg_rule(r, "1.2.22", A, "Ensure that the --service-account-key-file argument is set as appropriate", "medium",
              lambda a: bool(a.get("service-account-key-file")), "Set --service-account-key-file.",
              shown=("service-account-key-file",))
    _arg_rule(r, "1.2.23", A, "Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
              "high", lambda a: bool(a.get("etcd-certfile") and a.get("etcd-keyfile")),
              "Set --etcd-certfile and --etcd-keyfile.", shown=("etcd-certfile", "etcd-keyfile"))
    _arg_rule(r, "1.2.24", A, "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
              "high", lambda a: bool(a.get("tls-cert-file") and a.get("tls-private-key-file")),
              "Set --tls-cert-file and --tls-private-key-file.", shown=("tls-cert-file", "tls-private-key-file"))
    _arg_rule(r, "1.2.25", A, "Ensure that the --client-ca-file argument is set as appropriate", "high",
              lambda a: bool(a.get("client-ca-file")), "Set --client-ca-file.", shown=("client-ca-file",))
    _arg_rule(r, "1.2.26", A, "Ensure that the --etcd-cafile argument is set as appropriate", "high",
              lambda a: bool(a.get("etcd-cafile")), "Set --etcd-cafile.", shown=("etcd-cafile",))
    _arg_rule(r, "1.2.27", A, "Ensure that the --encryption-provider-config argument is set as appropriate", "high",
              lambda a: bool(a.get("encryption-provider-config")),
              "Create an EncryptionConfiguration and set --encryption-provider-config.",
              shown=("encryption-provider-config",))
    _rule(r, "1.2.28", "Ensure that encryption providers are appropriately configured", "high",
          lambda d: (section(d, "ENCRYPTION").split() or ["identity"])[0] in ("aescbc", "aesgcm", "secretbox", "kms"),
          lambda d: f"providers in order: {section(d, 'ENCRYPTION').strip() or 'none'}",
          "Put aescbc, secretbox or kms first in the EncryptionConfiguration (identity last or absent).",
          ["ENCRYPTION"])
    _arg_rule(r, "1.2.29", A, "Ensure that the API Server only makes use of Strong Cryptographic Ciphers", "medium",
              lambda a: _strong_ciphers(a.get("tls-cipher-suites")),
              "Set --tls-cipher-suites to ECDHE suites with AES-GCM or ChaCha20.", shown=("tls-cipher-suites",))

    C = "kube-controller-manager"
    _arg_rule(r, "1.3.1", C, "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate", "low",
              lambda a: bool(a.get("terminated-pod-gc-threshold")), "Set --terminated-pod-gc-threshold (e.g. 1000).",
              shown=("terminated-pod-gc-threshold",))
    _arg_rule(r, "1.3.2", C, "Ensure that the --profiling argument is set to false", "low",
              _flag_is(C, "profiling", "false"), "Set --profiling=false.", shown=("profiling",))
    _arg_rule(r, "1.3.3", C, "Ensure that the --use-service-account-credentials argument is set to true", "medium",
              _flag_is(C, "use-service-account-credentials", "true"), "Set --use-service-account-credentials=true.",
              shown=("use-service-account-credentials",))
    _arg_rule(r, "1.3.4", C, "Ensure that the --service-account-private-key-file argument is set as appropriate", "medium",
              lambda a: bool(a.get("service-account-private-key-file")), "Set --service-account-private-key-file.",
              shown=("service-account-private-key-file",))
    _arg_rule(r, "1.3.5", C, "Ensure that the --root-ca-file argument is set as appropriate", "medium",
              lambda a: bool(a.get("root-ca-file")), "Set --root-ca-file.", shown=("root-ca-file",))
    _arg_rule(r, "1.3.6", C, "Ensure that the RotateKubeletServerCertificate argument is set to true", "medium",
              lambda a: "RotateKubeletServerCertificate=false" not in a.get("feature-gates", ""),
              "Remove RotateKubeletServerCertificate=false from --feature-gates.", level="L2", shown=("feature-gates",))
    _arg_rule(r, "1.3.7", C, "Ensure that the --bind-address argument is set to 127.0.0.1", "low",
              _flag_is(C, "bind-address", "127.0.0.1"), "Set --bind-address=127.0.0.1.", shown=("bind-address",))
    S = "kube-scheduler"
    _arg_rule(r, "1.4.1", S, "Ensure that the --profiling argument is set to false", "low",
              _flag_is(S, "profiling", "false"), "Set --profiling=false.", shown=("profiling",))
    _arg_rule(r, "1.4.2", S, "Ensure that the --bind-address argument is set to 127.0.0.1", "low",
              _flag_is(S, "bind-address", "127.0.0.1"), "Set --bind-address=127.0.0.1.", shown=("bind-address",))


def _etcd_rules(r: List[BenchmarkRule]) -> None:
    E = "etcd"
    _arg_rule(r, "2.1", E, "Ensure that the --cert-file and --key-file arguments are set as appropriate", "high",
              lambda a: bool(a.get("cert-file") and a.get("key-file")), "Set --cert-file and --key-file.",
              shown=("cert-file", "key-file"))
    _arg_rule(r, "2.2", E, "Ensure that the --client-cert-auth argument is set to true", "high",
              _flag_is(E, "client-cert-auth", "true"), "Set --client-cert-auth=true.", shown=("client-cert-auth",))
    _arg_rule(r, "2.3", E, "Ensure that the --auto-tls argument is not set to true", "high",
              lambda a: a.get("auto-tls", "false") != "true", "Remove --auto-tls or set it to false.", shown=("auto-tls",))
    _arg_rule(r, "2.4", E, "Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate", "high",
              lambda a: bool(a.get("peer-cert-file") and a.get("peer-key-file")),
              "Set --peer-cert-file and --peer-key-file.", shown=("peer-cert-file", "peer-key-file"))
    _arg_rule(r, "2.5", E, "Ensure that the --peer-client-cert-auth argument is set to true", "high",
              _flag_is(E, "peer-client-cert-auth", "true"), "Set --peer-client-cert-auth=true.",
              shown=("peer-client-cert-auth",))
    _arg_rule(r, "2.6", E, "Ensure that the --peer-auto-tls argument is not set to true", "high",
              lambda a: a.get("peer-auto-tls", "false") != "true", "Remove --peer-auto-tls or set it to false.",
              shown=("peer-auto-tls",))
    _manual(r, "2.7", "Ensure that a unique Certificate Authority is used for etcd", "medium",
            "Give etcd its own CA, distinct from the cluster CA.",
            lambda d: (f"etcd --trusted-ca-file = {args(d, 'etcd').get('trusted-ca-file')}; "
                       f"API server --client-ca-file = {args(d, 'kube-apiserver').get('client-ca-file')}"),
            level="L2", sections=["PROCS", "MANIFESTS"])


def _control_plane_config_rules(r: List[BenchmarkRule]) -> None:
    _manual(r, "3.1.1", "Client certificate authentication should not be used for users", "medium",
            "Use OIDC or another revocable method for people; keep client certificates for components.", level="L2")
    _manual(r, "3.1.2", "Service account token authentication should not be used for users", "medium",
            "Give people their own identities, not service account tokens.", level="L2")
    _manual(r, "3.1.3", "Bootstrap token authentication should not be used for users", "medium",
            "Use bootstrap tokens only to join nodes.", level="L2")
    _rule(r, "3.2.1", "Ensure that a minimal audit policy is created", "medium",
          lambda d: bool(args(d, "kube-apiserver").get("audit-policy-file"))
          and not section(d, "AUDIT_POLICY").strip().startswith(("NONE", "MISSING")),
          lambda d: (f"--audit-policy-file = {args(d, 'kube-apiserver').get('audit-policy-file')}; "
                     f"policy file: {section(d, 'AUDIT_POLICY').strip().splitlines()[0] if section(d, 'AUDIT_POLICY').strip() else 'none'}"),
          "Create an audit policy and set --audit-policy-file.", ["PROCS", "MANIFESTS"])
    _manual(r, "3.2.2", "Ensure that the audit policy covers key security concerns", "medium",
            "Log Secret/ConfigMap/TokenReview access at Metadata level, pods/exec and RBAC changes at RequestResponse.",
            lambda d: "audit policy rules: " + _names(
                f"{rule.get('level')}:{','.join(r2 for x in rule.get('resources') or [] for r2 in (x.get('resources') or ['*']))}"
                for rule in ((_yaml(section(d, 'AUDIT_POLICY')) or {}).get('rules') or []) if isinstance(rule, dict)),
            level="L2", sections=["AUDIT_POLICY"])


def _yaml(text):
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return None


def _node_rules(r: List[BenchmarkRule]) -> None:
    for sec, tag, label, owner, mode in NODE_FILES:
        _file_rule(r, sec, tag, label, owner, mode)
    _manual(r, "4.1.3", "If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive", "medium",
            "kubeadm mounts the kube-proxy kubeconfig from a ConfigMap; where kube-proxy runs as a host service, chmod 600 its kubeconfig.",
            lambda d: f"kube-proxy on this host: {source(d, 'kube-proxy')}, --kubeconfig = {args(d, 'kube-proxy').get('kubeconfig')}",
            sections=["PROCS"])
    _manual(r, "4.1.4", "If proxy kubeconfig file exists ensure ownership is set to root:root", "medium",
            "Where kube-proxy runs as a host service, chown root:root its kubeconfig.",
            lambda d: f"kube-proxy on this host: {source(d, 'kube-proxy')}", sections=["PROCS"])

    K = ["PROCS", "KUBELET_CONFIG"]

    def kr(sec, title, severity, value, ok, remediation, level="L1"):
        _rule(r, sec, title, severity, lambda d: ok(value(d)), lambda d: f"kubelet: {value(d)!r}", remediation, K,
              level=level)

    kr("4.2.1", "Ensure that the --anonymous-auth argument is set to false", "high",
       lambda d: kubelet(d, "anonymous-auth", "authentication.anonymous.enabled", False, "true"),
       lambda v: _s(v) == "false", "Set authentication.anonymous.enabled: false in the kubelet config.")
    kr("4.2.2", "Ensure that the --authorization-mode argument is not set to AlwaysAllow", "high",
       lambda d: kubelet(d, "authorization-mode", "authorization.mode", "Webhook", "AlwaysAllow"),
       lambda v: str(v) != "AlwaysAllow", "Set authorization.mode: Webhook in the kubelet config.")
    kr("4.2.3", "Ensure that the --client-ca-file argument is set as appropriate", "high",
       lambda d: kubelet(d, "client-ca-file", "authentication.x509.clientCAFile"),
       lambda v: bool(v), "Set authentication.x509.clientCAFile in the kubelet config.")
    kr("4.2.4", "Verify that the --read-only-port argument is set to 0", "medium",
       lambda d: kubelet(d, "read-only-port", "readOnlyPort", 0, "10255"),
       lambda v: str(v) == "0", "Set readOnlyPort: 0 in the kubelet config.")
    def idle_timeout(d):
        # The kubelet replaces a zero duration in its config file with the 4h
        # default (kubeadm writes "0s"); only an explicit 0 flag disables it.
        a = args(d, "kubelet")
        if "streaming-connection-idle-timeout" in a:
            return a["streaming-connection-idle-timeout"]
        v = _dig(kubelet_config(d), "streamingConnectionIdleTimeout")
        return "4h0m0s (default)" if v in (None, "0", "0s", 0) else v
    kr("4.2.5", "Ensure that the --streaming-connection-idle-timeout argument is not set to 0", "low", idle_timeout,
       lambda v: str(v) not in ("0", "0s", "0m", "0h"), "Set streamingConnectionIdleTimeout: 4h0m0s.")
    kr("4.2.6", "Ensure that the --make-iptables-util-chains argument is set to true", "low",
       lambda d: kubelet(d, "make-iptables-util-chains", "makeIPTablesUtilChains", True, "true"),
       lambda v: _s(v) == "true", "Set makeIPTablesUtilChains: true.")
    _rule(r, "4.2.7", "Ensure that the --hostname-override argument is not set", "low",
          lambda d: "hostname-override" not in args(d, "kubelet"),
          lambda d: f"--hostname-override = {args(d, 'kubelet').get('hostname-override', 'not set')}",
          "Remove --hostname-override from the kubelet flags.", ["PROCS"])
    _manual(r, "4.2.8", "Ensure that the eventRecordQPS argument is set to a level which ensures appropriate event capture",
            "low", "Set eventRecordQPS so that events are not dropped (0 = unlimited).",
            lambda d: f"eventRecordQPS = {kubelet(d, 'event-qps', 'eventRecordQPS', 50, 5)}", level="L2", sections=K)
    kr("4.2.9", "Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate", "medium",
       lambda d: {"cert": kubelet(d, "tls-cert-file", "tlsCertFile"), "key": kubelet(d, "tls-private-key-file", "tlsPrivateKeyFile"),
                  "serverTLSBootstrap": kubelet(d, "serverTLSBootstrap", "serverTLSBootstrap")},
       lambda v: bool(v["cert"] and v["key"]) or _s(v["serverTLSBootstrap"]) == "true",
       "Give the kubelet a CA-signed serving certificate (tlsCertFile/tlsPrivateKeyFile or serverTLSBootstrap: true).")
    kr("4.2.10", "Ensure that the --rotate-certificates argument is not set to false", "medium",
       lambda d: kubelet(d, "rotate-certificates", "rotateCertificates"),
       lambda v: _s(v) != "false", "Set rotateCertificates: true.")
    kr("4.2.11", "Verify that the RotateKubeletServerCertificate argument is set to true", "medium",
       lambda d: kubelet(d, "feature-gates", "featureGates.RotateKubeletServerCertificate"),
       lambda v: "RotateKubeletServerCertificate=false" not in _s(v) and _s(v) != "false",
       "Remove RotateKubeletServerCertificate=false from the kubelet feature gates.")
    kr("4.2.12", "Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers", "medium",
       lambda d: kubelet(d, "tls-cipher-suites", "tlsCipherSuites"),
       _strong_ciphers, "Set tlsCipherSuites to ECDHE suites with AES-GCM or ChaCha20.")
    kr("4.2.13", "Ensure that a limit is set on pod PIDs", "medium",
       lambda d: kubelet(d, "pod-max-pids", "podPidsLimit"),
       lambda v: str(v).lstrip("-").isdigit() and int(v) > 0, "Set podPidsLimit in the kubelet config.")

    def metrics(d):
        a = args(d, "kube-proxy")
        if a:
            return a.get("metrics-bind-address", "127.0.0.1:10249"), "kube-proxy process"
        cfg = proxy_config(d)
        if cfg is None:
            return None, "no kube-proxy"
        return cfg.get("metricsBindAddress") or "127.0.0.1:10249 (default)", "kube-proxy ConfigMap"

    _rule(r, "4.3.1", "Ensure that the kube-proxy metrics service is bound to localhost", "low",
          lambda d: metrics(d)[0] is None or str(metrics(d)[0]).startswith(("127.0.0.1", "localhost", "[::1]")),
          lambda d: f"metricsBindAddress = {metrics(d)[0]} ({metrics(d)[1]})",
          "Set metricsBindAddress: 127.0.0.1:10249 in the kube-proxy configuration.", ["PROCS", "K8S_PROXY_CONFIG"],
          unavailable=lambda d: (None if args(d, "kube-proxy") or not section(d, "K8S_PROXY_CONFIG").strip().startswith(
              ("CMD_ERROR", "SSH_ERROR")) else "the kube-proxy configuration could not be read: "
              + section(d, "K8S_PROXY_CONFIG").strip().splitlines()[0][:160]))


def _policy_rules(r: List[BenchmarkRule]) -> None:
    R = ["K8S_RBAC"]

    def admin_subjects(d):
        out = []
        for b in bindings(d):
            if b.get("roleRef") == "cluster-admin" and b.get("roleKind") == "ClusterRole":
                for s in b.get("subjects") or []:
                    if not (s.get("kind") == "Group" and s.get("name") in DEFAULT_ADMIN_GROUPS):
                        out.append(f"{s.get('kind')} {s.get('name')} via {b.get('name')}")
        return out

    _rule(r, "5.1.1", "Ensure that the cluster-admin role is only used where required", "high",
          lambda d: not admin_subjects(d), lambda d: "cluster-admin granted to: " + _names(admin_subjects(d)),
          "Bind narrower roles; keep cluster-admin for break-glass accounts.", R)
    _role_rule(r, "5.1.2", "Minimize access to secrets", "high", [(["secrets"], ["get", "list", "watch"], "")],
               "Remove get/list/watch on secrets from roles that do not need it.")

    def wildcards(d):
        return [_label(x) for x in custom_roles(d)
                if any("*" in (rule.get("resources") or []) or "*" in (rule.get("verbs") or []) for rule in x.get("rules") or [])]
    _rule(r, "5.1.3", "Minimize wildcard use in Roles and ClusterRoles", "medium", lambda d: not wildcards(d),
          lambda d: "Custom roles with wildcards: " + _names(wildcards(d)), "List resources and verbs explicitly.", R)
    _role_rule(r, "5.1.4", "Minimize access to create pods", "medium", [(["pods"], ["create"], "")],
               "Remove create on pods from roles that do not need it.")

    def default_sa(d):
        out = [f"{s.get('namespace')}/default" for s in _list(d, "K8S_SERVICEACCOUNTS")
               if s.get("name") == "default" and s.get("automount") is not False]
        out += [f"bound by {b.get('name')}" for b in bindings(d) for s in b.get("subjects") or []
                if s.get("kind") == "ServiceAccount" and s.get("name") == "default"]
        return out
    _rule(r, "5.1.5", "Ensure that default service accounts are not actively used", "medium",
          lambda d: not default_sa(d),
          lambda d: "default service accounts that mount tokens or are bound to roles: " + _names(default_sa(d)),
          "Set automountServiceAccountToken: false on each namespace's default service account; give workloads their own.",
          ["K8S_SERVICEACCOUNTS", "K8S_RBAC"])
    _manual(r, "5.1.6", "Ensure that Service Account Tokens are only mounted where necessary", "medium",
            "Set automountServiceAccountToken: false on pods and service accounts that do not call the API.",
            lambda d: "pods mounting a token (outside kube-system): " + _names(
                pod_name(p) for p in workload_pods(d) if p.get("automount") is not False), sections=["K8S_PODS"])
    _manual(r, "5.1.7", "Avoid use of system:masters group", "high",
            "Do not issue certificates in system:masters; it bypasses RBAC and cannot be revoked.",
            lambda d: "bindings naming system:masters: " + _names(
                b.get("name") for b in bindings(d) for s in b.get("subjects") or [] if s.get("name") == "system:masters"),
            sections=R)
    _role_rule(r, "5.1.8", "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster", "high",
               [(["clusterroles", "roles"], ["bind", "escalate"], "rbac.authorization.k8s.io"),
                (["users", "groups", "serviceaccounts"], ["impersonate"], ""),
                (["userextras", "uids"], ["impersonate"], "authentication.k8s.io")],
               "Remove bind/impersonate/escalate from roles that do not need them.")
    _role_rule(r, "5.1.9", "Minimize access to create persistent volumes", "medium",
               [(["persistentvolumes"], ["create"], "")],
               "Remove create on persistentvolumes from roles that do not need it.")
    _role_rule(r, "5.1.10", "Minimize access to the proxy sub-resource of nodes", "high",
               [(["nodes/proxy"], ["get", "create", "update", "patch", "delete", "list", "watch"], "")],
               "Remove access to nodes/proxy.")
    _role_rule(r, "5.1.11", "Minimize access to the approval sub-resource of certificatesigningrequests objects", "high",
               [(["certificatesigningrequests/approval"], ["update", "patch"], "certificates.k8s.io")],
               "Remove update/patch on certificatesigningrequests/approval.")
    _role_rule(r, "5.1.12", "Minimize access to webhook configuration objects", "high",
               [(["validatingwebhookconfigurations", "mutatingwebhookconfigurations"],
                 ["create", "update", "patch", "delete"], "admissionregistration.k8s.io")],
               "Remove write access to admission webhook configurations.")
    _role_rule(r, "5.1.13", "Minimize access to the service account token creation", "medium",
               [(["serviceaccounts/token"], ["create"], "")], "Remove create on serviceaccounts/token.")

    def policy_mechanisms(d):
        psa = [f"{n['name']}={psa_level(n)}" for n in namespaces(d) if psa_level(n)]
        engines = [w.get("name") for w in _list(d, "K8S_WEBHOOKS") if POLICY_ENGINES.search(str(w.get("name")))]
        return psa, engines
    _rule(r, "5.2.1", "Ensure that the cluster has at least one active policy control mechanism in place", "high",
          lambda d: any(policy_mechanisms(d)),
          lambda d: (f"Pod Security admission labels: {_names(policy_mechanisms(d)[0])}; "
                     f"policy engine webhooks: {_names(policy_mechanisms(d)[1])}"),
          "Label namespaces with pod-security.kubernetes.io/enforce (baseline or restricted) or deploy a policy engine.",
          ["K8S_NAMESPACES", "K8S_WEBHOOKS"])
    _pod_rule(r, "5.2.2", "Minimize the admission of privileged containers", "high",
              lambda p: any(_csc(c).get("privileged") for c in _containers(p)), lambda p: "privileged",
              "Enforce the baseline Pod Security Standard; remove privileged: true.")
    _pod_rule(r, "5.2.3", "Minimize the admission of containers wishing to share the host process ID namespace", "high",
              lambda p: p.get("hostPID"), lambda p: "hostPID", "Remove hostPID: true.")
    _pod_rule(r, "5.2.4", "Minimize the admission of containers wishing to share the host IPC namespace", "high",
              lambda p: p.get("hostIPC"), lambda p: "hostIPC", "Remove hostIPC: true.")
    _pod_rule(r, "5.2.5", "Minimize the admission of containers wishing to share the host network namespace", "high",
              lambda p: p.get("hostNetwork"), lambda p: "hostNetwork", "Remove hostNetwork: true.")
    _pod_rule(r, "5.2.6", "Minimize the admission of containers with allowPrivilegeEscalation", "high",
              lambda p: any(_csc(c).get("allowPrivilegeEscalation") is not False for c in _containers(p)),
              lambda p: "allowPrivilegeEscalation not false", "Set allowPrivilegeEscalation: false on every container.")
    _pod_rule(r, "5.2.7", "Minimize the admission of root containers", "medium",
              lambda p: any(runs_as_root(p, c) for c in _containers(p)), lambda p: "may run as root",
              "Set runAsNonRoot: true (and a non-zero runAsUser).", level="L2")
    _pod_rule(r, "5.2.8", "Minimize the admission of containers with the NET_RAW capability", "medium",
              lambda p: any(not drops(c, "NET_RAW") for c in _containers(p)), lambda p: "NET_RAW not dropped",
              "Drop NET_RAW (or ALL) in each container's capabilities.")
    _pod_rule(r, "5.2.9", "Minimize the admission of containers with added capabilities", "medium",
              lambda p: any((_csc(c).get("capabilities") or {}).get("add") for c in _containers(p)),
              lambda p: "added " + ",".join(str(x) for c in _containers(p)
                                            for x in ((_csc(c).get("capabilities") or {}).get("add") or [])),
              "Remove added capabilities.")
    _pod_rule(r, "5.2.10", "Minimize the admission of containers with capabilities assigned", "low",
              lambda p: any(not drops(c, "ALL") for c in _containers(p)), lambda p: "capabilities not dropped",
              "Drop ALL capabilities and add back only what is needed.", level="L2")
    _pod_rule(r, "5.2.11", "Minimize the admission of Windows HostProcess Containers", "high",
              lambda p: any(((_csc(c).get("windowsOptions") or {}).get("hostProcess")) for c in _containers(p))
              or ((p.get("securityContext") or {}).get("windowsOptions") or {}).get("hostProcess"),
              lambda p: "Windows HostProcess", "Remove windowsOptions.hostProcess: true.")
    _pod_rule(r, "5.2.12", "Minimize the admission of HostPath volumes", "medium",
              lambda p: bool(p.get("hostPaths")), lambda p: "hostPath " + ",".join(str(x) for x in p.get("hostPaths") or []),
              "Use other volume types instead of hostPath.")
    _pod_rule(r, "5.2.13", "Minimize the admission of containers which use HostPorts", "medium",
              lambda p: any(c.get("hostPorts") for c in _containers(p)),
              lambda p: "hostPort " + ",".join(str(x) for c in _containers(p) for x in c.get("hostPorts") or []),
              "Remove hostPort; expose through a Service.")

    _manual(r, "5.3.1", "Ensure that the CNI in use supports Network Policies", "medium",
            "Use a CNI that enforces NetworkPolicy (Calico, Cilium, Antrea, ...).",
            lambda d: f"CNI configuration files: {section(d, 'CNI').strip() or 'none'}", sections=["CNI"])

    def without_netpol(d):
        covered = {n.get("namespace") for n in _list(d, "K8S_NETPOL")}
        return [n.get("name") for n in namespaces(d) if n.get("name") not in SYSTEM_NAMESPACES and n.get("name") not in covered]
    _rule(r, "5.3.2", "Ensure that all Namespaces have Network Policies defined", "medium",
          lambda d: not without_netpol(d), lambda d: "Namespaces without a NetworkPolicy: " + _names(without_netpol(d)),
          "Add a default-deny NetworkPolicy to each namespace, then allow the traffic it needs.",
          ["K8S_NAMESPACES", "K8S_NETPOL"], level="L2")

    def secret_env(d):
        return [f"{pod_name(p)} ({c.get('name')})" for p in _list(d, "K8S_PODS") for c in _containers(p)
                if c.get("secretEnv") or c.get("secretEnvFrom")]
    _rule(r, "5.4.1", "Prefer using Secrets as files over Secrets as environment variables", "medium",
          lambda d: not secret_env(d), lambda d: "Containers reading Secrets into environment variables: " + _names(secret_env(d)),
          "Mount Secrets as volumes instead of env/envFrom.", ["K8S_PODS"], level="L2")
    _manual(r, "5.4.2", "Consider external secret storage", "medium",
            "Use an external secrets manager (Vault, a cloud KMS-backed store) for sensitive secrets.", level="L2")
    _manual(r, "5.5.1", "Configure Image Provenance using ImagePolicyWebhook admission controller", "medium",
            "Verify image signatures at admission (ImagePolicyWebhook or a policy engine).",
            lambda d: "admission plugins: " + _names(_plugins(args(d, "kube-apiserver"))), level="L2",
            sections=["PROCS", "MANIFESTS"])
    _manual(r, "5.7.1", "Create administrative boundaries between resources using namespaces", "low",
            "Separate teams and environments into namespaces with their own RBAC and quotas.",
            lambda d: "namespaces: " + _names(n.get("name") for n in namespaces(d)), sections=["K8S_NAMESPACES"])
    _pod_rule(r, "5.7.2", "Ensure that the seccomp profile is set to docker/default in your Pod definitions", "medium",
              lambda p: not seccomp_ok(p), lambda p: "no RuntimeDefault seccomp profile",
              "Set seccompProfile.type: RuntimeDefault in the pod securityContext.", level="L2")
    _pod_rule(r, "5.7.3", "Apply Security Context to Your Pods and Containers", "medium",
              lambda p: not (p.get("securityContext") or any(_csc(c) for c in _containers(p))),
              lambda p: "no security context", "Give every pod and container a securityContext.", level="L2")

    def default_objects(d):
        return [f"{o.get('kind')} {o.get('name')}" for o in _list(d, "K8S_DEFAULT_NS")
                if not ((o.get("kind") == "Service" and o.get("name") == "kubernetes")
                        or (o.get("kind") == "ConfigMap" and o.get("name") == "kube-root-ca.crt"))]
    _rule(r, "5.7.4", "The default namespace should not be used", "low",
          lambda d: not default_objects(d) and not [p for p in _list(d, "K8S_PODS") if p.get("namespace") == "default"],
          lambda d: "Objects in default: " + _names(default_objects(d) + [
              f"Pod {p.get('name')}" for p in _list(d, "K8S_PODS") if p.get("namespace") == "default"]),
          "Move workloads to their own namespaces.", ["K8S_DEFAULT_NS", "K8S_PODS"], level="L2")


def build_rules(control_plane=True, etcd=True) -> List[BenchmarkRule]:
    r: List[BenchmarkRule] = []
    if control_plane:
        _control_plane_rules(r)
        if etcd:
            _etcd_rules(r)
        _control_plane_config_rules(r)
    _node_rules(r)
    _policy_rules(r)
    r.sort(key=lambda x: tuple(int(p) for p in x.section.split(".")))
    return r


def rules_for(dump: str) -> List[BenchmarkRule]:
    if section(dump, "NODE").strip() == NO_KUBERNETES:
        raise ValueError("Kubernetes is not installed on this host (no kubelet and no /etc/kubernetes).")
    n = node(dump)
    if not n:
        raise ValueError("The node information could not be read.")
    control_plane = n.get("control_plane") == "yes"
    return build_rules(control_plane=control_plane, etcd=control_plane and present(dump, "etcd"))


def all_rules() -> List[BenchmarkRule]:
    return build_rules()


def describe(dump: str) -> str:
    n = node(dump)
    role = "control-plane node" if n.get("control_plane") == "yes" else "worker node"
    return f"Kubernetes {n.get('kubelet_version')} {role} {n.get('hostname')}"
