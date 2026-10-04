"""
Kubernetes test data.

NODE: the node sections captured from a real kubeadm v1.32.2 control-plane
node (kind, tests/mock_data/kubernetes/kind_v1_32_control_plane_dump.txt).
The API server could not start in that environment, so the capture's
cluster sections are kubectl connection errors.

CLUSTER: built here, not captured - kubectl JSON for a small cluster: a
"shop" namespace enforcing the baseline Pod Security Standard with a
NetworkPolicy and a well-configured pod, a "monitoring" namespace with a
node-exporter (hostPID, hostNetwork, hostPath), a privileged debug pod in
"default" that reads a Secret into its environment, a CI role with
wildcards and secret access, and cluster-admin bound to a user. Values that
must never be stored (environment values, annotations) are included so the
tests can check they are dropped.
"""
import copy
import json
from pathlib import Path

from app.modules.benchmark.rules import section

NODE_DUMP = (Path(__file__).parent / "mock_data" / "kubernetes" / "kind_v1_32_control_plane_dump.txt").read_text()
NODE_SECTIONS = ("OS_RELEASE", "NODE", "PROCS", "MANIFESTS", "KUBELET_CONFIG", "FILES", "AUDIT_POLICY",
                 "ENCRYPTION", "CNI")


def _list(*items):
    return {"apiVersion": "v1", "kind": "List", "items": list(items)}


def _meta(name, ns=None, labels=None, annotations=None):
    m = {"name": name, "uid": "u-" + name, "creationTimestamp": "2026-09-01T00:00:00Z"}
    if ns:
        m["namespace"] = ns
    if labels:
        m["labels"] = labels
    if annotations:
        m["annotations"] = annotations
    return m


BOOT = {"kubernetes.io/bootstrapping": "rbac-defaults"}

RBAC = _list(
    {"kind": "ClusterRole", "metadata": _meta("cluster-admin", labels=BOOT),
     "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]},
    {"kind": "ClusterRole", "metadata": _meta("system:node", labels=BOOT),
     "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]},
    {"kind": "ClusterRole", "metadata": _meta("admin", labels=BOOT), "aggregationRule": {"clusterRoleSelectors": []},
     "rules": [{"apiGroups": [""], "resources": ["secrets", "pods"], "verbs": ["*"]}]},
    {"kind": "ClusterRole", "metadata": _meta("ci-deployer"),
     "rules": [{"apiGroups": ["", "apps"], "resources": ["*"], "verbs": ["get", "list", "create", "update"]},
               {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}]},
    {"kind": "ClusterRole", "metadata": _meta("node-metrics"),
     "rules": [{"apiGroups": [""], "resources": ["nodes/proxy", "nodes/metrics"], "verbs": ["get"]}]},
    {"kind": "Role", "metadata": _meta("shop-reader", "shop"),
     "rules": [{"apiGroups": [""], "resources": ["pods", "services"], "verbs": ["get", "list", "watch"]}]},
    {"kind": "ClusterRoleBinding", "metadata": _meta("cluster-admin", labels=BOOT),
     "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
     "subjects": [{"kind": "Group", "name": "system:masters"}]},
    {"kind": "ClusterRoleBinding", "metadata": _meta("kubeadm:cluster-admins"),
     "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
     "subjects": [{"kind": "Group", "name": "kubeadm:cluster-admins"}]},
    {"kind": "ClusterRoleBinding", "metadata": _meta("alice-admin"),
     "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
     "subjects": [{"kind": "User", "name": "alice@corp.example.com"}]},
    {"kind": "RoleBinding", "metadata": _meta("shop-readers", "shop"),
     "roleRef": {"kind": "Role", "name": "shop-reader"},
     "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "shop"}]},
)

NAMESPACES = _list(*[
    {"kind": "Namespace", "metadata": _meta(n, labels=dict({"kubernetes.io/metadata.name": n}, **labels))}
    for n, labels in (("default", {}), ("kube-system", {}), ("kube-public", {}), ("kube-node-lease", {}),
                      ("shop", {"pod-security.kubernetes.io/enforce": "baseline", "team": "web"}),
                      ("monitoring", {}))
])

SERVICEACCOUNTS = _list(
    {"kind": "ServiceAccount", "metadata": _meta("default", "default")},
    {"kind": "ServiceAccount", "metadata": _meta("default", "kube-system")},
    {"kind": "ServiceAccount", "metadata": _meta("default", "shop"), "automountServiceAccountToken": False},
    {"kind": "ServiceAccount", "metadata": _meta("default", "monitoring")},
    {"kind": "ServiceAccount", "metadata": _meta("web", "shop"), "automountServiceAccountToken": False},
)

NETPOL = _list({"kind": "NetworkPolicy", "metadata": _meta("default-deny", "shop"), "spec": {"podSelector": {}}})
WEBHOOKS = _list()


def _pod(name, ns, spec, annotations=None):
    return {"kind": "Pod", "metadata": dict(_meta(name, ns, annotations=annotations),
                                            ownerReferences=[{"kind": "ReplicaSet", "name": name + "-rs"}]),
            "spec": spec, "status": {"phase": "Running"}}


GOOD_SC = {"allowPrivilegeEscalation": False, "runAsNonRoot": True, "runAsUser": 10001,
           "capabilities": {"drop": ["ALL"]}, "readOnlyRootFilesystem": True}

PODS = _list(
    _pod("kube-apiserver-cp1", "kube-system", {"hostNetwork": True, "containers": [
        {"name": "kube-apiserver", "image": "registry.k8s.io/kube-apiserver:v1.32.2"}]}),
    _pod("web-7d9", "shop", {
        "serviceAccountName": "web", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "web", "image": "registry.corp/shop/web:2.4.1", "securityContext": GOOD_SC,
                        "ports": [{"containerPort": 8080}],
                        "env": [{"name": "LOG_LEVEL", "value": "info"}]}],
        "volumes": [{"name": "tls", "secret": {"secretName": "web-tls"}}]}),
    _pod("node-exporter-x2k", "monitoring", {
        "hostPID": True, "hostNetwork": True,
        "containers": [{"name": "node-exporter", "image": "quay.io/prometheus/node-exporter:v1.8.2",
                        "securityContext": {"readOnlyRootFilesystem": True},
                        "ports": [{"containerPort": 9100, "hostPort": 9100}]}],
        "volumes": [{"name": "proc", "hostPath": {"path": "/proc"}}, {"name": "sys", "hostPath": {"path": "/sys"}}]}),
    _pod("debug", "default", {
        "containers": [{"name": "shell", "image": "ubuntu:24.04",
                        "securityContext": {"privileged": True, "capabilities": {"add": ["NET_ADMIN", "SYS_ADMIN"]}},
                        "env": [{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "password"}}},
                                {"name": "API_TOKEN", "value": "tok-9f8e7d6c5b4a"}],
                        "envFrom": [{"secretRef": {"name": "legacy-creds"}}]}]},
        annotations={"kubectl.kubernetes.io/last-applied-configuration": '{"secret":"hunter2"}'}),
)

DEFAULT_NS = _list(
    {"kind": "Service", "metadata": _meta("kubernetes", "default")},
    {"kind": "ConfigMap", "metadata": _meta("kube-root-ca.crt", "default")},
    {"kind": "Deployment", "metadata": _meta("debug", "default")},
)

PROXY_CONFIG = ("apiVersion: kubeproxy.config.k8s.io/v1alpha1\nkind: KubeProxyConfiguration\n"
                "clusterCIDR: 10.244.0.0/16\nmetricsBindAddress: 0.0.0.0:10249\nmode: iptables\n")

CLUSTER = {
    "K8S_RBAC": RBAC, "K8S_NAMESPACES": NAMESPACES, "K8S_SERVICEACCOUNTS": SERVICEACCOUNTS, "K8S_NETPOL": NETPOL,
    "K8S_WEBHOOKS": WEBHOOKS, "K8S_PODS": PODS, "K8S_DEFAULT_NS": DEFAULT_NS, "K8S_PROXY_CONFIG": PROXY_CONFIG,
}


def sections(**changes):
    """What the commands print on the node: real node sections, built cluster JSON."""
    out = {name: section(NODE_DUMP, name) for name in NODE_SECTIONS}
    cluster = copy.deepcopy(CLUSTER)
    cluster.update(changes)
    for name, value in cluster.items():
        out[name] = value if isinstance(value, str) else json.dumps(value)
    return out


def dump(**changes):
    """A stored dump: collected through the module's collect() on a simulated host."""
    from app.modules.kubernetes.collect import collect, kubernetes_commands
    data = sections(**changes)
    by_script = {script: name for name, script in kubernetes_commands().items()}

    class _Conn:
        def run(self, script):
            return data.get(by_script.get(script), "(no output)")
    return collect(_Conn())
