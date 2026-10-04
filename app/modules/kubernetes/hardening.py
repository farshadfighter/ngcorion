"""
Kubernetes remediation (kubeadm layout).

- File ownership and modes (1.1.x, 4.1.x): only the permission bits the
  benchmark disallows are removed.
- Control plane flags (1.2.x, 1.3.x, 1.4.x): the static pod manifest is
  edited with python3 as text (no YAML library needed on the node), one
  `- --flag=value` line at a time; a copy of the manifest goes to
  /etc/kubernetes/ngcorion-backup first, outside the manifests directory so
  the kubelet never loads it. The kubelet then restarts the component.
- Kubelet settings (4.2.x): a top-level key of the kubelet config file is
  set, the kubelet restarted, and the previous file put back automatically
  if the kubelet does not come up again. Refused when the same setting is
  given as a kubelet flag (the flag would win).
- Default service accounts (5.1.5): automountServiceAccountToken: false,
  with the node's admin kubeconfig.

Flags that need certificates, an audit policy volume, an encryption
configuration or an admission configuration file, and every RBAC and pod
finding, come with guidance only.
"""

from app.modules.benchmark.templates import HardeningTemplate, ParamMeta, TemplateSet

from . import rules as R
from .collect import ADMIN_KUBECONFIG, FILE_GROUPS, KUBELET_CONFIG_PATH, MANIFESTS

TEMPLATES = TemplateSet()
TEMPLATES.param(ParamMeta(
    name="CONFIRM", input_type="select", label="Confirm the change",
    description="This change has side effects described in the check's warning. Choose 'yes' to apply it.",
    required=True, options=["yes"]))
TEMPLATES.param(ParamMeta(
    name="GC_THRESHOLD", input_type="number", label="Terminated pod GC threshold",
    description="How many terminated pods the cluster keeps before garbage collection (Kubernetes default 12500).",
    required=True, min_value=10, max_value=100000, placeholder="1000"))
TEMPLATES.param(ParamMeta(
    name="PIDS_LIMIT", input_type="number", label="Pod PIDs limit",
    description="Maximum number of processes per pod on this node.",
    required=True, min_value=64, max_value=4194304, placeholder="4096"))


def _add(sec, description, statements, verify, warning=None, params=(), restart=False):
    TEMPLATES.add(HardeningTemplate(
        check_id=f"K8S-{sec}", description=description, statements=statements, verify_statements=verify,
        parameters=list(params), warning=warning, requires_restart=restart))


# 1.1.x / 4.1.x files ────────────────────────────────────────────────────

def _file_fix(sec, tag, label, owner, mode):
    paths = FILE_GROUPS[tag]
    if owner:
        user = owner.split(":")[0]
        precheck = (f"id {user} >/dev/null 2>&1 || {{ echo 'there is no {user} user on this node: create it first "
                    f"(useradd -r -s /sbin/nologin {user})' >&2; exit 1; }}; " if user != "root" else "")
        _add(sec, f"Set the {label} ownership to {owner}",
             [precheck + f"for f in {paths}; do [ -e \"$f\" ] && chown {owner} \"$f\"; done; true"],
             [f"r=PASS; for f in {paths}; do [ -e \"$f\" ] || continue; "
              f"[ \"$(stat -c %U:%G \"$f\")\" = {owner} ] || r=FAIL; done; echo $r"])
    else:
        _add(sec, f"Set the {label} permissions to {mode:o} or more restrictive",
             [f"for f in {paths}; do [ -e \"$f\" ] || continue; m=$(stat -c %a \"$f\"); "
              f"chmod $(printf '%o' $(( 0$m & 0{mode:o} ))) \"$f\"; done; true"],
             [f"r=PASS; for f in {paths}; do [ -e \"$f\" ] || continue; m=$(stat -c %a \"$f\"); "
              f"[ $(( 0$m & ~0{mode:o} & 07777 )) -eq 0 ] || r=FAIL; done; echo $r"])


for _sec, _tag, _label, _owner, _mode in R.CONTROL_PLANE_FILES + R.NODE_FILES:
    _file_fix(_sec, _tag, _label, _owner, _mode)


# Control plane flags ────────────────────────────────────────────────────

MANIFEST_EDIT = r'''
import os, re, shutil, sys, time
path, binary, flag, op, value = sys.argv[1:6]
lines = open(path).read().split("\n")
idx = next((i for i, l in enumerate(lines) if re.match(r"^\s*- " + re.escape(binary) + r"\s*$", l)), None)
if idx is None:
    sys.exit("the command list of " + binary + " was not found in " + path)
indent = re.match(r"^(\s*)- ", lines[idx]).group(1)
j, found = idx + 1, None
while j < len(lines) and lines[j].startswith(indent + "- "):
    if re.match(r"^\s*- --" + re.escape(flag) + r"(=|\s*$)", lines[j]):
        found = j
    j += 1
current = lines[found].split("=", 1)[1].strip() if found is not None and "=" in lines[found] else ""
if op == "set":
    new = value
else:
    items = [x for x in current.split(",") if x]
    if op == "add" and value not in items:
        items.append(value)
    if op == "remove":
        items = [x for x in items if x != value]
    new = ",".join(items)
if found is not None and new == "":
    del lines[found]
elif found is not None:
    lines[found] = indent + "- --" + flag + "=" + new
elif new != "":
    lines.insert(j, indent + "- --" + flag + "=" + new)
backup = "/etc/kubernetes/ngcorion-backup"
os.makedirs(backup, mode=0o700, exist_ok=True)
name = os.path.basename(path)
if not os.path.exists(os.path.join(backup, name + ".orig")):
    shutil.copy2(path, os.path.join(backup, name + ".orig"))
shutil.copy2(path, os.path.join(backup, name + "." + time.strftime("%Y%m%d%H%M%S") + "-" + str(time.time_ns() % 10**9)))
tmp = os.path.join(backup, ".manifest.tmp")
with open(tmp, "w") as fh:
    fh.write("\n".join(lines))
os.chmod(tmp, os.stat(path).st_mode & 0o7777)
shutil.move(tmp, path)
'''

RESTARTS = ("The kubelet restarts {comp} with the new setting (about half a minute; on a single control-plane "
            "node the API is unavailable meanwhile). The original and each previous manifest are kept in "
            "/etc/kubernetes/ngcorion-backup.")


def manifest_edit(comp, flag, op, value) -> str:
    """Shell statement that edits one flag of a kubeadm static-pod manifest with an embedded Python
    script (set a value, add to or remove from a comma list); the kubelet restarts the component
    when the file changes. Flags and values are module constants or validated parameters.
    """
    path = MANIFESTS[comp]
    return (f"f={path}; [ -f $f ] || {{ echo \"$f not found: {comp} does not run as a kubeadm static pod on this node\" >&2; "
            "exit 1; }; command -v python3 >/dev/null 2>&1 || { echo 'python3 is needed to edit the manifest' >&2; exit 1; }; "
            f"python3 - $f {comp} {flag} {op} {value} <<'PY'\n{MANIFEST_EDIT.strip()}\nPY")


def manifest_check(comp, flag, op, value) -> str:
    """Verify statement for manifest_edit: prints PASS when the manifest carries the flag as asked.
    """
    path = MANIFESTS[comp]
    line = f"grep -E -- '^[[:space:]]*- --{flag}=' {path}"
    if op == "set":
        cond = f"{line} | grep -qE -- '={value}[[:space:]]*$'"
    elif op == "add":
        cond = f"{line} | grep -qE -- '[=,]{value}(,|[[:space:]]*$)'"
    else:
        cond = f"! {line} | grep -qE -- '[=,]{value}(,|[[:space:]]*$)'"
    return f"[ -f {path} ] || {{ echo FAIL; exit 0; }}; if {cond}; then echo PASS; else echo FAIL; fi"


def _flag(sec, comp, flag, op, value, description, warning=None, params=()):
    _add(sec, description, [manifest_edit(comp, flag, op, value)], [manifest_check(comp, flag, op, value)],
         warning=" ".join(x for x in (warning, RESTARTS.format(comp=comp)) if x), params=params)


A, C, S = "kube-apiserver", "kube-controller-manager", "kube-scheduler"
_flag("1.2.10", A, "enable-admission-plugins", "remove", "AlwaysAdmit", "Remove the AlwaysAdmit admission plugin")
_flag("1.2.11", A, "enable-admission-plugins", "add", "AlwaysPullImages", "Enable the AlwaysPullImages admission plugin",
      warning="Every pod start pulls its image again: pods using images that only exist on the node, or private "
              "images without pull secrets, stop starting; registry outages delay pod starts.", params=["CONFIRM"])
_flag("1.2.14", A, "enable-admission-plugins", "add", "NodeRestriction", "Enable the NodeRestriction admission plugin")
_flag("1.2.15", A, "profiling", "set", "false", "Turn API server profiling off")
_flag("1.2.17", A, "audit-log-maxage", "set", "30", "Keep API server audit logs for 30 days",
      warning="Takes effect once --audit-log-path is set.")
_flag("1.2.18", A, "audit-log-maxbackup", "set", "10", "Keep 10 rotated API server audit logs",
      warning="Takes effect once --audit-log-path is set.")
_flag("1.2.19", A, "audit-log-maxsize", "set", "100", "Rotate API server audit logs at 100 MB",
      warning="Takes effect once --audit-log-path is set.")
_flag("1.2.21", A, "service-account-lookup", "set", "true", "Validate service account tokens against etcd")
_flag("1.3.1", C, "terminated-pod-gc-threshold", "set", "{GC_THRESHOLD}", "Set the terminated pod garbage-collection threshold",
      params=["GC_THRESHOLD"])
_flag("1.3.2", C, "profiling", "set", "false", "Turn controller manager profiling off")
_flag("1.3.3", C, "use-service-account-credentials", "set", "true", "Run each controller with its own service account")
_flag("1.3.7", C, "bind-address", "set", "127.0.0.1", "Bind the controller manager to 127.0.0.1",
      warning="Metrics and health endpoints are then reachable only from the node itself (remote Prometheus scraping stops).",
      params=["CONFIRM"])
_flag("1.4.1", S, "profiling", "set", "false", "Turn scheduler profiling off")
_flag("1.4.2", S, "bind-address", "set", "127.0.0.1", "Bind the scheduler to 127.0.0.1",
      warning="Metrics and health endpoints are then reachable only from the node itself (remote Prometheus scraping stops).",
      params=["CONFIRM"])


# Kubelet settings ───────────────────────────────────────────────────────

KUBELET_EDIT = r'''
import os, re, shutil, sys
path, key, value = sys.argv[1:4]
lines = open(path).read().split("\n")
pattern = re.compile(r"^" + re.escape(key) + r":")
for i, line in enumerate(lines):
    if pattern.match(line):
        lines[i] = key + ": " + value
        break
else:
    lines.insert(len(lines) - (1 if lines and lines[-1] == "" else 0), key + ": " + value)
if not os.path.exists(path + ".ngcorion-orig"):
    shutil.copy2(path, path + ".ngcorion-orig")
shutil.copy2(path, path + ".ngcorion-prev")
with open(path + ".ngcorion-new", "w") as fh:
    fh.write("\n".join(lines))
os.chmod(path + ".ngcorion-new", os.stat(path).st_mode & 0o7777)
os.replace(path + ".ngcorion-new", path)
'''

KUBELET_RESTART = (
    "systemctl restart kubelet; sleep 10; "
    "if ! systemctl is-active --quiet kubelet; then cp -p \"$f.ngcorion-prev\" \"$f\"; systemctl restart kubelet; "
    "echo 'the kubelet did not come back with the new setting; the previous configuration was restored' >&2; exit 1; fi"
)


def kubelet_edit(key, value, flag) -> str:
    """Shell statement that sets one key of the kubelet config file and restarts the kubelet; refused
    when the same setting is given as a command-line flag (the flag would win).
    """
    return (f"f={KUBELET_CONFIG_PATH}; [ -f \"$f\" ] || {{ echo \"kubelet config file $f not found\" >&2; exit 1; }}; "
            "ps -eo args= | grep -E '^(\\S*/)?kubelet( |$)' | grep -qE -- "
            f"'--{flag}([= ]|$)' && {{ echo '--{flag} is set on the kubelet command line and would override the config "
            "file; change it in the kubelet flags (kubeadm-flags.env) instead' >&2; exit 1; }; "
            "command -v python3 >/dev/null 2>&1 || { echo 'python3 is needed to edit the kubelet config' >&2; exit 1; }; "
            f"python3 - \"$f\" {key} {value} <<'PY'\n{KUBELET_EDIT.strip()}\nPY\n" + KUBELET_RESTART)


def kubelet_check(key, value) -> str:
    return (f"f={KUBELET_CONFIG_PATH}; if grep -qE '^{key}:[[:space:]]*\"?{value}\"?[[:space:]]*$' \"$f\" "
            "&& systemctl is-active --quiet kubelet; then echo PASS; else echo FAIL; fi")


KUBELET_WARNING = "The kubelet restarts (running pods are not affected); it is put back if it does not start."


def _kubelet(sec, key, value, flag, description, params=()):
    _add(sec, description, [kubelet_edit(key, value, flag)], [kubelet_check(key, value)], warning=KUBELET_WARNING,
         params=params)


_kubelet("4.2.4", "readOnlyPort", "0", "read-only-port", "Close the kubelet read-only port")
_kubelet("4.2.5", "streamingConnectionIdleTimeout", "4h0m0s", "streaming-connection-idle-timeout",
         "Time out idle streaming connections after 4 hours")
_kubelet("4.2.6", "makeIPTablesUtilChains", "true", "make-iptables-util-chains", "Let the kubelet manage its iptables chains")
_kubelet("4.2.10", "rotateCertificates", "true", "rotate-certificates", "Rotate the kubelet client certificate")
_kubelet("4.2.13", "podPidsLimit", "{PIDS_LIMIT}", "pod-max-pids", "Limit the number of processes per pod",
         params=["PIDS_LIMIT"])


# 5.1.5 default service accounts ─────────────────────────────────────────

_KC = f"kubectl --kubeconfig {ADMIN_KUBECONFIG}"
_add("5.1.5", "Stop mounting tokens of the default service accounts",
     # A kubectl failure must fail the fix and its verification: an empty
     # namespace list or empty output is never read as "nothing to do".
     [f"[ -f {ADMIN_KUBECONFIG} ] || {{ echo 'no admin kubeconfig on this node' >&2; exit 1; }}; "
      f"nss=$({_KC} get ns -o jsonpath='{{.items[*].metadata.name}}' 2>&1) || "
      "{ echo \"kubectl failed: $nss\" | head -1 >&2; exit 1; }; "
      "[ -n \"$nss\" ] || { echo 'kubectl returned no namespaces' >&2; exit 1; }; "
      f"for ns in $nss; do "
      f"{_KC} -n \"$ns\" patch serviceaccount default -p '{{\"automountServiceAccountToken\": false}}' >/dev/null || exit 1; done"],
     [f"out=$({_KC} get serviceaccounts -A -o jsonpath='{{range .items[?(@.metadata.name==\"default\")]}}"
      "{.automountServiceAccountToken}{\"\\n\"}{end}' 2>/dev/null) || { echo FAIL; exit 0; }; "
      "[ -n \"$out\" ] || { echo FAIL; exit 0; }; "
      "echo \"$out\" | grep -qvx false && echo FAIL || echo PASS"],
     warning="Pods that use the default service account and call the Kubernetes API lose their token when they are "
             "next recreated; give those workloads their own service account first.", params=["CONFIRM"])


# Guidance only ──────────────────────────────────────────────────────────

_GUIDANCE = {
    "1.2.1": "Set --anonymous-auth=false; kubeadm's liveness probes call the API anonymously, so give them credentials "
             "or switch them to the authenticated port first.",
    "1.2.3": "Add DenyServiceExternalIPs to --enable-admission-plugins.",
    "1.2.5": "Sign the kubelet serving certificates with a CA and set --kubelet-certificate-authority.",
    "1.2.9": "Write an EventRateLimit admission configuration and pass it with --admission-control-config-file.",
    "1.2.16": "Mount a hostPath for the audit log directory into the API server pod and set --audit-log-path.",
    "1.2.27": "Create an EncryptionConfiguration (aescbc or kms), mount it and set --encryption-provider-config.",
    "1.2.28": "Put aescbc, secretbox or kms first in the EncryptionConfiguration, then re-encrypt secrets.",
    "1.2.29": "Set --tls-cipher-suites to ECDHE suites with AES-GCM or ChaCha20.",
    "2.3": "Give etcd real certificates and remove --auto-tls.",
    "2.6": "Give etcd real peer certificates and remove --peer-auto-tls.",
    "3.2.1": "Write an audit policy, mount it and set --audit-policy-file.",
    "4.2.1": "Set authentication.anonymous.enabled: false in the kubelet config and restart the kubelet.",
    "4.2.2": "Set authorization.mode: Webhook in the kubelet config and restart the kubelet.",
    "4.2.3": "Set authentication.x509.clientCAFile in the kubelet config and restart the kubelet.",
    "4.2.9": "Set serverTLSBootstrap: true (and approve the CSRs) or give the kubelet tlsCertFile/tlsPrivateKeyFile.",
    "4.2.12": "Set tlsCipherSuites in the kubelet config to ECDHE suites with AES-GCM or ChaCha20.",
    "4.3.1": "Set metricsBindAddress: 127.0.0.1:10249 in the kube-proxy ConfigMap and restart the kube-proxy pods.",
    "5.2.1": "Label namespaces with pod-security.kubernetes.io/enforce=baseline (or restricted), starting with warn/audit.",
    "5.3.2": "Add a default-deny NetworkPolicy per namespace, then allow the traffic each workload needs.",
}
for _r in R.all_rules():
    if _r.id not in TEMPLATES.templates:
        TEMPLATES.manual(_r.id, _GUIDANCE.get(_r.section, _r.remediation))
