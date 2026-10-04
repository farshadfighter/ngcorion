"""
Docker host rules after the CIS Docker Benchmark: 1 host configuration,
2 Docker daemon configuration, 3 daemon configuration files, 4 container
images and build files, 5 container runtime, 6 security operations.

Numbering follows the benchmark's v1.6/v1.7 layout (swarm checks folded
into 5.1); it was written from the benchmark's content rather than copied
from a specific edition, so item numbers can differ slightly from the
edition in use. Runtime checks (section 5) look at the running containers;
with none running they pass. A daemon setting is read from daemon.json and
the dockerd command line, and from `docker info` where Docker reports the
effective value.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from app.modules.benchmark.rules import BenchmarkRule, json_section, parse_json, section

from .collect import NO_DOCKER, SHELL_PATHS

JSON_SECTIONS = frozenset({"DOCKER_VERSION", "DOCKER_INFO", "DAEMON_JSON", "CONTAINERS", "IMAGES"})

# Docker's default capability set: anything added beyond it needs a reason.
DEFAULT_CAPS = {"CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID", "SETUID",
                "SETFCAP", "SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE"}
SENSITIVE_DIRS = ("/boot", "/dev", "/etc", "/lib", "/proc", "/sys", "/usr")
LOCAL_LOG_DRIVERS = ("json-file", "local", "none", "")


# ── data access ──────────────────────────────────────────────────────────

def _dict(d, name) -> Dict[str, Any]:
    v = json_section(d, name)
    return v if isinstance(v, dict) else {}


def info(d):
    return _dict(d, "DOCKER_INFO")


def version(d):
    return _dict(d, "DOCKER_VERSION")


def daemon(d):
    return _dict(d, "DAEMON_JSON")


def containers(d) -> List[Dict[str, Any]]:
    v = json_section(d, "CONTAINERS")
    return [c for c in v if isinstance(c, dict)] if isinstance(v, list) else []


def images(d) -> List[Dict[str, Any]]:
    v = json_section(d, "IMAGES")
    return [i for i in v if isinstance(i, dict)] if isinstance(v, list) else []


def dockerd_args(d) -> List[str]:
    text = section(d, "DOCKERD_ARGS").strip()
    if not text or text == "NONE":
        return []
    return text.splitlines()[0].split()


def flag(d, name) -> List[str]:
    """Values given for --name on the dockerd command line ("" for a bare flag)."""
    args, out = dockerd_args(d), []
    for i, a in enumerate(args):
        if a == f"--{name}":
            nxt = args[i + 1] if i + 1 < len(args) else ""
            out.append("" if nxt.startswith("-") else nxt)
        elif a.startswith(f"--{name}="):
            out.append(a.split("=", 1)[1])
    return out


def setting(d, key, flag_name=None):
    """daemon.json value, else the command-line value, else None."""
    cfg = daemon(d)
    if key in cfg:
        return cfg[key]
    values = flag(d, flag_name or key)
    if not values:
        return None
    v = values[-1]
    return {"": True, "true": True, "false": False}.get(v.lower(), v)


def bool_setting(d, key, flag_name=None) -> Optional[bool]:
    v = setting(d, key, flag_name)
    if v is None:
        return None
    return v if isinstance(v, bool) else str(v).lower() == "true"


def files(d) -> Dict[str, List[Tuple[str, str, str, str, str]]]:
    out: Dict[str, List[Tuple[str, str, str, str, str]]] = {}
    for line in section(d, "FILES").splitlines():
        parts = line.split("|")
        if len(parts) == 6:
            out.setdefault(parts[0], []).append(tuple(parts[1:]))
    return out


def audit_paths(d) -> Dict[str, Tuple[str, bool]]:
    out = {}
    for line in section(d, "AUDIT_PATHS").splitlines():
        parts = line.split("|")
        if len(parts) == 3:
            out[parts[0]] = (parts[1], parts[2] == "1")
    return out


def host(d) -> Dict[str, str]:
    out = {}
    for line in section(d, "HOST").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def procs(d) -> Dict[str, List[str]]:
    out, cur = {}, None
    for line in section(d, "CONTAINER_PROCS").splitlines():
        if line.startswith("### "):
            cur = line[4:].strip()
            out[cur] = []
        elif cur and line.strip():
            out[cur].append(line.strip())
    return out


def history(d) -> Dict[str, List[str]]:
    out, cur = {}, None
    for line in section(d, "IMAGE_HISTORY").splitlines():
        if line.startswith("### "):
            cur = line[4:].strip()
            out[cur] = []
        elif cur and line.strip():
            out[cur].append(line.strip())
    return out


def networks(d) -> Dict[str, Dict[str, Any]]:
    out = {}
    for line in section(d, "NETWORKS").splitlines():
        n = parse_json(line)
        if isinstance(n, dict) and n.get("Name"):
            out[n["Name"]] = n
    return out


def security_options(d) -> List[str]:
    return [str(o) for o in (info(d).get("SecurityOptions") or [])]


def _sec(d, name) -> bool:
    return any(o.startswith(f"name={name}") for o in security_options(d))


def name_of(c) -> str:
    return str(c.get("Name") or c.get("Id", "")[:12]).lstrip("/")


def _names(items, limit=15) -> str:
    items = list(items)
    if not items:
        return "none"
    return ", ".join(str(i) for i in items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def _mode_ok(mode: str, maximum: int) -> bool:
    try:
        return int(mode, 8) & ~maximum & 0o7777 == 0
    except ValueError:
        return False


def image_label(d, image_id: str) -> str:
    for i in images(d):
        if str(i.get("Id", "")).replace("sha256:", "").startswith(image_id):
            tags = i.get("Tags") or []
            return tags[0] if tags else image_id
    return image_id


# ── rule builders ────────────────────────────────────────────────────────

def _rule(rules, sec, title, severity, check, evidence, remediation, sections, level="L1", manual=False,
          unavailable=None):
    rules.append(BenchmarkRule(
        id=f"DKR-{sec}", section=sec, title=title, severity=severity, level=level,
        check_fn=check, evidence_fn=evidence, remediation=remediation, description=title,
        manual=manual, data_sections=list(sections), source="CIS", unavailable_fn=unavailable))


def _manual(rules, sec, title, severity, guidance, evidence=None, level="L1", sections=()):
    _rule(rules, sec, title, severity, lambda d: False,
          evidence or (lambda d: "Review on the host."), guidance, sections, level=level, manual=True)


def _per_container(rules, sec, title, severity, bad, describe, remediation, level="L1", sections=("CONTAINERS",)):
    """A runtime check every running container must pass."""
    def offenders(d):
        return [c for c in containers(d) if bad(c, d)]
    _rule(rules, sec, title, severity, lambda d: not offenders(d),
          lambda d: (f"{len(containers(d))} running containers; not compliant: "
                     + _names(f"{name_of(c)} ({describe(c, d)})" for c in offenders(d))),
          remediation, sections, level=level)


def _audit_rule(rules, sec, tag, label):
    def state(d):
        path, exists = audit_paths(d).get(tag, ("", False))
        return path, exists

    def watched(d, path):
        text = section(d, "AUDIT_RULES")
        return bool(re.search(r"(-w |path=|dir=)" + re.escape(path.rstrip("/")) + r"/?( |$)", text, re.M))

    def check(d):
        path, exists = state(d)
        if not exists:
            return True
        return section(d, "AUDIT_RULES").strip() != "NO_AUDITCTL" and watched(d, path)

    def evidence(d):
        path, exists = state(d)
        if not exists:
            return f"{path or label}: not present on this host (nothing to audit)"
        if section(d, "AUDIT_RULES").strip() == "NO_AUDITCTL":
            return f"{path}: auditd is not installed (auditctl not found)"
        return f"{path}: audit watch {'present' if watched(d, path) else 'missing'}"

    _rule(rules, sec, f"Ensure auditing is configured for Docker files and directories - {label}", "low",
          check, evidence, f"Add '-w {label} -k docker' to /etc/audit/rules.d/docker.rules and load it (augenrules --load).",
          ["AUDIT_RULES", "AUDIT_PATHS"])


def _file_rule(rules, sec, tag, label, owner=None, group=None, mode=None, severity="medium"):
    def bad_entries(d):
        out = []
        for path, o, g, m, kind in files(d).get(tag, []):
            if kind == "missing":
                continue
            if owner and (o != owner or g != group):
                out.append(f"{path} ({o}:{g})")
            if mode is not None and not _mode_ok(m, mode):
                out.append(f"{path} ({m})")
        return out

    def present(d):
        return [p for p, *_rest, kind in files(d).get(tag, []) if kind != "missing"]

    if owner:
        title = f"Ensure that the {label} ownership is set to {owner}:{group}"
        remediation = f"chown {owner}:{group} {label}"
    else:
        title = f"Ensure that {label} permissions are set to {mode:o} or more restrictive"
        remediation = f"chmod {mode:o} {label}"
    _rule(rules, sec, title, severity, lambda d: not bad_entries(d),
          lambda d: (f"Not compliant: {_names(bad_entries(d))}" if bad_entries(d)
                     else f"Compliant: {_names(present(d))}" if present(d) else f"{label}: not present on this host"),
          remediation, ["FILES"])


# ── the benchmark ────────────────────────────────────────────────────────

AUDITED = (
    ("1.1.3", "dockerd", "/usr/bin/dockerd"), ("1.1.4", "run_containerd", "/run/containerd"),
    ("1.1.5", "docker_root", "/var/lib/docker"), ("1.1.6", "etc_docker", "/etc/docker"),
    ("1.1.7", "docker_service", "docker.service"), ("1.1.8", "containerd_sock", "containerd.sock"),
    ("1.1.9", "docker_socket", "docker.socket"), ("1.1.10", "default_docker", "/etc/default/docker"),
    ("1.1.11", "daemon_json", "/etc/docker/daemon.json"), ("1.1.12", "containerd_config", "/etc/containerd/config.toml"),
    ("1.1.13", "sysconfig_docker", "/etc/sysconfig/docker"), ("1.1.14", "containerd", "/usr/bin/containerd"),
    ("1.1.15", "containerd_shim", "/usr/bin/containerd-shim"),
    ("1.1.16", "shim_runc_v1", "/usr/bin/containerd-shim-runc-v1"),
    ("1.1.17", "shim_runc_v2", "/usr/bin/containerd-shim-runc-v2"), ("1.1.18", "runc", "/usr/bin/runc"),
)
assert {tag for _s, tag, _l in AUDITED} == set(SHELL_PATHS)

FILE_RULES = (
    ("3.1", "docker_service", "docker.service file", "root", "root", None, "medium"),
    ("3.2", "docker_service", "docker.service file", None, None, 0o644, "medium"),
    ("3.3", "docker_socket", "docker.socket file", "root", "root", None, "medium"),
    ("3.4", "docker_socket", "docker.socket file", None, None, 0o644, "medium"),
    ("3.5", "etc_docker", "/etc/docker directory", "root", "root", None, "medium"),
    ("3.6", "etc_docker", "/etc/docker directory", None, None, 0o755, "medium"),
    ("3.7", "registry_cert", "registry certificate file", "root", "root", None, "medium"),
    ("3.8", "registry_cert", "registry certificate file", None, None, 0o444, "medium"),
    ("3.9", "tlscacert", "TLS CA certificate file", "root", "root", None, "medium"),
    ("3.10", "tlscacert", "TLS CA certificate file", None, None, 0o444, "medium"),
    ("3.11", "tlscert", "Docker server certificate file", "root", "root", None, "medium"),
    ("3.12", "tlscert", "Docker server certificate file", None, None, 0o444, "medium"),
    ("3.13", "tlskey", "Docker server certificate key file", "root", "root", None, "high"),
    ("3.14", "tlskey", "Docker server certificate key file", None, None, 0o400, "high"),
    ("3.15", "docker_sock", "Docker socket file", "root", "docker", None, "high"),
    ("3.16", "docker_sock", "Docker socket file", None, None, 0o660, "high"),
    ("3.17", "daemon_json", "daemon.json file", "root", "root", None, "medium"),
    ("3.18", "daemon_json", "daemon.json file", None, None, 0o644, "medium"),
    ("3.19", "default_docker", "/etc/default/docker file", "root", "root", None, "medium"),
    ("3.20", "default_docker", "/etc/default/docker file", None, None, 0o644, "medium"),
    ("3.21", "sysconfig_docker", "/etc/sysconfig/docker file", "root", "root", None, "medium"),
    ("3.22", "sysconfig_docker", "/etc/sysconfig/docker file", None, None, 0o644, "medium"),
    ("3.23", "containerd_sock", "Containerd socket file", "root", "root", None, "high"),
    ("3.24", "containerd_sock", "Containerd socket file", None, None, 0o660, "high"),
)


def _icc_effective(d) -> Optional[str]:
    bridge = networks(d).get("bridge")
    return None if bridge is None else str((bridge.get("Options") or {}).get("com.docker.network.bridge.enable_icc"))


def _insecure(d) -> List[str]:
    reg = info(d).get("RegistryConfig") or {}
    out = [c for c in (reg.get("InsecureRegistryCIDRs") or []) if c not in ("127.0.0.0/8", "::1/128")]
    out += [n for n, v in (reg.get("IndexConfigs") or {}).items()
            if isinstance(v, dict) and v.get("Secure") is False and n not in out]
    return out


def _tcp_hosts(d) -> List[str]:
    hosts = daemon(d).get("hosts") or []
    hosts = hosts if isinstance(hosts, list) else [hosts]
    args = dockerd_args(d)
    hosts += flag(d, "host")
    hosts += [args[i + 1] for i, a in enumerate(args) if a == "-H" and i + 1 < len(args)]
    hosts += [a[2:].lstrip("=") for a in args if a.startswith("-H") and len(a) > 2]
    return [h for h in hosts if str(h).startswith("tcp://")]


def _tls_ok(d) -> bool:
    if not _tcp_hosts(d):
        return True
    return bool(bool_setting(d, "tlsverify") and setting(d, "tlscacert") and setting(d, "tlscert")
                and setting(d, "tlskey"))


def _ports(c) -> List[Tuple[str, str, str]]:
    """(container port, host ip, host port) for each published binding."""
    out = []
    for cport, bindings in (c.get("Ports") or {}).items():
        for b in bindings or []:
            out.append((cport, str(b.get("HostIp") or ""), str(b.get("HostPort") or "")))
    return out


def _sensitive_mounts(c) -> List[str]:
    out = []
    for m in c.get("Mounts") or []:
        src = str(m.get("Source") or "").rstrip("/") or "/"
        if m.get("Type") not in (None, "bind"):
            continue
        if src == "/" or any(src == s or src.startswith(s + "/") for s in SENSITIVE_DIRS):
            out.append(f"{src}{'' if m.get('RW') is False else ' rw'}")
    return out


def _secopts(c) -> List[str]:
    return [str(o) for o in ((c.get("HostConfig") or {}).get("SecurityOpt") or [])]


def _hc(c):
    return c.get("HostConfig") or {}


def _added_caps(c) -> List[str]:
    caps = [str(x).upper().replace("CAP_", "") for x in (_hc(c).get("CapAdd") or [])]
    return [x for x in caps if x == "ALL" or x not in DEFAULT_CAPS]


def _restart_ok(c) -> bool:
    rp = _hc(c).get("RestartPolicy") or {}
    name = rp.get("Name") or "no"
    return name == "no" or (name == "on-failure" and 0 < int(rp.get("MaximumRetryCount") or 0) <= 5)


def _update_alone(lines: List[str]) -> bool:
    return any(re.search(r"\b(apt-get|apt|yum|dnf|apk|zypper)\s+update\b", ln) and not re.search(
        r"\b(install|upgrade|add)\b", ln) for ln in lines)


def _uses_add(lines: List[str]) -> bool:
    for ln in lines:
        m = re.match(r"^(?:/bin/sh -c #\(nop\)\s+)?ADD\s+(\S+)", ln)
        # A base image's root filesystem ("ADD file:<hash> in /", "ADD rootfs.tar.xz /") is not a build choice.
        if m and not re.match(r"^(file:[0-9a-f]+|[\w.-]*rootfs[\w.-]*\.tar(\.\w+)?)$", m.group(1)):
            return True
    return False


SECRET_IN_HISTORY = re.compile(r"\b[A-Z0-9_]*(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*=", re.I)


def build_rules() -> List[BenchmarkRule]:
    r: List[BenchmarkRule] = []
    C = ["CONTAINERS"]

    # 1 Host configuration ────────────────────────────────────────────────
    _rule(r, "1.1.1", "Ensure a separate partition for containers has been created", "medium",
          lambda d: (host(d).get("root") or "").split("|")[1:2] == ["separate"],
          lambda d: "Docker root: " + (host(d).get("root") or "unknown").replace("|", " · "),
          "Mount the Docker root directory (DockerRootDir) on its own partition or logical volume.", ["HOST"])
    _manual(r, "1.1.2", "Ensure only trusted users are allowed to control Docker daemon", "high",
            "Members of the docker group have root-equivalent access; keep only administrators in it (gpasswd -d <user> docker).",
            lambda d: "docker group: " + (host(d).get("group") or "unknown"), sections=["HOST"])
    for sec, tag, label in AUDITED:
        _audit_rule(r, sec, tag, label)
    _manual(r, "1.2.1", "Ensure the container host has been Hardened", "medium",
            "Harden the host OS (CIS Linux benchmark); run the Linux audit on this host.",
            lambda d: section(d, "OS_RELEASE").splitlines()[0] if section(d, "OS_RELEASE") else "", sections=["OS_RELEASE"])
    _manual(r, "1.2.2", "Ensure that the version of Docker is up to date", "medium",
            "Compare with the current Docker Engine release and the CVE findings for this asset.",
            lambda d: f"Docker Engine {(version(d).get('Server') or {}).get('Version')}", sections=["DOCKER_VERSION"])

    # 2 Docker daemon configuration ───────────────────────────────────────
    _manual(r, "2.1", "Run the Docker daemon as a non-root user, if possible", "medium",
            "Consider rootless mode (dockerd-rootless-setuptool.sh install) where its limitations are acceptable.",
            lambda d: f"rootless = {_sec(d, 'rootless')}", level="L2", sections=["DOCKER_INFO"])
    _rule(r, "2.2", "Ensure network traffic is restricted between containers on the default bridge", "medium",
          lambda d: _icc_effective(d) in (None, "false"),
          lambda d: (f"default bridge enable_icc = {_icc_effective(d)}; configured icc = {setting(d, 'icc')}"
                     + (" (configured, not yet in effect: the default bridge keeps its setting until Docker "
                        "restarts with no container attached to it)"
                        if bool_setting(d, "icc") is False and _icc_effective(d) == "true" else "")),
          "Set \"icc\": false in /etc/docker/daemon.json and restart Docker.", ["NETWORKS", "DAEMON_JSON"])
    _rule(r, "2.3", "Ensure the logging level is set to 'info'", "low",
          lambda d: str(setting(d, "log-level") or "info").lower() == "info" and not info(d).get("Debug"),
          lambda d: f"log-level = {setting(d, 'log-level') or 'info (default)'}, debug = {info(d).get('Debug')}",
          "Set \"log-level\": \"info\" in daemon.json (or remove it).", ["DAEMON_JSON", "DOCKER_INFO"])
    _rule(r, "2.4", "Ensure Docker is allowed to make changes to iptables", "medium",
          lambda d: bool_setting(d, "iptables") is not False,
          lambda d: f"iptables = {setting(d, 'iptables') if setting(d, 'iptables') is not None else 'true (default)'}",
          "Remove \"iptables\": false (and --iptables=false) so Docker manages its firewall rules.", ["DAEMON_JSON"])
    _rule(r, "2.5", "Ensure insecure registries are not used", "high",
          lambda d: not _insecure(d) and not daemon(d).get("insecure-registries"),
          lambda d: f"insecure registries: {_names(_insecure(d) or daemon(d).get('insecure-registries') or [])}",
          "Remove insecure-registries; give each registry a trusted TLS certificate.", ["DOCKER_INFO", "DAEMON_JSON"])
    _rule(r, "2.6", "Ensure aufs storage driver is not used", "medium",
          lambda d: info(d).get("Driver") != "aufs", lambda d: f"storage driver = {info(d).get('Driver')}",
          "Move to overlay2 (or the containerd snapshotter).", ["DOCKER_INFO"])
    _rule(r, "2.7", "Ensure TLS authentication for Docker daemon is configured", "high", _tls_ok,
          lambda d: (f"TCP listeners: {_names(_tcp_hosts(d))}; tlsverify = {setting(d, 'tlsverify')}"
                     if _tcp_hosts(d) else "The daemon listens on the local socket only"),
          "Give a TCP listener tlsverify with tlscacert, tlscert and tlskey, or remove it.", ["DAEMON_JSON", "DOCKERD_ARGS"])
    _manual(r, "2.8", "Ensure the default ulimit is configured appropriately", "low",
            "Set default-ulimits (nofile, nproc) in daemon.json to values the workloads need.",
            lambda d: f"default-ulimits = {setting(d, 'default-ulimits', 'default-ulimit')}", sections=["DAEMON_JSON"])
    _rule(r, "2.9", "Enable user namespace support", "medium",
          lambda d: _sec(d, "userns") or bool(setting(d, "userns-remap")),
          lambda d: f"userns active = {_sec(d, 'userns')}; userns-remap = {setting(d, 'userns-remap')}",
          "Set \"userns-remap\": \"default\" in daemon.json and restart Docker.", ["DOCKER_INFO", "DAEMON_JSON"], level="L2")
    _manual(r, "2.10", "Ensure the default cgroup usage has been confirmed", "low",
            "Leave cgroup-parent at its default unless a specific cgroup is required.",
            lambda d: f"cgroup-parent = {setting(d, 'cgroup-parent') or 'default'}", level="L2", sections=["DAEMON_JSON"])
    _manual(r, "2.11", "Ensure base device size is not changed until needed", "low",
            "Do not set dm.basesize unless needed.",
            lambda d: f"storage-opts = {setting(d, 'storage-opts', 'storage-opt')}", level="L2", sections=["DAEMON_JSON"])
    _rule(r, "2.12", "Ensure that authorization for Docker client commands is enabled", "medium",
          lambda d: bool(setting(d, "authorization-plugins", "authorization-plugin")),
          lambda d: f"authorization-plugins = {setting(d, 'authorization-plugins', 'authorization-plugin')}",
          "Install an authorization plugin and list it in authorization-plugins.", ["DAEMON_JSON"], level="L2")
    _rule(r, "2.13", "Ensure centralized and remote logging is configured", "medium",
          lambda d: str(info(d).get("LoggingDriver") or "") not in LOCAL_LOG_DRIVERS,
          lambda d: f"logging driver = {info(d).get('LoggingDriver')}",
          "Set log-driver to a remote driver (syslog with syslog-address, gelf, fluentd, ...).", ["DOCKER_INFO"], level="L2")
    _rule(r, "2.14", "Ensure containers are restricted from acquiring new privileges", "medium",
          lambda d: bool_setting(d, "no-new-privileges") is True,
          lambda d: f"no-new-privileges = {setting(d, 'no-new-privileges')}",
          "Set \"no-new-privileges\": true in daemon.json and restart Docker.", ["DAEMON_JSON"], level="L2")
    _rule(r, "2.15", "Ensure live restore is enabled", "low",
          lambda d: info(d).get("LiveRestoreEnabled") is True,
          lambda d: f"LiveRestoreEnabled = {info(d).get('LiveRestoreEnabled')}",
          "Set \"live-restore\": true in daemon.json (not with swarm mode).", ["DOCKER_INFO"])
    _rule(r, "2.16", "Ensure Userland Proxy is Disabled", "low",
          lambda d: bool_setting(d, "userland-proxy") is False,
          lambda d: f"userland-proxy = {setting(d, 'userland-proxy') if setting(d, 'userland-proxy') is not None else 'true (default)'}",
          "Set \"userland-proxy\": false in daemon.json and restart Docker.", ["DAEMON_JSON"])
    _manual(r, "2.17", "Ensure that a daemon-wide custom seccomp profile is applied if appropriate", "low",
            "Apply a custom seccomp profile (seccomp-profile) only where the default one is too permissive for the workloads.",
            lambda d: "security options: " + _names(security_options(d)), level="L2", sections=["DOCKER_INFO"])
    _rule(r, "2.18", "Ensure that experimental features are not implemented in production", "low",
          lambda d: info(d).get("ExperimentalBuild") is not True,
          lambda d: f"ExperimentalBuild = {info(d).get('ExperimentalBuild')}",
          "Remove \"experimental\": true from daemon.json.", ["DOCKER_INFO"])

    # 3 Docker daemon configuration files ─────────────────────────────────
    for sec, tag, label, owner, group, mode, sev in FILE_RULES:
        _file_rule(r, sec, tag, label, owner, group, mode, sev)

    # 4 Container images and build file ───────────────────────────────────
    _per_container(r, "4.1", "Ensure that a user for the container has been created", "medium",
                   lambda c, d: str(c.get("User") or "") in ("", "0", "root", "0:0", "root:root"),
                   lambda c, d: f"user {c.get('User') or 'root (default)'}",
                   "Add a USER instruction to the Dockerfile (or run with --user).")
    _manual(r, "4.2", "Ensure that containers use only trusted base images", "high",
            "Pull only from trusted registries and verify image provenance.",
            lambda d: "images: " + _names(t for i in images(d) for t in (i.get("Tags") or ["<untagged>"])),
            sections=["IMAGES"])
    _manual(r, "4.3", "Ensure that unnecessary packages are not installed in the container", "medium",
            "Build minimal images (slim/distroless bases, no tools the service does not need).")
    _manual(r, "4.4", "Ensure images are scanned and rebuilt to include security patches", "high",
            "Scan images regularly and rebuild them on patched base images.",
            lambda d: "image build dates: " + _names(f"{(i.get('Tags') or ['<untagged>'])[0]} ({str(i.get('Created'))[:10]})"
                                                       for i in images(d)), sections=["IMAGES"])
    _rule(r, "4.5", "Ensure Content trust for Docker is Enabled", "medium",
          lambda d: re.search(r"DOCKER_CONTENT_TRUST=['\"]?1", host(d).get("content_trust") or "") is not None,
          lambda d: f"DOCKER_CONTENT_TRUST: {host(d).get('content_trust')}",
          "export DOCKER_CONTENT_TRUST=1 for every shell (e.g. /etc/profile.d).", ["HOST"], level="L2")
    _rule(r, "4.6", "Ensure that HEALTHCHECK instructions have been added to container images", "low",
          lambda d: not [i for i in images(d) if i.get("Tags") and not i.get("Healthcheck")],
          lambda d: "Images without HEALTHCHECK: " + _names(
              i["Tags"][0] for i in images(d) if i.get("Tags") and not i.get("Healthcheck")),
          "Add a HEALTHCHECK instruction to each image's Dockerfile.", ["IMAGES"])
    _rule(r, "4.7", "Ensure update instructions are not used alone in Dockerfiles", "low",
          lambda d: not [i for i, h in history(d).items() if _update_alone(h)],
          lambda d: "Images with a lone update instruction: " + _names(
              image_label(d, i) for i, h in history(d).items() if _update_alone(h)),
          "Combine the update with the install in one RUN instruction.", ["IMAGE_HISTORY"])
    _manual(r, "4.8", "Ensure setuid and setgid permissions are removed", "medium",
            "Remove setuid/setgid bits in the Dockerfile (find / -perm /6000 -type f -exec chmod a-s {} +).", level="L2")
    _rule(r, "4.9", "Ensure that COPY is used instead of ADD in Dockerfiles", "low",
          lambda d: not [i for i, h in history(d).items() if _uses_add(h)],
          lambda d: "Images built with ADD: " + _names(image_label(d, i) for i, h in history(d).items() if _uses_add(h)),
          "Use COPY instead of ADD in the Dockerfiles.", ["IMAGE_HISTORY"])
    _manual(r, "4.10", "Ensure secrets are not stored in Dockerfiles", "high",
            "Pass secrets at run time (docker secrets, BuildKit --secret), never as ENV or ARG.",
            lambda d: "Image history with secret-like build arguments: " + _names(
                image_label(d, i) for i, h in history(d).items() if any(SECRET_IN_HISTORY.search(x) for x in h)),
            sections=["IMAGE_HISTORY"])
    _manual(r, "4.11", "Ensure only verified packages are installed", "medium",
            "Install packages only from signed repositories (GPG-verified).", level="L2")
    _manual(r, "4.12", "Ensure all signed artifacts are validated", "medium",
            "Validate signatures of artifacts copied into images.", level="L2")

    # 5 Container runtime ─────────────────────────────────────────────────
    _rule(r, "5.1", "Ensure swarm mode is not Enabled, if not needed", "medium",
          lambda d: ((info(d).get("Swarm") or {}).get("LocalNodeState") or "inactive") != "active",
          lambda d: f"Swarm LocalNodeState = {(info(d).get('Swarm') or {}).get('LocalNodeState')}",
          "If the host is not part of a swarm on purpose: docker swarm leave.", ["DOCKER_INFO"])
    _per_container(r, "5.2", "Ensure that, if applicable, an AppArmor Profile is enabled", "medium",
                   lambda c, d: _sec(d, "apparmor") and str(c.get("AppArmorProfile") or "") in ("", "unconfined"),
                   lambda c, d: f"AppArmor profile {c.get('AppArmorProfile') or 'none'}",
                   "Run containers with an AppArmor profile (docker-default or a custom one).",
                   sections=("CONTAINERS", "DOCKER_INFO"))
    _per_container(r, "5.3", "Ensure that, if applicable, SELinux security options are set", "medium",
                   lambda c, d: _sec(d, "selinux") and not any(o.startswith("label") for o in _secopts(c)),
                   lambda c, d: f"security options {_secopts(c) or 'none'}",
                   "Run containers with --security-opt label=... on SELinux hosts.", level="L2",
                   sections=("CONTAINERS", "DOCKER_INFO"))
    _per_container(r, "5.4", "Ensure that Linux kernel capabilities are restricted within containers", "high",
                   lambda c, d: bool(_added_caps(c)), lambda c, d: f"added {', '.join(_added_caps(c))}",
                   "Drop all capabilities and add back only the ones needed (--cap-drop=all --cap-add=...).")
    _per_container(r, "5.5", "Ensure that privileged containers are not used", "high",
                   lambda c, d: bool(_hc(c).get("Privileged")), lambda c, d: "privileged",
                   "Run the container without --privileged.")
    _per_container(r, "5.6", "Ensure sensitive host system directories are not mounted on containers", "high",
                   lambda c, d: bool(_sensitive_mounts(c)), lambda c, d: _names(_sensitive_mounts(c)),
                   "Do not bind-mount /, /boot, /dev, /etc, /lib, /proc, /sys or /usr.")
    _per_container(r, "5.7", "Ensure sshd is not run within containers", "medium",
                   lambda c, d: "sshd" in procs(d).get(str(c.get("Id", ""))[:12], []), lambda c, d: "runs sshd",
                   "Remove sshd from the image; use docker exec for access.", sections=("CONTAINERS", "CONTAINER_PROCS"))
    _per_container(r, "5.8", "Ensure privileged ports are not mapped within containers", "medium",
                   lambda c, d: any(p[2].isdigit() and int(p[2]) < 1024 for p in _ports(c)),
                   lambda c, d: _names(f"{p[2]}->{p[0]}" for p in _ports(c) if p[2].isdigit() and int(p[2]) < 1024),
                   "Publish container ports on host ports above 1024 (or behind a reverse proxy).")
    _manual(r, "5.9", "Ensure that only needed ports are open on the container", "medium",
            "Publish only the ports the service needs.",
            lambda d: "published: " + _names(f"{name_of(c)} {p[1] or '*'}:{p[2]}->{p[0]}"
                                             for c in containers(d) for p in _ports(c)), sections=C)
    _per_container(r, "5.10", "Ensure that the host's network namespace is not shared", "high",
                   lambda c, d: _hc(c).get("NetworkMode") == "host", lambda c, d: "network host",
                   "Run the container without --network=host.")
    _per_container(r, "5.11", "Ensure that the memory usage for containers is limited", "medium",
                   lambda c, d: not _hc(c).get("Memory"), lambda c, d: "no memory limit",
                   "Run with --memory (and --memory-swap).")
    _per_container(r, "5.12", "Ensure that CPU priority is set appropriately on containers", "low",
                   lambda c, d: _hc(c).get("CpuShares") in (None, 0, 1024) and not _hc(c).get("NanoCpus"),
                   lambda c, d: "no CPU shares or limit", "Run with --cpu-shares (or --cpus).")
    _per_container(r, "5.13", "Ensure that the container's root filesystem is mounted as read only", "medium",
                   lambda c, d: not _hc(c).get("ReadonlyRootfs"), lambda c, d: "writable root filesystem",
                   "Run with --read-only and mount writable paths as volumes or tmpfs.")
    _per_container(r, "5.14", "Ensure that incoming container traffic is bound to a specific host interface", "medium",
                   lambda c, d: any(p[1] in ("", "0.0.0.0", "::") for p in _ports(c)),
                   lambda c, d: _names(f"{p[1] or '*'}:{p[2]}" for p in _ports(c) if p[1] in ("", "0.0.0.0", "::")),
                   "Publish ports on a specific address (-p 10.0.0.5:8080:80).")
    _per_container(r, "5.15", "Ensure that the 'on-failure' container restart policy is set to '5'", "low",
                   lambda c, d: not _restart_ok(c),
                   lambda c, d: f"restart {(_hc(c).get('RestartPolicy') or {}).get('Name')}:"
                                f"{(_hc(c).get('RestartPolicy') or {}).get('MaximumRetryCount')}",
                   "Use --restart=on-failure:5.")
    _per_container(r, "5.16", "Ensure that the host's process namespace is not shared", "high",
                   lambda c, d: _hc(c).get("PidMode") == "host", lambda c, d: "pid host", "Run without --pid=host.")
    _per_container(r, "5.17", "Ensure that the host's IPC namespace is not shared", "high",
                   lambda c, d: _hc(c).get("IpcMode") == "host", lambda c, d: "ipc host", "Run without --ipc=host.")
    _per_container(r, "5.18", "Ensure that host devices are not directly exposed to containers", "medium",
                   lambda c, d: bool(_hc(c).get("Devices")),
                   lambda c, d: _names(x.get("PathOnHost") for x in _hc(c).get("Devices") or []),
                   "Do not pass host devices with --device unless required.")
    _manual(r, "5.19", "Ensure that the default ulimit is overwritten at run time if needed", "low",
            "Override ulimits per container only where needed.",
            lambda d: "overrides: " + _names(f"{name_of(c)} {_hc(c).get('Ulimits')}" for c in containers(d)
                                             if _hc(c).get("Ulimits")), sections=C)
    _per_container(r, "5.20", "Ensure mount propagation mode is not set to shared", "medium",
                   lambda c, d: any(m.get("Propagation") in ("shared", "rshared") for m in c.get("Mounts") or []),
                   lambda c, d: "shared mount propagation", "Do not mount volumes with shared propagation.")
    _per_container(r, "5.21", "Ensure that the host's UTS namespace is not shared", "medium",
                   lambda c, d: _hc(c).get("UTSMode") == "host", lambda c, d: "uts host", "Run without --uts=host.")
    _per_container(r, "5.22", "Ensure the default seccomp profile is not Disabled", "high",
                   lambda c, d: any(re.match(r"seccomp[=:]unconfined", o) for o in _secopts(c)),
                   lambda c, d: "seccomp unconfined", "Run without --security-opt seccomp=unconfined.")
    _manual(r, "5.23", "Ensure that docker exec commands are not used with the privileged option", "high",
            "Do not use docker exec --privileged; review audit logs for its use.")
    _manual(r, "5.24", "Ensure that docker exec commands are not used with the user=root option", "medium",
            "Do not use docker exec --user=root; review audit logs for its use.", level="L2")
    _per_container(r, "5.25", "Ensure that cgroup usage is confirmed", "low",
                   lambda c, d: bool(_hc(c).get("CgroupParent")),
                   lambda c, d: f"cgroup parent {_hc(c).get('CgroupParent')}",
                   "Leave --cgroup-parent at the default unless required.")
    _per_container(r, "5.26", "Ensure that the container is restricted from acquiring additional privileges", "high",
                   lambda c, d: bool_setting(d, "no-new-privileges") is not True and not any(
                       re.match(r"no-new-privileges(?:[=:]true)?$", o) for o in _secopts(c)),
                   lambda c, d: "no-new-privileges not set",
                   "Run with --security-opt=no-new-privileges (or set it daemon-wide).",
                   sections=("CONTAINERS", "DAEMON_JSON"))
    _per_container(r, "5.27", "Ensure that container health is checked at runtime", "low",
                   lambda c, d: not c.get("Health"), lambda c, d: "no health check",
                   "Give the image a HEALTHCHECK or run with --health-cmd.")
    _manual(r, "5.28", "Ensure that Docker commands always make use of the latest version of their image", "low",
            "Pull images before running them and pin by digest where reproducibility matters.")
    _per_container(r, "5.29", "Ensure that the PIDs cgroup limit is used", "medium",
                   lambda c, d: not (_hc(c).get("PidsLimit") or 0) > 0, lambda c, d: "no PIDs limit",
                   "Run with --pids-limit.")
    _per_container(r, "5.30", "Ensure that Docker's default bridge 'docker0' is not used", "low",
                   lambda c, d: "bridge" in (c.get("Networks") or []), lambda c, d: "on the default bridge",
                   "Attach containers to user-defined networks.", level="L2")
    _per_container(r, "5.31", "Ensure that the host's user namespaces are not shared", "medium",
                   lambda c, d: _hc(c).get("UsernsMode") == "host", lambda c, d: "userns host",
                   "Run without --userns=host.")
    _per_container(r, "5.32", "Ensure that the Docker socket is not mounted inside any containers", "high",
                   lambda c, d: any("docker.sock" in str(m.get("Source") or "") for m in c.get("Mounts") or []),
                   lambda c, d: "docker.sock mounted", "Do not mount /var/run/docker.sock into containers.")

    # 6 Docker security operations ────────────────────────────────────────
    _manual(r, "6.1", "Ensure that image sprawl is avoided", "low",
            "Remove images that no container uses (docker image prune -a after review).",
            lambda d: f"{host(d).get('images')} images, {host(d).get('dangling')} dangling", sections=["HOST"])
    _manual(r, "6.2", "Ensure that container sprawl is avoided", "low",
            "Remove stopped containers that are no longer needed (docker container prune after review).",
            lambda d: f"{host(d).get('containers_all')} containers, {host(d).get('containers_running')} running",
            sections=["HOST"])
    return r


def rules_for(dump: str) -> List[BenchmarkRule]:
    if section(dump, "DOCKER_VERSION").strip() == NO_DOCKER:
        raise ValueError("Docker is not installed on this host (the docker command was not found).")
    if not (version(dump).get("Server")):
        raise ValueError("The Docker daemon is not running or not reachable on this host.")
    return build_rules()


def all_rules() -> List[BenchmarkRule]:
    return build_rules()


def describe(dump: str) -> str:
    os_name = next((ln.split("=", 1)[1].strip('"') for ln in section(dump, "OS_RELEASE").splitlines()
                    if ln.startswith("PRETTY_NAME=")), "Linux")
    return (f"Docker Engine {(version(dump).get('Server') or {}).get('Version')} on {os_name}, "
            f"{len(containers(dump))} running containers")
