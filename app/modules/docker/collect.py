"""
Read-only collection for a Docker host audit, over SSH (as root via sudo).

Everything comes from the Docker CLI, the daemon configuration and the
host's files: `docker info` / `docker version`, /etc/docker/daemon.json, the
dockerd command line, ownership and modes of the files the benchmark
names, the audit rules, and for each running container a selection of its
`docker inspect` output. Container environment variables are never read -
they often hold passwords; `docker inspect` output is cut down to the fields
the rules need before anything is stored - and nothing is executed inside a container
(`docker top` reads the process list from the host).

Every script prints something even when there is nothing to report
("NONE", "[]"), so an empty section always means the collection failed.
"""

import json
from typing import Dict

from app.modules.benchmark.rules import assemble, parse_json

NO_DOCKER = "NO_DOCKER"

# Paths the benchmark audits, as shell expressions resolved on the host
# (the binaries' real location, the unit files systemd actually loads).
_UNIT = (
    "$(systemctl show -p FragmentPath --value {unit} 2>/dev/null | grep . || "
    "for f in /etc/systemd/system/{unit} /usr/lib/systemd/system/{unit} /lib/systemd/system/{unit}; do "
    "[ -e $f ] && echo $f && break; done)"
)
SHELL_PATHS = {
    "dockerd": "$(command -v dockerd || echo /usr/bin/dockerd)",
    "run_containerd": "/run/containerd",
    "docker_root": "$(docker info --format '{{.DockerRootDir}}' 2>/dev/null | grep . || echo /var/lib/docker)",
    "etc_docker": "/etc/docker",
    "docker_service": _UNIT.format(unit="docker.service"),
    "containerd_sock": "/run/containerd/containerd.sock",
    "docker_socket": _UNIT.format(unit="docker.socket"),
    "default_docker": "/etc/default/docker",
    "daemon_json": "/etc/docker/daemon.json",
    "containerd_config": "/etc/containerd/config.toml",
    "sysconfig_docker": "/etc/sysconfig/docker",
    "containerd": "$(command -v containerd || echo /usr/bin/containerd)",
    "containerd_shim": "$(command -v containerd-shim || echo /usr/bin/containerd-shim)",
    "shim_runc_v1": "$(command -v containerd-shim-runc-v1 || echo /usr/bin/containerd-shim-runc-v1)",
    "shim_runc_v2": "$(command -v containerd-shim-runc-v2 || echo /usr/bin/containerd-shim-runc-v2)",
    "runc": "$(command -v runc || echo /usr/bin/runc)",
}

# dockerd process lines (the daemon may be started by systemd with flags).
DOCKERD_PS = "ps -eo args= | grep -E '^(\\S*/)?dockerd( |$)'"

_REQUIRE_DOCKER = f"command -v docker >/dev/null 2>&1 || {{ echo {NO_DOCKER}; exit 0; }}; "

DOCKER_VERSION = _REQUIRE_DOCKER + "docker version --format '{{json .}}'"
DOCKER_INFO = _REQUIRE_DOCKER + "docker info --format '{{json .}}'"
DAEMON_JSON = "if [ -s /etc/docker/daemon.json ]; then cat /etc/docker/daemon.json; else echo '{}'; fi"
DOCKERD_ARGS = f"out=$({DOCKERD_PS}); [ -n \"$out\" ] && printf '%s\\n' \"$out\" || echo NONE"


def _tls_paths(key: str) -> str:
    """Paths given for --tlscacert/--tlscert/--tlskey in daemon.json or on the command line."""
    return (
        f"{{ sed -n 's/.*\"{key}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' /etc/docker/daemon.json 2>/dev/null; "
        f"{DOCKERD_PS} | grep -oE -- '--{key}[= ][^ ]+' | sed -E 's/--{key}[= ]//'; }} | sort -u"
    )


FILES = (
    "st() { tag=$1; shift; for f in \"$@\"; do [ -n \"$f\" ] || continue; "
    "if [ -e \"$f\" ]; then printf '%s|' \"$tag\"; stat -c '%n|%U|%G|%a|%F' \"$f\"; "
    "else echo \"$tag|$f|-|-|-|missing\"; fi; done; }; "
    f"st docker_service {SHELL_PATHS['docker_service']}; "
    f"st docker_socket {SHELL_PATHS['docker_socket']}; "
    "st etc_docker /etc/docker; "
    "find /etc/docker/certs.d -type f 2>/dev/null | while read -r f; do st registry_cert \"$f\"; done; "
    f"for f in $({_tls_paths('tlscacert')}); do st tlscacert \"$f\"; done; "
    f"for f in $({_tls_paths('tlscert')}); do st tlscert \"$f\"; done; "
    f"for f in $({_tls_paths('tlskey')}); do st tlskey \"$f\"; done; "
    "st docker_sock /var/run/docker.sock; "
    "st daemon_json /etc/docker/daemon.json; "
    "st default_docker /etc/default/docker; "
    "st sysconfig_docker /etc/sysconfig/docker; "
    "st containerd_sock /run/containerd/containerd.sock; "
    "echo END"
)

AUDIT_PATHS = "; ".join(
    f"p={expr}; if [ -n \"$p\" ] && [ -e \"$p\" ]; then echo \"{tag}|$p|1\"; else echo \"{tag}|$p|0\"; fi"
    for tag, expr in SHELL_PATHS.items()
)

AUDIT_RULES = "if command -v auditctl >/dev/null 2>&1; then auditctl -l; else echo NO_AUDITCTL; fi"

HOST = (
    "echo \"group=$(getent group docker || echo NONE)\"; "
    f"d={SHELL_PATHS['docker_root']}; "
    "if mountpoint -q \"$d\" 2>/dev/null; then m=separate; else m=shared; fi; "
    "echo \"root=$d|$m|$(findmnt -n -o SOURCE,TARGET --target \"$d\" 2>/dev/null | head -1)\"; "
    "t=$(grep -rhsE '^[[:space:]]*(export[[:space:]]+)?DOCKER_CONTENT_TRUST=' /etc/environment /etc/profile "
    "/etc/profile.d /etc/bash.bashrc /etc/bashrc | tail -1); echo \"content_trust=${t:-NONE}\"; "
    "echo \"images=$(docker images -q 2>/dev/null | sort -u | wc -l)\"; "
    "echo \"dangling=$(docker images -q -f dangling=true 2>/dev/null | sort -u | wc -l)\"; "
    "echo \"containers_all=$(docker ps -aq 2>/dev/null | wc -l)\"; "
    "echo \"containers_running=$(docker ps -q 2>/dev/null | wc -l)\""
)

CONTAINERS = "ids=$(docker ps -q); if [ -z \"$ids\" ]; then echo '[]'; else docker inspect $ids; fi"
CONTAINER_PROCS = (
    "ids=$(docker ps -q); [ -n \"$ids\" ] || echo NONE; "
    "for i in $ids; do echo \"### $i\"; docker top \"$i\" -o pid,comm 2>/dev/null | awk 'NR>1{print $2}'; done"
)

IMAGES = ("ids=$(docker images -q | sort -u | head -200); "
          "if [ -z \"$ids\" ]; then echo '[]'; else docker image inspect $ids; fi")
IMAGE_HISTORY = (
    "ids=$(docker images -q | sort -u | head -200); [ -n \"$ids\" ] || echo NONE; "
    "for i in $ids; do echo \"### $i\"; docker history --no-trunc --format '{{.CreatedBy}}' \"$i\" 2>/dev/null "
    "| head -150; done"
)
NETWORKS = (
    "docker network inspect --format '{\"Name\":{{json .Name}},\"Driver\":{{json .Driver}},"
    "\"Options\":{{json .Options}}}' $(docker network ls -q)"
)
OS_RELEASE = "cat /etc/os-release 2>/dev/null || uname -sr"


def docker_commands() -> Dict[str, str]:
    return {
        "OS_RELEASE": OS_RELEASE,
        "DOCKER_VERSION": DOCKER_VERSION,
        "DOCKER_INFO": DOCKER_INFO,
        "DAEMON_JSON": DAEMON_JSON,
        "DOCKERD_ARGS": DOCKERD_ARGS,
        "FILES": FILES,
        "AUDIT_PATHS": AUDIT_PATHS,
        "AUDIT_RULES": AUDIT_RULES,
        "HOST": HOST,
        "CONTAINERS": CONTAINERS,
        "CONTAINER_PROCS": CONTAINER_PROCS,
        "IMAGES": IMAGES,
        "IMAGE_HISTORY": IMAGE_HISTORY,
        "NETWORKS": NETWORKS,
    }


# What is kept of `docker inspect`. Environment variables, labels and the
# command line are dropped here, on this side, before anything is stored.
CONTAINER_KEYS = ("Id", "Name", "AppArmorProfile")
CONTAINER_CONFIG_KEYS = ("Image", "User", "Healthcheck")
HOST_CONFIG_KEYS = (
    "Privileged", "CapAdd", "CapDrop", "NetworkMode", "PidMode", "IpcMode", "UTSMode", "UsernsMode",
    "Memory", "CpuShares", "NanoCpus", "ReadonlyRootfs", "RestartPolicy", "Devices", "SecurityOpt",
    "CgroupParent", "PidsLimit", "Ulimits", "PortBindings",
)
MOUNT_KEYS = ("Type", "Source", "Destination", "RW", "Propagation")


def _pick(obj, keys):
    return {k: obj.get(k) for k in keys} if isinstance(obj, dict) else {}


def slim_containers(raw: str) -> str:
    data = parse_json(raw)
    if not isinstance(data, list):
        return raw
    out = []
    for c in data:
        if not isinstance(c, dict):
            continue
        # Already-slim input (a re-run on stored output) passes through unchanged.
        item = _pick(c, CONTAINER_KEYS)
        item.update(_pick(c.get("Config") if "Config" in c else c, CONTAINER_CONFIG_KEYS))
        item["HostConfig"] = _pick(c.get("HostConfig"), HOST_CONFIG_KEYS)
        item["Mounts"] = [_pick(m, MOUNT_KEYS) for m in (c.get("Mounts") or []) if isinstance(m, dict)]
        if "NetworkSettings" in c:
            net = c.get("NetworkSettings") or {}
            item["Ports"] = net.get("Ports") or {}
            item["Networks"] = sorted((net.get("Networks") or {}).keys())
            health = (c.get("State") or {}).get("Health")
            item["Health"] = health.get("Status") if isinstance(health, dict) else None
        else:
            item["Ports"] = c.get("Ports") or {}
            item["Networks"] = sorted(c.get("Networks") or [])
            item["Health"] = c.get("Health")
        out.append(item)
    return json.dumps(out, separators=(",", ":"))


def slim_images(raw: str) -> str:
    data = parse_json(raw)
    if not isinstance(data, list):
        return raw
    out = []
    for i in data:
        if not isinstance(i, dict):
            continue
        cfg = (i.get("Config") or {}) if "Config" in i else i
        out.append({"Id": i.get("Id"), "Tags": i.get("RepoTags") or i.get("Tags") or [], "Created": i.get("Created"),
                    "User": cfg.get("User") or "", "Healthcheck": cfg.get("Healthcheck")})
    return json.dumps(out, separators=(",", ":"))


SLIM = {"CONTAINERS": slim_containers, "IMAGES": slim_images}


def collect(conn) -> str:
    cmds = docker_commands()
    version = conn.run(cmds["DOCKER_VERSION"])
    if version.strip() == NO_DOCKER:
        return assemble({"DOCKER_VERSION": NO_DOCKER})
    out = {"DOCKER_VERSION": version}
    for name, script in cmds.items():
        if name == "DOCKER_VERSION":
            continue
        text = conn.run(script)
        out[name] = SLIM[name](text) if name in SLIM else text
    return assemble(out)
