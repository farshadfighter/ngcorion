"""
Docker host remediation.

Three kinds of automated fix:
- audit rules for the Docker files (1.1.x): written to
  /etc/audit/rules.d/docker.rules and loaded with auditctl;
- daemon settings (2.x): merged into /etc/docker/daemon.json with python3,
  checked with `dockerd --validate` before the file is replaced, refused when
  the same option is given on the dockerd command line (Docker would not
  start with it in both places). The first change keeps the original file as
  daemon.json.ngcorion-orig. Most settings take effect when Docker restarts,
  which is left to the operator because it stops running containers unless
  live-restore is on; live-restore itself is applied with a reload;
- ownership and modes of the daemon's files (3.x): only permission bits the
  benchmark disallows are removed, so a stricter file stays as it is.

Container runtime findings (section 5) and image findings (section 4) need
the containers recreated or the images rebuilt; they come with guidance only.
"""

import json
from typing import Dict, Iterable, Optional

from app.modules.benchmark.templates import HardeningTemplate, ParamMeta, TemplateSet

from . import rules as R
from .collect import DOCKERD_PS, SHELL_PATHS, _tls_paths

TEMPLATES = TemplateSet()
TEMPLATES.param(ParamMeta(
    name="CONFIRM", input_type="select", label="Confirm the change",
    description="This change has side effects described in the check's warning. Choose 'yes' to apply it.",
    required=True, options=["yes"]))

RESTART = ("Takes effect when the Docker daemon restarts (systemctl restart docker); running containers stop "
           "then unless live-restore is enabled.")


def _add(sec, description, statements, verify, warning=None, confirm=False, restart=False):
    TEMPLATES.add(HardeningTemplate(
        check_id=f"DKR-{sec}", description=description, statements=statements, verify_statements=verify,
        parameters=["CONFIRM"] if confirm else [], warning=warning, requires_restart=restart))


# 1.1.x audit rules ──────────────────────────────────────────────────────

_WATCHED = "auditctl -l 2>/dev/null | grep -qE -- \"(-w |path=|dir=)$p/?( |$)\""

for _sec, _tag, _label in R.AUDITED:
    _p = SHELL_PATHS[_tag]
    _add(_sec, f"Audit {_label} (auditd watch, key docker)", [
        "command -v auditctl >/dev/null 2>&1 || { echo 'auditd is not installed: install the auditd package, "
        "then run this fix again' >&2; exit 1; }; "
        f"p={_p}; if [ -z \"$p\" ] || [ ! -e \"$p\" ]; then echo \"nothing to audit: $p is not present\"; exit 0; fi; "
        "f=/etc/audit/rules.d/docker.rules; mkdir -p /etc/audit/rules.d; touch $f; chmod 640 $f; "
        "grep -qxF -- \"-w $p -k docker\" $f || echo \"-w $p -k docker\" >> $f; "
        f"{_WATCHED} || auditctl -w \"$p\" -k docker"
    ], [
        f"p={_p}; if [ -z \"$p\" ] || [ ! -e \"$p\" ]; then echo PASS; elif {_WATCHED}; then echo PASS; else echo FAIL; fi"
    ])


# 2.x daemon.json ────────────────────────────────────────────────────────

DAEMON_JSON = "/etc/docker/daemon.json"
NEW = DAEMON_JSON + ".ngcorion-new"


def daemon_json_edit(updates: Optional[Dict] = None, remove: Iterable[str] = (), flags: Iterable[str] = ()) -> str:
    """One shell statement that merges `updates` into daemon.json and drops `remove`."""
    py = (
        "import json, os\n"
        f"p = {DAEMON_JSON!r}\n"
        "d = json.load(open(p)) if os.path.exists(p) and os.path.getsize(p) else {}\n"
        f"d.update(json.loads({json.dumps(updates or {})!r}))\n"
        f"for k in {list(remove)!r}:\n"
        "    d.pop(k, None)\n"
        f"json.dump(d, open({NEW!r}, 'w'), indent=2)\n"
    )
    conflicts = "".join(
        f"{DOCKERD_PS} | grep -qE -- '--{f}([= ]|$)' && {{ echo '--{f} is set on the dockerd command line; "
        f"change it in the service unit instead' >&2; exit 1; }}; " for f in flags)
    return (
        "command -v python3 >/dev/null 2>&1 || { echo 'python3 is needed to edit daemon.json safely' >&2; exit 1; }; "
        + conflicts +
        f"mkdir -p /etc/docker; [ -f {DAEMON_JSON} ] && [ ! -e {DAEMON_JSON}.ngcorion-orig ] && "
        f"cp -p {DAEMON_JSON} {DAEMON_JSON}.ngcorion-orig; "
        f"python3 - <<'PY'\n{py}PY\n"
        "if dockerd --help 2>&1 | grep -q -- '--validate'; then "
        f"dockerd --validate --config-file {NEW} >/dev/null 2>&1 || {{ rm -f {NEW}; "
        "echo 'dockerd rejected the new configuration; daemon.json was not changed' >&2; exit 1; }; fi; "
        f"chown root:root {NEW}; chmod 644 {NEW}; mv {NEW} {DAEMON_JSON}"
    )


def daemon_json_check(expr: str) -> str:
    """Prints PASS when `expr` (Python, over the parsed file `d`) holds."""
    return (f"python3 -c \"import json, os; p = '{DAEMON_JSON}'; "
            f"d = json.load(open(p)) if os.path.exists(p) and os.path.getsize(p) else dict(); "
            f"print('PASS' if ({expr}) else 'FAIL')\"")


def _daemon(sec, description, updates=None, remove=(), flags=(), check="True", warning=None, confirm=False,
            restart=True):
    _add(sec, description, [daemon_json_edit(updates, remove, flags)], [daemon_json_check(check)],
         warning=" ".join(x for x in (warning, RESTART if restart else None) if x) or None,
         confirm=confirm, restart=restart)


_daemon("2.2", "Disable inter-container communication on the default bridge (icc: false)",
        {"icc": False}, flags=["icc"], check="d.get('icc') is False",
        warning="Containers on the default bridge can no longer reach each other unless linked or moved to a "
                "user-defined network. The default bridge picks the setting up only when Docker restarts with no "
                "container attached to it.", confirm=True)
_daemon("2.3", "Set the daemon log level to info", {"log-level": "info"}, remove=["debug"],
        flags=["log-level", "debug"], check="d.get('log-level') == 'info' and not d.get('debug')")
_daemon("2.4", "Let Docker manage iptables", remove=["iptables"], flags=["iptables"],
        check="d.get('iptables', True) is not False",
        warning="Docker adds its own iptables chains; published ports then bypass host firewall rules that "
                "are not in DOCKER-USER.", confirm=True)
_daemon("2.5", "Remove insecure registries", remove=["insecure-registries"], flags=["insecure-registry"],
        check="not d.get('insecure-registries')",
        warning="Pulls and pushes to registries without a trusted TLS certificate stop working.", confirm=True)
_daemon("2.9", "Enable user namespace remapping (userns-remap: default)", {"userns-remap": "default"},
        flags=["userns-remap"], check="bool(d.get('userns-remap'))",
        warning="Docker starts with a new, empty image and container store under the remapped root; existing "
                "containers and images are not visible until it is turned off again, and bind-mounted files "
                "need ownership changes. Host networking and --privileged no longer work.", confirm=True)
_daemon("2.14", "Block privilege escalation in containers by default (no-new-privileges)",
        {"no-new-privileges": True}, flags=["no-new-privileges"], check="d.get('no-new-privileges') is True",
        warning="setuid programs (sudo, su, ping on some images) stop gaining privileges inside containers.",
        confirm=True)
_daemon("2.16", "Disable the userland proxy", {"userland-proxy": False}, flags=["userland-proxy"],
        check="d.get('userland-proxy') is False",
        warning="Published ports are forwarded with iptables (hairpin NAT) instead of docker-proxy.")
_daemon("2.18", "Turn experimental features off", {"experimental": False}, flags=["experimental"],
        check="not d.get('experimental')")

# live-restore is the one daemon option applied with a reload, so it is
# verified on what the daemon reports, not only on the file.
_add("2.15", "Enable live restore", [
    "[ \"$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null)\" = active ] && "
    "{ echo 'live-restore cannot be used in swarm mode' >&2; exit 1; }; "
    + daemon_json_edit({"live-restore": True}, flags=["live-restore"])
    + "; systemctl reload docker 2>/dev/null || kill -HUP $(pidof dockerd)"
], [daemon_json_check("d.get('live-restore') is True"),
    "sleep 1; [ \"$(docker info --format '{{.LiveRestoreEnabled}}')\" = true ] && echo PASS || echo FAIL"])


# 3.x file ownership and modes ───────────────────────────────────────────

FILE_PATHS = {
    "docker_service": SHELL_PATHS["docker_service"],
    "docker_socket": SHELL_PATHS["docker_socket"],
    "etc_docker": "/etc/docker",
    "registry_cert": "$(find /etc/docker/certs.d -type f 2>/dev/null)",
    "tlscacert": f"$({_tls_paths('tlscacert')})",
    "tlscert": f"$({_tls_paths('tlscert')})",
    "tlskey": f"$({_tls_paths('tlskey')})",
    "docker_sock": "/var/run/docker.sock",
    "daemon_json": DAEMON_JSON,
    "default_docker": "/etc/default/docker",
    "sysconfig_docker": "/etc/sysconfig/docker",
    "containerd_sock": "/run/containerd/containerd.sock",
}
assert {tag for _s, tag, *_r in R.FILE_RULES} <= set(FILE_PATHS)

for _sec, _tag, _label, _owner, _group, _mode, _sev in R.FILE_RULES:
    _paths = FILE_PATHS[_tag]
    if _owner:
        _add(_sec, f"Set the {_label} ownership to {_owner}:{_group}",
             [f"for f in {_paths}; do [ -e \"$f\" ] && chown {_owner}:{_group} \"$f\"; done; true"],
             [f"r=PASS; for f in {_paths}; do [ -e \"$f\" ] || continue; "
              f"[ \"$(stat -c %U:%G \"$f\")\" = {_owner}:{_group} ] || r=FAIL; done; echo $r"])
    else:
        _add(_sec, f"Set the {_label} permissions to {_mode:o} or more restrictive",
             [f"for f in {_paths}; do [ -e \"$f\" ] || continue; m=$(stat -c %a \"$f\"); "
              f"chmod $(printf '%o' $(( 0$m & 0{_mode:o} ))) \"$f\"; done; true"],
             [f"r=PASS; for f in {_paths}; do [ -e \"$f\" ] || continue; m=$(stat -c %a \"$f\"); "
              f"[ $(( 0$m & ~0{_mode:o} & 07777 )) -eq 0 ] || r=FAIL; done; echo $r"])


# 4.5 content trust ──────────────────────────────────────────────────────

_CT = "/etc/profile.d/docker-content-trust.sh"
_add("4.5", "Enable Docker Content Trust for every login shell",
     [f"printf 'export DOCKER_CONTENT_TRUST=1\\n' > {_CT}; chmod 644 {_CT}"],
     [f"grep -qs '^export DOCKER_CONTENT_TRUST=1' {_CT} && echo PASS || echo FAIL"],
     warning="docker pull, push, build and run then refuse unsigned images for users of this host.", confirm=True)


# Guidance only ──────────────────────────────────────────────────────────

_GUIDANCE = {
    "1.1.1": "Move the Docker root directory to its own partition or logical volume (stop Docker, copy, mount, start).",
    "1.1.2": "Remove users who should not have root-equivalent access from the docker group (gpasswd -d <user> docker).",
    "1.2.1": "Harden the host OS with the CIS Linux benchmark (Linux audit on this host).",
    "1.2.2": "Upgrade Docker Engine to the current release.",
    "2.1": "Consider rootless mode (dockerd-rootless-setuptool.sh install).",
    "2.6": "Migrate from aufs to overlay2 (images must be pulled again).",
    "2.7": "Create a CA and server certificate and set tlsverify, tlscacert, tlscert and tlskey for the TCP listener.",
    "2.8": "Set default-ulimits in daemon.json to values the workloads need.",
    "2.10": "Keep cgroup-parent at its default unless a specific cgroup is required.",
    "2.11": "Do not set dm.basesize unless needed.",
    "2.12": "Install an authorization plugin (e.g. OPA) and list it in authorization-plugins.",
    "2.13": "Set log-driver and log-opts for the central log server (syslog-address, gelf-address, fluentd-address).",
    "2.17": "Write a seccomp profile for the workloads and set seccomp-profile in daemon.json.",
    "4.1": "Add a USER instruction to the Dockerfile and recreate the container.",
    "4.2": "Use base images from trusted registries only.",
    "4.3": "Remove packages the service does not need from the image.",
    "4.4": "Scan the images and rebuild them on patched base images.",
    "4.6": "Add a HEALTHCHECK instruction to each Dockerfile and rebuild.",
    "4.7": "Combine the package index update with the install in one RUN instruction.",
    "4.8": "Remove setuid/setgid bits in the Dockerfile.",
    "4.9": "Replace ADD with COPY in the Dockerfiles.",
    "4.10": "Move secrets out of the Dockerfiles (BuildKit --secret, docker secrets).",
    "4.11": "Install packages only from GPG-verified repositories.",
    "4.12": "Validate the signatures of artifacts added to images.",
    "5.1": "If the host is not meant to be in a swarm: docker swarm leave.",
}
_RUNTIME = "Recreate the container with the setting described in the finding (docker run / compose file)."
for _r in R.all_rules():
    if _r.id not in TEMPLATES.templates:
        TEMPLATES.manual(_r.id, _GUIDANCE.get(_r.section, _RUNTIME if _r.section.startswith("5.") else _r.remediation))
