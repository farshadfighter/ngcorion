"""
File-bundle restore for SSH hosts whose "configuration" is a set of files
(Linux, Apache, MongoDB).

A backup of these families is the text bundle built by
app/modules/shared/hardening_backup.build_file_bundle_command:

    ##### BEGIN FILE: /etc/ssh/sshd_config #####
    <exact file content>
    <one extra newline added by `echo ""`>
    ##### END FILE: /etc/ssh/sshd_config #####

This module turns bundles back into {path: content}, diffs two of them, and
produces the restore plan. Every path is checked against the family's own
backup path globs: a restore can only ever write the files that family backs
up, whatever a (possibly tampered) backup row contains.
"""
import base64
import difflib
import fnmatch
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.modules.backup.restore.config_tree import ConfigDiff, DiffLine, DiffSection

_BEGIN = re.compile(r"^##### BEGIN FILE: (.+) #####$")
_END = "##### END FILE: {} #####"

# Per family: how to validate the new files and make the service pick them up.
# Validation runs BEFORE the reload; a failed validation restores the old files.
FAMILY_SERVICES = {
    "linux": {
        "validate": [("sshd", "/etc/ssh/sshd_config*", "sshd -t")],
        "reload": [("sshd", "/etc/ssh/sshd_config*",
                    "systemctl reload sshd 2>/dev/null || systemctl reload ssh")],
    },
    "apache": {
        "validate": [("apache", "*", "apachectl -t 2>&1 || apache2ctl -t 2>&1 || httpd -t 2>&1")],
        "reload": [("apache", "*",
                    "systemctl reload apache2 2>/dev/null || systemctl reload httpd")],
    },
    "mongodb": {
        "validate": [],
        "reload": [("mongod", "*", "systemctl restart mongod && sleep 3 && systemctl is-active mongod")],
    },
}


def family_paths(family: str) -> List[str]:
    if family == "linux":
        from app.modules.linux.hardening.ssh_executor import LINUX_BACKUP_PATHS
        return LINUX_BACKUP_PATHS
    if family == "apache":
        from app.modules.apache.hardening.ssh_executor import APACHE_BACKUP_PATHS
        return APACHE_BACKUP_PATHS
    if family == "mongodb":
        from app.modules.mongodb.hardening.ssh_executor import MONGODB_BACKUP_PATHS
        return MONGODB_BACKUP_PATHS
    raise ValueError(f"Not a file-bundle family: {family}")


def path_allowed(path: str, family: str) -> bool:
    if not path.startswith("/") or posixpath.normpath(path) != path or "\n" in path:
        return False
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in family_paths(family))


def parse_bundle(text: str) -> Dict[str, str]:
    files: Dict[str, str] = {}
    lines = (text or "").split("\n")
    i = 0
    while i < len(lines):
        m = _BEGIN.match(lines[i])
        i += 1
        if not m:
            continue
        path = m.group(1)
        end = _END.format(path)
        body = []
        while i < len(lines) and lines[i] != end:
            body.append(lines[i])
            i += 1
        i += 1  # skip END marker
        content = "\n".join(body)
        # `cat` output is followed by `echo ""`: exactly one newline to strip.
        if content.endswith("\n"):
            content = content[:-1]
        files[path] = content
    return files


@dataclass
class BundlePlan:
    write: Dict[str, str] = field(default_factory=dict)     # path -> backup content
    remove: List[str] = field(default_factory=list)          # added after the backup
    rejected: List[str] = field(default_factory=list)        # outside the allowlist
    diff: ConfigDiff = field(default_factory=ConfigDiff)


def plan_bundle(backup_text: str, live_text: str, family: str) -> BundlePlan:
    backup, live = parse_bundle(backup_text), parse_bundle(live_text)
    plan = BundlePlan()
    for path in sorted(set(backup) | set(live)):
        if not path_allowed(path, family):
            plan.rejected.append(path)
            continue
        b, l = backup.get(path), live.get(path)
        if b == l:
            continue
        section = DiffSection(path)
        if b is None:
            plan.remove.append(path)
            section.title = f"{path} — added after the backup, will be removed"
            section.lines = [DiffLine("-", t) for t in l.split("\n")]
        else:
            plan.write[path] = b
            if l is None:
                section.title = f"{path} — missing now, will be recreated"
                section.lines = [DiffLine("+", t) for t in b.split("\n")]
            else:
                for line in difflib.unified_diff(l.split("\n"), b.split("\n"), lineterm="", n=2):
                    if line.startswith(("---", "+++")):
                        continue
                    if line.startswith("@@"):
                        section.lines.append(DiffLine(" ", line))
                    else:
                        section.lines.append(DiffLine(line[0] if line[0] in "+-" else " ", line[1:]))
        plan.diff.sections.append(section)
    if plan.rejected:
        plan.diff.skipped += [f"{p} (outside the restorable paths for {family})" for p in plan.rejected]
    return plan


def matches(backup_text: str, live_text: str, family: str) -> bool:
    return not plan_bundle(backup_text, live_text, family).diff.sections


# --------------------------------------------------------------------------- #
#  Shell generation (all paths are allowlisted and shell-quoted)              #
# --------------------------------------------------------------------------- #

def _touched(plan: BundlePlan) -> List[str]:
    return sorted(set(plan.write) | set(plan.remove))


def _matches_pattern(paths: List[str], pattern: str) -> bool:
    return any(fnmatch.fnmatchcase(p, pattern) for p in paths)


def validate_commands(plan: BundlePlan, family: str) -> List[str]:
    touched = _touched(plan)
    return [cmd for _, pattern, cmd in FAMILY_SERVICES[family]["validate"] if _matches_pattern(touched, pattern)]


def reload_commands(plan: BundlePlan, family: str) -> List[str]:
    touched = _touched(plan)
    return [cmd for _, pattern, cmd in FAMILY_SERVICES[family]["reload"] if _matches_pattern(touched, pattern)]


def snapshot_command(plan: BundlePlan, workdir: str) -> str:
    """Save the current state of every touched path (content + which existed)."""
    q = shlex.quote
    paths = " ".join(q(p) for p in _touched(plan))
    return (
        f"mkdir -p {q(workdir)} && chmod 700 {q(workdir)} && : > {q(workdir + '/absent')} && "
        f"for f in {paths}; do if [ -e \"$f\" ]; then tar -cpf - \"$f\" 2>/dev/null; "
        f"else echo \"$f\" >> {q(workdir + '/absent')}; fi; done > {q(workdir + '/snapshot.tar')}"
    )


def revert_script(plan: BundlePlan, family: str, workdir: str) -> str:
    """Shell that puts every touched path back exactly as snapshotted."""
    q = shlex.quote
    reload = " ; ".join(reload_commands(plan, family)) or "true"
    return (
        f"cd / && tar -xpif {q(workdir + '/snapshot.tar')} 2>/dev/null; "
        f"while read -r f; do [ -n \"$f\" ] && rm -f \"$f\"; done < {q(workdir + '/absent')}; "
        f"{reload}"
    )


def write_command(path: str, content: str) -> str:
    """Replace a file's content, keeping owner/mode when it already exists."""
    q = shlex.quote
    b64 = base64.b64encode(content.encode()).decode()
    tmp = f"{path}.ngcorion-restore"
    return (
        f"printf %s {q(b64)} | base64 -d > {q(tmp)} && "
        f"if [ -e {q(path)} ]; then cat {q(tmp)} > {q(path)} && rm -f {q(tmp)}; "
        f"else mv {q(tmp)} {q(path)} && chmod 644 {q(path)}; fi"
    )


def remove_command(path: str) -> str:
    return f"rm -f {shlex.quote(path)}"


def arm_timer_command(workdir: str, minutes: int, revert: str) -> str:
    """Start the dead-man switch; prints its PID. Survives the SSH session."""
    q = shlex.quote
    body = f"sleep {int(minutes) * 60}; {revert}"
    return (
        f"printf %s {q(body)} > {q(workdir + '/revert.sh')} && "
        f"nohup sh {q(workdir + '/revert.sh')} >/dev/null 2>&1 & echo $!"
    )


def disarm_command(pid: Optional[str], workdir: str) -> str:
    q = shlex.quote
    kill = f"kill {int(pid)} 2>/dev/null; pkill -P {int(pid)} 2>/dev/null; " if pid and str(pid).isdigit() else ""
    return f"{kill}rm -rf {q(workdir)}"
