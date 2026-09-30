"""
Management-access risk of a restore.

Restoring an older configuration can cut off the very session that applies it
(and every operator): an admin trusted-hosts list, an SSH port, an AllowUsers
line. Changes that touch management access are flagged as warnings; when the
restored configuration provably excludes the connection NGCorion is using,
the finding is a "lockout".
"""
import ipaddress
import re
from typing import Dict, List, Optional

from app.modules.backup.restore.config_tree import ConfigDiff, parse_fortios

_FORTI_MGMT = re.compile(
    r"config system admin|trusthost|admin-sport|admin-port|admin-ssh-port|allowaccess|"
    r"config system interface|local-in-policy|admin-https|admin-ssh",
    re.I,
)
_CISCO_MGMT = re.compile(
    r"^(line vty|ip ssh|aaa |username |ip access-list|access-list|access-class|transport input|"
    r"interface |ip address|management)",
    re.I,
)
_SSHD_MGMT = re.compile(
    r"^\s*(port|listenaddress|allowusers|allowgroups|denyusers|denygroups|permitrootlogin|"
    r"passwordauthentication|pubkeyauthentication|usepam|authenticationmethods)\b",
    re.I,
)


def _risk(severity: str, message: str) -> Dict[str, str]:
    return {"severity": severity, "message": message}


def _flagged_lines(diff: ConfigDiff, pattern: re.Pattern, use_title: bool = True) -> int:
    count = 0
    for section in diff.sections:
        title_hit = use_title and pattern.search(section.title)
        for line in section.lines:
            if line.op in "+-" and (title_hit or pattern.search(line.text.strip())):
                count += 1
    return count


def fortios_risks(diff: ConfigDiff, backup_text: str, username: str,
                  source_ip: Optional[str], ssh_port: int) -> List[Dict[str, str]]:
    risks: List[Dict[str, str]] = []
    n = _flagged_lines(diff, _FORTI_MGMT)
    if n:
        risks.append(_risk("warning", f"{n} changed line(s) affect management access "
                                      "(admin accounts, trusted hosts, admin ports or interface access)."))

    root = parse_fortios(backup_text)
    admin_scope = _find_scope(root, "config system admin")
    if admin_scope is not None:
        entry = admin_scope.children.get(f'edit "{username}"') or admin_scope.children.get(f"edit {username}")
        if entry is None:
            risks.append(_risk("lockout", f'The account "{username}" used for this connection does not '
                                          "exist in the backup; NGCorion will not be able to log back in."))
        elif source_ip:
            nets = []
            for key, node in entry.children.items():
                if key.startswith("set trusthost"):
                    parts = node.line.split()
                    if len(parts) >= 4:
                        try:
                            nets.append(ipaddress.ip_network(f"{parts[2]}/{parts[3]}", strict=False))
                        except ValueError:
                            pass
            if nets and not any(n.prefixlen == 0 for n in nets):
                try:
                    ip = ipaddress.ip_address(source_ip)
                    if not any(ip in n for n in nets):
                        shown = ", ".join(str(n) for n in nets)
                        risks.append(_risk("lockout", f"The backup restricts \"{username}\" to {shown}, but "
                                                      f"NGCorion connects from {source_ip}. After this restore "
                                                      "NGCorion may lose SSH access."))
                except ValueError:
                    pass

    global_scope = _find_scope(root, "config system global")
    if global_scope is not None:
        port_node = global_scope.children.get("set admin-ssh-port")
        if port_node is not None:
            parts = port_node.line.split()
            if len(parts) >= 3 and parts[2].isdigit() and int(parts[2]) != ssh_port:
                risks.append(_risk("lockout", f"The backup moves SSH to port {parts[2]}; this connection uses {ssh_port}."))
    return risks


def _find_scope(node, key):
    """Depth-first search for a config scope (handles `config global` wrapping)."""
    if key in node.children:
        return node.children[key]
    for child in node.children.values():
        if child.line.startswith(("config global", "config vdom", "edit ")):
            found = _find_scope(child, key)
            if found is not None:
                return found
    return None


def cisco_risks(diff: ConfigDiff, backup_text: str, username: str) -> List[Dict[str, str]]:
    risks: List[Dict[str, str]] = []
    n = _flagged_lines(diff, _CISCO_MGMT)
    if n:
        risks.append(_risk("warning", f"{n} changed line(s) affect management access "
                                      "(VTY lines, SSH, AAA, local users, ACLs or interface addresses)."))
    if username and not re.search(rf"^username {re.escape(username)}\b", backup_text or "", re.M) \
            and re.search(r"^username ", backup_text or "", re.M):
        risks.append(_risk("lockout", f'The account "{username}" used for this connection does not exist '
                                      "in the backup; local login may fail after the restore."))
    return risks


def bundle_risks(diff: ConfigDiff, files_after: Dict[str, str], family: str,
                 username: str, ssh_port: int) -> List[Dict[str, str]]:
    if family != "linux":
        return []
    risks: List[Dict[str, str]] = []
    touched = [s for s in diff.sections if "/etc/ssh/" in s.title or "/etc/pam.d/" in s.title
               or "/etc/security/" in s.title]
    if touched:
        risks.append(_risk("warning", f"{len(touched)} changed file(s) affect SSH login "
                                      "(sshd configuration, PAM or account security policy)."))
    sshd = files_after.get("/etc/ssh/sshd_config", "")
    for line in sshd.splitlines():
        if not _SSHD_MGMT.match(line):
            continue
        parts = line.split()
        key = parts[0].lower()
        if key == "port" and len(parts) > 1 and parts[1].isdigit() and int(parts[1]) != ssh_port:
            risks.append(_risk("lockout", f"The backup's sshd listens on port {parts[1]}; this connection uses {ssh_port}."))
        if key == "allowusers" and username not in [p.split("@")[0] for p in parts[1:]]:
            risks.append(_risk("lockout", f'The backup\'s AllowUsers does not include "{username}".'))
        if key == "denyusers" and username in [p.split("@")[0] for p in parts[1:]]:
            risks.append(_risk("lockout", f'The backup\'s DenyUsers blocks "{username}".'))
    return risks
