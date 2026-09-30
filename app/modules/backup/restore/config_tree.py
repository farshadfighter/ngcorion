"""
Configuration trees for Cisco IOS and FortiOS, and the diff between two of them.

A restore is computed as "what must change on the LIVE device so its
configuration equals the BACKUP": the same diff drives the preview the operator
reviews, the CLI commands that are sent, and the post-restore verification
(an empty diff means the device now matches the backup).

Both parsers normalise away what legitimately differs between two captures of
an unchanged device (timestamps, prompts, byte counts) so an unchanged device
diffs as empty.
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
#  Shared diff model                                                          #
# --------------------------------------------------------------------------- #


@dataclass
class DiffLine:
    op: str          # "+" set / added on the device, "-" removed, " " context
    text: str


@dataclass
class DiffSection:
    title: str
    lines: List[DiffLine] = field(default_factory=list)


@dataclass
class ConfigDiff:
    sections: List[DiffSection] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)   # things compared but not restorable

    @property
    def added(self) -> int:
        return sum(1 for s in self.sections for l in s.lines if l.op == "+")

    @property
    def removed(self) -> int:
        return sum(1 for s in self.sections for l in s.lines if l.op == "-")

    @property
    def is_empty(self) -> bool:
        return not any(l.op in "+-" for s in self.sections for l in s.lines)


class Node:
    """An ordered config tree node. ``children`` keys are normalised lines."""

    __slots__ = ("line", "children")

    def __init__(self, line: str = ""):
        self.line = line
        self.children: Dict[str, "Node"] = {}

    def child(self, key: str, line: str) -> "Node":
        node = self.children.get(key)
        if node is None:
            node = Node(line)
            self.children[key] = node
        return node

    def flatten(self, depth: int = 0) -> List[Tuple[int, str]]:
        out = []
        for node in self.children.values():
            out.append((depth, node.line))
            out.extend(node.flatten(depth + 1))
        return out


# --------------------------------------------------------------------------- #
#  FortiOS                                                                    #
# --------------------------------------------------------------------------- #

# Keys the restore itself toggles (revert mode) - never part of the comparison.
_FORTI_VOLATILE_SET_KEYS = {"cfg-save", "cfg-revert-timeout"}
# Tables whose entry order is significant (evaluated top-down).
_FORTI_ORDERED_TABLE = re.compile(r"policy|local-in|shaping|acl", re.I)
_PROMPT_RE = re.compile(r"^\S+(?: \([^)]*\))? [#$]\s*(?:show .*)?$")


def _forti_lines(text: str) -> List[str]:
    lines = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or _PROMPT_RE.match(line):
            continue
        if line.lower().startswith("show full-configuration"):
            continue
        lines.append(line)
    return lines


def _forti_key(line: str) -> str:
    parts = line.split(None, 2)
    verb = parts[0]
    if verb in ("set", "unset") and len(parts) > 1:
        return f"set {parts[1]}"
    return line


def parse_fortios(text: str) -> Node:
    """Parse ``show full-configuration`` output into a tree.

    ``config X ... end`` and ``edit Y ... next`` open child scopes; repeated
    scopes at one level (multi-VDOM output repeats ``config vdom``) merge.
    """
    root = Node()
    stack = [root]
    for line in _forti_lines(text):
        verb = line.split(None, 1)[0]
        if verb in ("config", "edit"):
            node = stack[-1].child(line, line)
            stack.append(node)
        elif verb in ("end", "next"):
            if len(stack) > 1:
                stack.pop()
        elif verb == "set":
            key = _forti_key(line)
            if key.split(None, 1)[1] in _FORTI_VOLATILE_SET_KEYS:
                continue
            stack[-1].children[key] = Node(line)
        # anything else (e.g. stray output) is not configuration
    return root


def _is_enc(line: str) -> bool:
    parts = line.split(None, 3)
    return len(parts) >= 3 and parts[2] == "ENC"


def _forti_body(node: Node) -> List[str]:
    """Commands that recreate ``node``'s children from scratch."""
    cmds = []
    for child in node.children.values():
        verb = child.line.split(None, 1)[0]
        if verb == "set":
            cmds.append(child.line)
        else:
            cmds.append(child.line)
            cmds.extend(_forti_body(child))
            cmds.append("next" if verb == "edit" else "end")
    return cmds


def _forti_clear(node: Node) -> List[str]:
    """Commands that empty a scope present only on the live device."""
    cmds = []
    for key, child in node.children.items():
        verb = child.line.split(None, 1)[0]
        if verb == "set":
            cmds.append(f"unset {key.split(None, 1)[1]}")
        elif verb == "edit":
            cmds.append(f"delete {child.line.split(None, 1)[1]}")
        else:
            inner = _forti_clear(child)
            if inner:
                cmds += [child.line, *inner, "end"]
    return cmds


def _forti_moves(desired: List[str], current: List[str]) -> List[str]:
    """``move`` commands turning ``current`` edit order into ``desired``."""
    current = [c for c in current if c in desired]
    cmds = []
    for i, name in enumerate(desired):
        if i < len(current) and current[i] != name:
            cmds.append(f"move {name} before {current[i]}")
            current.remove(name)
            current.insert(i, name)
    return cmds


def _forti_diff(backup: Node, live: Node, path: List[str], diff: ConfigDiff) -> List[str]:
    cmds: List[str] = []
    title = " › ".join(path) or "(top level)"
    section: Optional[DiffSection] = None

    def mark(op: str, text: str):
        nonlocal section
        if section is None:
            section = DiffSection(title)
            diff.sections.append(section)
        section.lines.append(DiffLine(op, text))

    for key, b in backup.children.items():
        verb = b.line.split(None, 1)[0]
        l = live.children.get(key)
        if verb == "set":
            if l is None:
                cmds.append(b.line)
                mark("+", b.line)
            elif l.line != b.line:
                if _is_enc(b.line) and _is_enc(l.line):
                    diff.skipped.append(f"{title} › {key} (encrypted value, cannot be compared)")
                    continue
                cmds.append(b.line)
                mark("-", l.line)
                mark("+", b.line)
        elif l is None:
            body = _forti_body(b)
            closer = "next" if verb == "edit" else "end"
            cmds += [b.line, *body, closer]
            mark("+", b.line)
            for depth, text in b.flatten(1):
                mark("+", "    " * depth + text)
        else:
            inner = _forti_diff(b, l, path + [b.line], diff)
            if inner:
                cmds += [b.line, *inner, "next" if verb == "edit" else "end"]

    for key, l in live.children.items():
        if key in backup.children:
            continue
        verb = l.line.split(None, 1)[0]
        if verb == "set":
            cmds.append(f"unset {key.split(None, 1)[1]}")
            mark("-", l.line)
        elif verb == "edit":
            cmds.append(f"delete {l.line.split(None, 1)[1]}")
            mark("-", l.line)
            for depth, text in l.flatten(1):
                mark("-", "    " * depth + text)
        else:
            inner = _forti_clear(l)
            if inner:
                cmds += [l.line, *inner, "end"]
                mark("-", l.line)

    if path and path[-1].startswith("config ") and _FORTI_ORDERED_TABLE.search(path[-1]):
        desired = [k.split(None, 1)[1] for k in backup.children if k.startswith("edit ")]
        current = [k.split(None, 1)[1] for k in live.children if k.startswith("edit ") and k in backup.children]
        current += [n for n in desired if f"edit {n}" not in live.children]
        moves = _forti_moves(desired, current)
        if moves:
            cmds += moves
            for m in moves:
                mark("+", m)
    return cmds


def diff_fortios(backup_text: str, live_text: str) -> ConfigDiff:
    diff = ConfigDiff()
    diff.commands = _forti_diff(parse_fortios(backup_text), parse_fortios(live_text), [], diff)
    return diff


# --------------------------------------------------------------------------- #
#  Cisco IOS                                                                  #
# --------------------------------------------------------------------------- #

_CISCO_SKIP_PREFIXES = (
    "building configuration", "current configuration", "load for ", "time source is",
    "ntp clock-period",
)
# Blocks that cannot be replayed through the CLI from a running-config dump.
_CISCO_UNRESTORABLE = re.compile(r"^crypto pki certificate chain\b")
_CISCO_PROMPT_RE = re.compile(r"^[\w.\-]+(?:\([^)]*\))?[#>]\s*(?:show .*)?$")

# Settings that hold ONE value. When the backup's value differs, writing it
# replaces the live one in place - and the live line must never be `no`-ed:
# IOS ignores the trailing arguments of many `no` forms, so
# `no username admin privilege 15 secret 9 <old>` deletes the account the
# backup's line just re-created, and `no ip address ...` drops the
# management address. Matched by prefix; others fall back to _setting_id.
_CISCO_SINGLE_VALUE_HEADS = (
    "hostname", "description", "ip address", "ip default-gateway", "ip domain-name",
    "ip domain name", "clock timezone", "enable secret", "enable password",
    "snmp-server location", "snmp-server contact", "exec-timeout", "ip ssh version",
    "ip ssh time-out", "ip ssh authentication-retries", "logging buffered",
    "login block-for", "password", "transport input", "transport output",
    "access-class", "switchport mode", "switchport access vlan", "speed", "duplex", "mtu",
)
# Settings that are lists: each entry is independent, so a live entry the
# backup lacks is always removed.
_CISCO_MULTI_VALUE_HEADS = (
    "logging host", "ntp server", "ntp peer", "ip route", "snmp-server host",
    "snmp-server community", "ip name-server", "access-list", "permit", "deny",
    "remark", "ip dhcp excluded-address", "boot system", "neighbor", "network",
    "ip helper-address", "switchport trunk allowed vlan add",
)


def _setting_id(line: str) -> str:
    """What a line configures, independent of its value ('' for list entries)."""
    low = line.lower()
    for head in _CISCO_MULTI_VALUE_HEADS:
        if low == head or low.startswith(head + " "):
            return ""
    for head in _CISCO_SINGLE_VALUE_HEADS:
        if low == head or low.startswith(head + " "):
            return head
    toks = low.split()
    if toks and toks[0] == "no":
        toks = toks[1:]
    return " ".join(toks[:2]) if len(toks) >= 3 else (toks[0] if toks else "")


def _cisco_block(node: Node, depth: int) -> List[str]:
    """Commands recreating ``node`` (and its sub-mode) from scratch."""
    cmds = [" " * depth + node.line]
    if node.children:
        for child in node.children.values():
            cmds += _cisco_block(child, depth + 1)
        cmds.append(" " * depth + "exit")
    return cmds


def parse_cisco(text: str) -> Node:
    """Parse ``show running-config`` into an indentation tree."""
    root = Node()
    stack: List[Tuple[int, Node]] = [(-1, root)]
    lines = (text or "").splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i].rstrip()
        i += 1
        stripped = raw.strip()
        if not stripped or stripped.startswith("!") or _CISCO_PROMPT_RE.match(stripped):
            continue
        low = stripped.lower()
        if low.startswith(_CISCO_SKIP_PREFIXES) or low == "end" or low.startswith("show running-config"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if low.startswith("banner "):
            # banner <kind> ^C text ... ^C  -> one node holding the whole text
            parts = stripped.split(None, 2)
            body = parts[2] if len(parts) > 2 else ""
            text_lines = []
            delim = "^C"
            rest = body[len(delim):] if body.startswith(delim) else body
            if delim in rest:
                text_lines.append(rest.split(delim, 1)[0])
            else:
                text_lines.append(rest)
                while i < len(lines):
                    nxt = lines[i]
                    i += 1
                    if delim in nxt:
                        text_lines.append(nxt.split(delim, 1)[0])
                        break
                    text_lines.append(nxt)
            banner_text = "\n".join(text_lines).strip("\n")
            key = f"banner {parts[1]}"
            root.children[key] = Node(key)
            root.children[key].children["__text__"] = Node(banner_text)
            stack = [(-1, root)]
            continue
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        node = parent.child(stripped, stripped)
        stack.append((indent, node))
    return root


def _banner_commands(key: str, text: str) -> List[str]:
    delim = next((d for d in "^#%@~" if d not in text), "^")
    return [f"{key} {delim}", *text.split("\n"), delim]


def _cisco_diff(backup: Node, live: Node, path: List[str], diff: ConfigDiff) -> List[str]:
    title = " › ".join(path) or "global"
    section: Optional[DiffSection] = None

    def mark(op: str, text: str):
        nonlocal section
        if section is None:
            section = DiffSection(title)
            diff.sections.append(section)
        section.lines.append(DiffLine(op, text))

    adds: List[str] = []
    nested: List[str] = []
    removes: List[str] = []
    added_settings = set()

    for key, b in backup.children.items():
        if _CISCO_UNRESTORABLE.match(key):
            if key not in live.children or live.children[key].flatten() != b.flatten():
                diff.skipped.append(f"{key} (certificates are not restored)")
            continue
        l = live.children.get(key)
        if key.startswith("banner "):
            b_text = b.children["__text__"].line
            l_text = l.children["__text__"].line if l else None
            if b_text != l_text:
                adds += _banner_commands(key, b_text)
                if l_text is not None:
                    mark("-", f"{key} (current text)")
                mark("+", f"{key} (backup text)")
            continue
        if l is None:
            adds += _cisco_block(b, 0)
            mark("+", b.line)
            for depth, text in b.flatten(1):
                mark("+", " " * depth + text)
            setting = _setting_id(key)
            if setting:
                added_settings.add(setting)
        elif b.children or l.children:
            inner = _cisco_diff(b, l, path + [b.line], diff)
            if inner:
                nested += [b.line, *inner, "exit"]

    for key, l in live.children.items():
        if key in backup.children or _CISCO_UNRESTORABLE.match(key):
            continue
        if key.startswith("banner "):
            removes.append(f"no {key}")
            mark("-", key)
            continue
        if key.lower().startswith("no "):
            # "no X" on the live side is undone by the backup's positive form
            # (already queued above); "no no X" is not a command.
            mark("-", l.line)
            continue
        mark("-", l.line)
        for depth, text in l.flatten(1):
            mark("-", " " * depth + text)
        setting = _setting_id(key)
        if setting and setting in added_settings:
            continue  # replaced in place by the backup's value
        removes.append(f"no {key}")

    # Additions first so single-value settings are overwritten in place, then
    # sub-mode changes, then removals of what the backup does not have.
    return adds + nested + removes


def diff_cisco(backup_text: str, live_text: str) -> ConfigDiff:
    diff = ConfigDiff()
    diff.commands = _cisco_diff(parse_cisco(backup_text), parse_cisco(live_text), [], diff)
    return diff
