"""
The Sophos connection used by the benchmark engine, and its configuration
changes.

Collection scripts are "VERSION" and "GET:<Entity>". Hardening statements
start with "SFOS:" and change configuration through the XML API the way the
web admin does: the current object is read, only the named fields are
changed, and the object is sent back with Set operation="update" -
everything else in it stays as it was.

    SFOS:set AdminSettings LoginSecurity BlockLogin=Enable BlockLoginSettings/UnsucccessfulAttempt=5
    SFOS:set Hotfix - AllowAutoInstallOfHotFixes=Enable
    SFOS:zone type=WAN ApplianceAccess/AdminServices/HTTPS=Disable
    SFOS:each SyslogServers EnableSecureConnection=Enable
    SFOS:rules-log
    SFOS:check SOPHOS-1.6

"SFOS:check" collects again and evaluates the benchmark rule, so
verification is the audit itself.
"""

import shlex
from copy import deepcopy
from typing import List, Tuple
from xml.etree import ElementTree as ET

from .api import SophosAPI, SophosAPIError, child_path, split_assignment, strip_transaction
from .collect import NO_RECORDS, VERSION, entity_text

PREFIX = "SFOS:"


def _assign(el: ET.Element, assignments: List[Tuple[str, str]], create: bool = True) -> bool:
    """Apply path=value pairs; True when something changed. Without create,
    fields this firmware does not have are left out rather than invented."""
    changed = False
    for path, value in assignments:
        node = child_path(el, path, create=create)
        if node is None:
            continue
        if (node.text or "").strip() != value:
            node.text = value
            changed = True
    return changed


def _parse(words: List[str]) -> List[Tuple[str, str]]:
    return [split_assignment(w) for w in words]


class SophosConnection:
    def __init__(self, api: SophosAPI):
        self.api = api
        self.ip = api.host

    # ── engine contract ──
    def run(self, script: str) -> str:
        try:
            return self._do(script)
        except Exception as exc:  # noqa: BLE001 - reported per section / per statement
            return f"API_ERROR: {str(exc)[:300]}"

    def execute(self, script: str) -> str:
        return self._do(script)

    def _do(self, script: str) -> str:
        if script == VERSION:
            return f"APIVersion={self.api.login()}"
        if script.startswith("GET:"):
            entity = script[4:]
            return entity_text(entity, self.api.get(entity)) or NO_RECORDS
        if script.startswith(PREFIX):
            return self._statement(shlex.split(script[len(PREFIX):]))
        raise SophosAPIError(f"unknown Sophos operation {script[:60]!r}")

    # ── edits ──
    def _statement(self, words: List[str]) -> str:
        if not words:
            raise SophosAPIError("empty Sophos statement")
        op, args = words[0], words[1:]
        if op == "check":
            return self.check(args[0])
        if op == "set":
            return self.set(args[0], args[1], _parse(args[2:]))
        if op == "zone":
            return self.zone(args[0], _parse(args[1:]))
        if op == "each":
            return self.each(args[0], _parse(args[1:]))
        if op == "rules-log":
            return self.rules_log()
        raise SophosAPIError(f"unknown Sophos edit '{op}'")

    def set(self, entity: str, section: str, assignments: List[Tuple[str, str]]) -> str:
        """A singleton entity (AdminSettings, Hotfix, ...); with a section,
        only that part is sent back, as the web admin does."""
        found = self.api.get(entity)
        if len(found) != 1:
            raise SophosAPIError(f"{entity}: expected one object, the firewall returned {len(found)}")
        current = strip_transaction(found[0])
        if section == "-":
            payload, target = current, current
        else:
            part = current.find(section)
            if part is None:
                raise SophosAPIError(f"{entity} has no {section} on this firmware")
            payload = ET.Element(entity)
            target = deepcopy(part)
            payload.append(target)
        if not _assign(target, assignments):
            return f"{entity}{'' if section == '-' else '/' + section} already compliant"
        return f"{entity}: {self.api.set(payload)}"

    def zone(self, selector: str, assignments: List[Tuple[str, str]]) -> str:
        key, _, value = selector.partition("=")
        zones = [z for z in self.api.get("Zone")
                 if (key == "type" and (z.findtext("Type") or "").upper() == value.upper())
                 or (key == "name" and z.findtext("Name") == value)]
        if not zones:
            raise SophosAPIError(f"no zone matches {selector}")
        changed = []
        for z in zones:
            el = strip_transaction(z)
            if _assign(el, assignments, create=False):
                self.api.set(el)
                changed.append(el.findtext("Name"))
        return f"zones changed: {', '.join(changed) or 'none needed'}"

    def each(self, entity: str, assignments: List[Tuple[str, str]]) -> str:
        changed = []
        for obj in self.api.get(entity):
            el = strip_transaction(obj)
            if _assign(el, assignments, create=False):
                self.api.set(el)
                changed.append(el.findtext("Name") or "?")
        return f"{entity} changed: {', '.join(changed) or 'none needed'}"

    def rules_log(self) -> str:
        """Turn on logging for every rule that allows traffic."""
        changed = []
        for rule in self.api.get("FirewallRule"):
            el = strip_transaction(rule)
            policy = el.find("NetworkPolicy") if el.find("NetworkPolicy") is not None else el.find("UserPolicy")
            if policy is None or (policy.findtext("Action") or "").lower() != "accept":
                continue
            if _assign(policy, [("LogTraffic", "Enable")]):
                self.api.set(el)
                changed.append(el.findtext("Name"))
        return f"logging turned on for: {', '.join(changed) or 'none needed'}"

    def check(self, rule_id: str) -> str:
        from app.modules.benchmark.rules import evaluate
        from . import rules as R
        from .collect import collect
        dump = collect(self)
        rule = next((r for r in R.rules_for(dump) if r.id == rule_id), None)
        if rule is None:
            raise SophosAPIError(f"unknown rule {rule_id}")
        finding = evaluate(dump, [rule])["findings"][0]
        return f"{'PASS' if finding['status'] == 'pass' else 'FAIL'}: {finding['evidence']}"
