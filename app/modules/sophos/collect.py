"""
Read-only collection for a Sophos Firewall audit through the XML API: one Get
per configuration entity, each stored as the XML the firewall returned.

Before storage, values that are secrets (passwords, SNMP community strings,
pre-shared keys, tokens) are replaced by "***", and user accounts are cut
down to name, type, profile and status.
"""

import re
from typing import Dict
from xml.etree import ElementTree as ET

from app.modules.benchmark.rules import assemble

ENTITIES = (
    "AdminSettings", "Zone", "LocalServiceACL", "OTPSettings", "User", "AdminAuthentication", "Hotfix",
    "PatternDownload", "SyslogServers", "Notification", "SNMPAgentConfiguration", "SNMPCommunity", "SNMPv3User",
    "FirewallRule", "ATP", "BackupRestore", "Time",
)
VERSION = "VERSION"
COMMANDS: Dict[str, str] = {VERSION: VERSION, **{e: f"GET:{e}" for e in ENTITIES}}
NO_RECORDS = "<Records count=\"0\" />"

# Tags that hold a secret end in one of these words ("EncryptionPassword",
# "CommunityString"); settings about secrets ("PasswordComplexityCheck",
# "MinimumPasswordLengthValue") do not and are kept.
_SECRET_WORDS = r"(?:password|passphrase|secret|psk|presharedkey|token|communitystring|privatekey|apikey)"
_SECRET_TAG = re.compile(_SECRET_WORDS + r"$", re.I)
_USER_KEEP = ("Username", "Name", "UserType", "Profile", "Status", "Group")


def redact_element(el: ET.Element) -> ET.Element:
    for node in el.iter():
        if _SECRET_TAG.search(node.tag) and (node.text or "").strip():
            node.text = "***"
            node.attrib.pop("hashform", None)
    return el


def slim_user(el: ET.Element) -> ET.Element:
    out = ET.Element("User")
    for tag in _USER_KEEP:
        child = el.find(tag)
        if child is not None:
            ET.SubElement(out, tag).text = child.text
    return out


def entity_text(entity: str, elements) -> str:
    if not elements:
        return NO_RECORDS
    parts = []
    for el in elements:
        el = slim_user(el) if entity == "User" else redact_element(el)
        el.attrib.pop("transactionid", None)
        ET.indent(el, space="  ")
        parts.append(ET.tostring(el, encoding="unicode"))
    return "\n".join(parts)


_TEXT_SECRET = re.compile(r"(<(\w*" + _SECRET_WORDS + r")(?:\s[^>]*)?>)([^<]+)(</\2>)", re.I)


def redact(dump: str) -> str:
    """Second line of defence on the stored text."""
    return _TEXT_SECRET.sub(lambda m: m.group(1) + ("***" if m.group(3).strip() else m.group(3)) + m.group(4), dump)


def collect(conn) -> str:
    out = {VERSION: conn.run(COMMANDS[VERSION])}
    if out[VERSION].startswith(("API_ERROR", "CMD_ERROR")):
        return assemble(out)
    out.update({entity: conn.run(COMMANDS[entity]) for entity in ENTITIES})
    return assemble(out)
