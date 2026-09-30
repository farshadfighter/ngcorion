"""
Configuration Generation Templates

Turns one design component's relationships into the interface configuration
commands for a real device, in the dialect of the device family that will
run them. Only cisco and fortinet are covered: they are the two families
whose hardening executors expose a multi-command `execute_commands()` (see
app/modules/{cisco,fortinet}/hardening/ssh_executor.py) - the others
(linux/apache/mongodb) only run single shell commands, which isn't a fit for
"push this generated interface config".
"""
import re

from app.models import DesignComponent, DesignRelationship

# Every value below ends up as a line typed into a live device's CLI. Labels,
# interface names and VLANs are free text (and labels can originate from
# discovered asset names), so a newline in any of them would smuggle extra
# commands onto the device, and a '"' would break out of a FortiOS quoted
# string. Interfaces and VLANs must match a strict shape; free text is
# reduced to printable characters with quoting metacharacters removed.
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._:-]{0,49}$")
_UNSAFE_TEXT_RE = re.compile(r'[\x00-\x1f\x7f"\\?]')


def _safe_text(value) -> str:
    return _UNSAFE_TEXT_RE.sub("", str(value or "")).strip()[:100]


def _safe_vlan(value):
    text = str(value or "").strip()
    if text.isdigit() and 1 <= int(text) <= 4094:
        return int(text)
    return None


def _interface_for_component(relationship: DesignRelationship, component_id: int):
    if relationship.source_component_id == component_id:
        name = relationship.source_interface
    else:
        name = relationship.destination_interface
    name = (name or "").strip()
    return name if _INTERFACE_RE.match(name) else None


def _other_component(relationship: DesignRelationship, component_id: int):
    if relationship.source_component_id == component_id:
        return relationship.destination_component
    return relationship.source_component


def generate_cisco_commands(component: DesignComponent, relationships: list[DesignRelationship]) -> list[str]:
    lines = []
    for relationship in relationships:
        interface = _interface_for_component(relationship, component.id)
        if not interface:
            continue
        other = _other_component(relationship, component.id)
        vlan = _safe_vlan(relationship.vlan)
        lines.append(f"interface {interface}")
        if other:
            lines.append(f" description Link to {_safe_text(other.label)}")
        if vlan:
            lines.append(" switchport mode access")
            lines.append(f" switchport access vlan {vlan}")
        lines.append(" no shutdown")
    return lines or ["! No relationships to configure for this component"]


def generate_fortinet_commands(component: DesignComponent, relationships: list[DesignRelationship]) -> list[str]:
    lines = []
    for relationship in relationships:
        interface = _interface_for_component(relationship, component.id)
        if not interface:
            continue
        other = _other_component(relationship, component.id)
        vlan = _safe_vlan(relationship.vlan)
        lines.append("config system interface")
        lines.append(f'edit "{interface}"')
        if other:
            lines.append(f'set alias "Link to {_safe_text(other.label)}"')
        if vlan:
            lines.append(f"set vlanid {vlan}")
        lines.append("set status up")
        lines.append("next")
        lines.append("end")
    return lines or ["# No relationships to configure for this component"]


GENERATORS = {
    "cisco": generate_cisco_commands,
    "fortinet": generate_fortinet_commands,
}


def generate_commands(component: DesignComponent, relationships: list[DesignRelationship], device_type: str) -> list[str]:
    generator = GENERATORS.get(device_type)
    if generator is None:
        return [f"# Configuration generation is not implemented yet for device type '{_safe_text(device_type)}'."]
    return generator(component, relationships)
