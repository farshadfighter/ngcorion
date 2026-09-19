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
from app.models import DesignComponent, DesignRelationship


def _interface_for_component(relationship: DesignRelationship, component_id: int):
    if relationship.source_component_id == component_id:
        return relationship.source_interface
    return relationship.destination_interface


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
        lines.append(f"interface {interface}")
        if other:
            lines.append(f" description Link to {other.label}")
        if relationship.vlan:
            lines.append(" switchport mode access")
            lines.append(f" switchport access vlan {relationship.vlan}")
        lines.append(" no shutdown")
    return lines or ["! No relationships to configure for this component"]


def generate_fortinet_commands(component: DesignComponent, relationships: list[DesignRelationship]) -> list[str]:
    lines = []
    for relationship in relationships:
        interface = _interface_for_component(relationship, component.id)
        if not interface:
            continue
        other = _other_component(relationship, component.id)
        lines.append("config system interface")
        lines.append(f'edit "{interface}"')
        if other:
            lines.append(f'set alias "Link to {other.label}"')
        if relationship.vlan:
            lines.append(f"set vlanid {relationship.vlan}")
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
        return [f"# Configuration generation is not implemented yet for device type '{device_type}'."]
    return generator(component, relationships)
