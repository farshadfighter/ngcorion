"""
Standard design templates.

Pre-built starting points for a new Design, based on Cisco SAFE (Secure
Architecture For Enterprise) - a defense-in-depth reference architecture
organized around "Places in the Network" (Internet Edge, Campus core/
distribution/access, Data Center) with explicit security segmentation
between them, rather than a flat network. Applying a template creates
DesignComponent/DesignRelationship rows on a design version exactly as if
they had been drawn on the canvas by hand - nothing here is a special case
the rest of the Design module needs to know about.

Only one template today (the enterprise campus - the reference design that
applies to the widest range of organizations), parameterized by scale
(access-layer switch count). The registry is structured to add more
(e.g. a SAFE branch or small-office variant) without changing the apply path.
"""
from dataclasses import dataclass
from typing import Any


@dataclass
class TemplateInfo:
    id: str
    name: str
    description: str
    framework: str


TEMPLATES: list[TemplateInfo] = [
    TemplateInfo(
        id="safe_enterprise_campus",
        name="Enterprise Campus (Cisco SAFE)",
        description=(
            "Segmented core/distribution/access campus with a firewalled "
            "Internet Edge + DMZ and an isolated Data Center zone, built on "
            "Cisco SAFE's defense-in-depth model: redundant paths at every "
            "layer, no zone reachable without crossing a firewall."
        ),
        framework="Cisco SAFE",
    ),
]

SCALES = {
    "small": {"access_switches": 1, "label": "Small (< 50 devices, single site)"},
    "medium": {"access_switches": 2, "label": "Medium (50-200 devices)"},
    "large": {"access_switches": 4, "label": "Large (200+ devices, multiple wings/floors)"},
}


def list_templates() -> list[TemplateInfo]:
    return TEMPLATES


def _component(key: str, component_type: str, label: str, x: float, y: float) -> dict[str, Any]:
    return {"_key": key, "component_type": component_type, "label": label, "pos_x": x, "pos_y": y}


def _link(source_key: str, dest_key: str, link_type: str = "ethernet") -> dict[str, Any]:
    return {"_source": source_key, "_destination": dest_key, "link_type": link_type}


def build_safe_enterprise_campus(scale: str = "medium") -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Component/relationship definitions for the SAFE enterprise campus
    template, scaled by access-layer switch count.

    Returns (components, relationships). Each component dict carries a local
    "_key" (not persisted) used only to wire up relationships before the
    real DesignComponent rows exist and get real ids - see
    DesignService.apply_template, which resolves _key/_source/_destination
    to real ids as it inserts each row.
    """
    access_count = SCALES.get(scale, SCALES["medium"])["access_switches"]

    # The access layer spreads out horizontally with access_count (see the
    # loop below); the Data Center column must stay clear of its rightmost
    # switch or the two zones visually overlap on the canvas at "large".
    access_x_start = 460 - (access_count - 1) * 90
    last_access_x = access_x_start + (access_count - 1) * 180
    dc_x = max(760, last_access_x + 200)

    components = [
        # --- Internet Edge: the only path in, and the first firewall -----
        _component("internet", "cloud", "Internet", 460, 20),
        _component("edge_router", "router", "Internet Edge Router", 460, 140),
        _component("edge_fw", "firewall", "Perimeter Firewall", 460, 260),

        # --- DMZ: public-facing services, isolated behind the perimeter FW
        _component("dmz_lb", "load_balancer", "DMZ Load Balancer", 200, 380),
        _component("dmz_server", "server", "DMZ Web Server", 200, 500),

        # --- Campus core: redundant backbone --------------------------
        _component("core_sw1", "switch", "Core Switch 1", 360, 380),
        _component("core_sw2", "switch", "Core Switch 2", 560, 380),

        # --- Distribution: redundant, dual-homed to both core switches -
        _component("dist_sw1", "switch", "Distribution Switch 1", 360, 500),
        _component("dist_sw2", "switch", "Distribution Switch 2", 560, 500),

        # --- Data Center: its own firewall segments it from the campus -
        _component("dc_fw", "firewall", "Data Center Firewall", dc_x, 380),
        _component("dc_sw", "switch", "Data Center Switch", dc_x, 500),
        _component("dc_server", "server", "Data Center Server", dc_x, 620),
    ]

    relationships = [
        _link("internet", "edge_router", "logical"),
        _link("edge_router", "edge_fw"),
        _link("edge_fw", "dmz_lb"),
        _link("dmz_lb", "dmz_server"),
        # Perimeter firewall dual-homed to both core switches - no single
        # point of failure between the internet edge and the campus core.
        _link("edge_fw", "core_sw1"),
        _link("edge_fw", "core_sw2"),
        _link("core_sw1", "core_sw2"),
        # Full-mesh core<->distribution, the classic SAFE/Cisco campus
        # redundant design: either core switch, or either distribution
        # switch, can fail alone without partitioning the network.
        _link("core_sw1", "dist_sw1"),
        _link("core_sw1", "dist_sw2"),
        _link("core_sw2", "dist_sw1"),
        _link("core_sw2", "dist_sw2"),
        _link("dist_sw1", "dist_sw2"),
        # Data center reachable only through its own firewall, itself
        # dual-homed to the core for the same no-single-point-of-failure
        # reason as the internet edge above.
        _link("core_sw1", "dc_fw"),
        _link("core_sw2", "dc_fw"),
        _link("dc_fw", "dc_sw"),
        _link("dc_sw", "dc_server"),
    ]

    # Access layer: each switch dual-homed to both distribution switches
    # (redundant, matching the rest of the campus), spread out
    # horizontally below distribution.
    for i in range(access_count):
        key = f"access_sw{i + 1}"
        components.append(_component(key, "switch", f"Access Switch {i + 1}", access_x_start + i * 180, 620))
        relationships.append(_link("dist_sw1", key))
        relationships.append(_link("dist_sw2", key))

    # One wireless AP off the first access switch - SAFE's wireless
    # capability is part of the access layer, not a separate zone.
    components.append(_component("wireless_ap", "wireless", "Wireless AP", access_x_start, 740))
    relationships.append(_link("access_sw1", "wireless_ap"))

    return components, relationships


def build_template(template_id: str, scale: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if template_id == "safe_enterprise_campus":
        return build_safe_enterprise_campus(scale)
    raise ValueError(f"Unknown template: {template_id}")
