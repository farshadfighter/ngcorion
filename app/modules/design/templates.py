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

Two templates, each parameterized by scale: the enterprise campus (the
reference design that applies to the widest range of organizations, scaled by
access-layer switch count) and the data center with its storage network (SAN),
scaled by hypervisor count. The registry is structured to add more (e.g. a SAFE
branch or small-office variant) without changing the apply path.
"""
from dataclasses import dataclass
from typing import Any


@dataclass
class TemplateInfo:
    """A standard design template: id, name, description and the framework it follows."""
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
    TemplateInfo(
        id="safe_data_center_san",
        name="Data Center with SAN (Cisco SAFE)",
        description=(
            "A firewalled data center: a redundant firewall and switch pair, "
            "hypervisors dual-homed to both, and a separate storage network with "
            "two SAN fabrics (A and B) that only the hypervisors reach, plus an "
            "isolated management network with a jump host."
        ),
        framework="Cisco SAFE",
    ),
    TemplateInfo(
        id="safe_branch_wan",
        name="Branch with WAN (Cisco SAFE)",
        description=(
            "A branch joined to the organisation over MPLS and SD-WAN, with the "
            "Internet and an LTE backup: two WAN routers, a branch firewall "
            "pair behind both, a redundant switch pair and dual-homed access "
            "switches, so no single circuit, router or switch cuts the branch "
            "off."
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


# Every zone a component can belong to, in the order they should list in a
# legend - matches the "Places in the Network" SAFE groups this shape is
# built from. Used to draw a labeled background band behind each zone's
# nodes on the Suggested Design canvas (see app/modules/design/suggestion.py
# and front/src/components/DesignConfiguration/SuggestedDesign.jsx) so the
# zoning the layout already encodes in y/x position is also visible at a
# glance, not just implied by where boxes happen to sit.
ZONES: dict[str, dict[str, str]] = {
    "wan_edge": {"label": "WAN Edge", "color": "#f0fdfa"},
    "internet_edge": {"label": "Internet Edge", "color": "#eef2ff"},
    "dmz": {"label": "DMZ", "color": "#fff7ed"},
    "core": {"label": "Core", "color": "#eef6ff"},
    "distribution": {"label": "Distribution", "color": "#ecfdf5"},
    "access": {"label": "Access", "color": "#f0fdf4"},
    "data_center": {"label": "Data Center", "color": "#fdf4ff"},
    "storage": {"label": "Storage network (SAN)", "color": "#fefce8"},
    "management": {"label": "Management", "color": "#f1f5f9"},
}


def _component(key: str, component_type: str, label: str, x: float, y: float, zone: str) -> dict[str, Any]:
    return {"_key": key, "component_type": component_type, "label": label, "pos_x": x, "pos_y": y, "zone": zone}


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
    # Layer gap is 170px (was 120px) and the DMZ/Core columns sit further
    # apart - both give the smoothstep edges (see SuggestedDesign.jsx /
    # DesignCanvas.jsx) room to route around node boxes instead of through
    # them, which is what made the old, tighter layout look tangled.
    access_x_start = 480 - (access_count - 1) * 100
    last_access_x = access_x_start + (access_count - 1) * 200
    dc_x = max(880, last_access_x + 240)

    components = [
        # --- Internet Edge: the only path in, and the first firewall -----
        _component("internet", "cloud", "Internet", 480, 20, "internet_edge"),
        _component("edge_router", "router", "Internet Edge Router", 480, 180, "internet_edge"),
        _component("edge_fw", "firewall", "Perimeter Firewall", 480, 340, "internet_edge"),

        # --- DMZ: public-facing services, isolated behind the perimeter FW
        _component("dmz_lb", "load_balancer", "DMZ Load Balancer", 140, 510, "dmz"),
        _component("dmz_server", "server", "DMZ Web Server", 140, 680, "dmz"),

        # --- Campus core: redundant backbone --------------------------
        _component("core_sw1", "switch", "Core Switch 1", 400, 510, "core"),
        _component("core_sw2", "switch", "Core Switch 2", 640, 510, "core"),

        # --- Distribution: redundant, dual-homed to both core switches -
        _component("dist_sw1", "switch", "Distribution Switch 1", 400, 680, "distribution"),
        _component("dist_sw2", "switch", "Distribution Switch 2", 640, 680, "distribution"),

        # --- Data Center: its own firewall segments it from the campus -
        _component("dc_fw", "firewall", "Data Center Firewall", dc_x, 510, "data_center"),
        _component("dc_sw", "switch", "Data Center Switch", dc_x, 680, "data_center"),
        _component("dc_server", "server", "Data Center Server", dc_x, 850, "data_center"),
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
        components.append(_component(key, "switch", f"Access Switch {i + 1}", access_x_start + i * 200, 850, "access"))
        relationships.append(_link("dist_sw1", key))
        relationships.append(_link("dist_sw2", key))

    # One wireless AP off the first access switch - SAFE's wireless
    # capability is part of the access layer, not a separate zone.
    components.append(_component("wireless_ap", "wireless", "Wireless AP", access_x_start, 1020, "access"))
    relationships.append(_link("access_sw1", "wireless_ap"))

    return components, relationships


# Hypervisors per scale in the data center template (the access-switch count is the campus's).
DC_HOSTS = {"small": 2, "medium": 3, "large": 4}


def build_safe_data_center_san(scale: str = "medium") -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The SAFE data center with its storage network: reached from the campus core only through a
    redundant firewall pair; hypervisors dual-homed to a redundant switch pair; storage on its own two
    SAN fabrics (A and B), reached by the hypervisors only and by every one over both fabrics, so no
    switch, cable or port is a single point of failure for the data; management on its own network
    behind the firewall, reached through a jump host."""
    hosts = DC_HOSTS.get(scale, DC_HOSTS["medium"])
    x0 = 480 - (hosts - 1) * 110
    components = [
        _component("campus_core", "router", "Campus Core", 480, 20, "core"),
        _component("dc_fw1", "firewall", "Data Center Firewall 1", 360, 180, "data_center"),
        _component("dc_fw2", "firewall", "Data Center Firewall 2", 600, 180, "data_center"),
        _component("dc_sw1", "switch", "Data Center Switch 1", 360, 350, "data_center"),
        _component("dc_sw2", "switch", "Data Center Switch 2", 600, 350, "data_center"),
        _component("san_a", "switch", "SAN Fabric A Switch", 360, 690, "storage"),
        _component("san_b", "switch", "SAN Fabric B Switch", 600, 690, "storage"),
        _component("storage", "storage", "Storage Array", 360, 860, "storage"),
        _component("backup", "storage", "Backup Storage", 600, 860, "storage"),
        _component("mgmt_sw", "switch", "Management Switch", 980, 350, "management"),
        _component("jump", "server", "Jump Host", 980, 520, "management"),
    ]
    relationships = [
        _link("campus_core", "dc_fw1"),
        _link("campus_core", "dc_fw2"),
        _link("dc_fw1", "dc_fw2"),
        _link("dc_fw1", "dc_sw1"),
        _link("dc_fw1", "dc_sw2"),
        _link("dc_fw2", "dc_sw1"),
        _link("dc_fw2", "dc_sw2"),
        _link("dc_sw1", "dc_sw2"),
        # storage on both fabrics; the fabrics are not linked to each other (A and B stay apart)
        _link("storage", "san_a", "fiber"),
        _link("storage", "san_b", "fiber"),
        _link("backup", "san_a", "fiber"),
        _link("backup", "san_b", "fiber"),
        # management only behind the firewall pair
        _link("dc_fw1", "mgmt_sw"),
        _link("dc_fw2", "mgmt_sw"),
        _link("mgmt_sw", "jump"),
    ]
    for i in range(hosts):
        key = f"host{i + 1}"
        components.append(_component(key, "hypervisor", f"Hypervisor {i + 1}", x0 + i * 220, 520, "data_center"))
        for upstream in ("dc_sw1", "dc_sw2"):
            relationships.append(_link(upstream, key))
        for fabric in ("san_a", "san_b"):
            relationships.append(_link(key, fabric, "fiber"))
    return components, relationships


def build_safe_branch_wan(scale: str = "medium") -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The SAFE branch with its WAN: MPLS and an LTE backup on one router, the SD-WAN overlay and the
    Internet on the other, so one circuit or router never cuts the branch off from the organisation or
    the Internet; a branch firewall pair
    behind both routers, so nothing from a WAN or the Internet reaches the branch unfiltered; a
    redundant switch pair with every access switch dual-homed. The external networks are design
    components of their own kinds (mpls, sdwan, internet, lte), as drawn on the topology, and the
    shape passes Architecture Validation's checks (tests/test_design_templates.py)."""
    access = SCALES.get(scale, SCALES["medium"])["access_switches"]
    components = [
        _component("mpls", "mpls", "MPLS", 220, 20, "wan_edge"),
        _component("sdwan", "sdwan", "SD-WAN", 560, 20, "wan_edge"),
        _component("internet", "internet", "Internet", 780, 20, "wan_edge"),
        _component("lte", "lte", "LTE / 4G Backup", 0, 20, "wan_edge"),
        _component("wan_r1", "router", "WAN Router 1 (MPLS, LTE)", 300, 180, "wan_edge"),
        _component("wan_r2", "router", "WAN Router 2 (SD-WAN, Internet)", 660, 180, "wan_edge"),
        _component("br_fw1", "firewall", "Branch Firewall 1", 360, 340, "wan_edge"),
        _component("br_fw2", "firewall", "Branch Firewall 2", 600, 340, "wan_edge"),
        _component("br_sw1", "switch", "Branch Switch 1", 360, 500, "core"),
        _component("br_sw2", "switch", "Branch Switch 2", 600, 500, "core"),
    ]
    relationships = [
        _link("mpls", "wan_r1", "logical"),
        _link("sdwan", "wan_r2", "logical"),
        _link("internet", "wan_r2", "logical"),
        _link("lte", "wan_r1", "wireless"),
        _link("wan_r1", "wan_r2"),
        _link("br_fw1", "br_fw2"),
        _link("br_sw1", "br_sw2"),
    ]
    for fw in ("br_fw1", "br_fw2"):
        relationships += [_link("wan_r1", fw), _link("wan_r2", fw), _link(fw, "br_sw1"), _link(fw, "br_sw2")]
    x0 = 480 - (access - 1) * 120
    for i in range(access):
        key = f"access{i + 1}"
        components.append(_component(key, "switch", f"Access Switch {i + 1}", x0 + i * 240, 660, "access"))
        relationships += [_link("br_sw1", key), _link("br_sw2", key)]
    return components, relationships


def build_template(template_id: str, scale: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if template_id == "safe_enterprise_campus":
        return build_safe_enterprise_campus(scale)
    if template_id == "safe_data_center_san":
        return build_safe_data_center_san(scale)
    if template_id == "safe_branch_wan":
        return build_safe_branch_wan(scale)
    raise ValueError(f"Unknown template: {template_id}")
