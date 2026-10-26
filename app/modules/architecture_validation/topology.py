"""
What the topology says about each asset, for the Cisco SAFE checks (rules/safe.yaml).

The topology is the links between assets (Topology: drawn, or found over LLDP/CDP), and the external
networks drawn on it (TopologyCloud: the Internet, MPLS, a WAN, a public cloud ...) with the devices that
connect to them; a cloud is a node in the graph (negative id) with the place its kind gives - the
Internet, the WAN or the Cloud - but never has findings of its own. A link counts while
it is active, a link that is down - set so, or found over LLDP/CDP and no longer reported by the devices -
is reported, a planned one is not there yet. Each asset has a kind
(the icon resolver: app/core/asset_icons.py) and a place in the network (its zone's; places.py).

SAFE's segmentation is that traffic between places of different trust passes a firewall. A path between
two places is "unfiltered" when it reaches from one to the other over active links without passing a
firewall: the search below starts at every asset of the source places and never steps past a firewall.
Network devices (switches, routers, access points) carry traffic, so the asset at the end of a path is
always a host - a server, an endpoint - in the target place.
"""
from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional, Set

from sqlalchemy.orm import Session

from app.core.asset_icons import resolve_icon
from app.models.asset import Asset
from app.models.risk import AssetRiskProfile, RiskZone
from app.models.topology import TopologyCloud, TopologyCloudLink, TopologyLink
from app.modules.architecture_validation.places import place_of

FIREWALL = {"firewall"}
NETWORK = {"router", "switch", "wireless", "load_balancer", "waf", "ips", "vpn"}
SERVER = {"server", "hypervisor", "container", "cluster", "linux", "windows", "web", "database", "storage",
          "directory", "dns", "dhcp"}
ENDPOINT = {"workstation", "laptop", "ip_phone", "printer", "iot", "camera", "nvr", "ups", "plc"}

# External networks (app/core/asset_icons.py EXTERNAL_KINDS): untrusted like the Internet, the
# organisation's WAN (a provider's, not the Internet), or a public cloud.
OUTSIDE_KINDS = {"internet", "partner", "lte"}
WAN_KINDS = {"mpls", "wan", "sdwan"}
CLOUD_KINDS = {"public_cloud"}
WAN_ENDPOINTS = {"router", "firewall", "vpn"}           # where SAFE ends a WAN circuit

INSIDE = {"data_center", "storage", "campus", "branch", "management", "wan", "cloud", "lab", "edge", "guest"}

# Storage (SAN, iSCSI, NFS) is for servers: reached from these places without a firewall it is exposed.
STORAGE_REACHED_FROM = {"campus", "branch", "guest", "edge", "lab", "wan", "cloud"}

# (context name, places a path starts in, places of the host it reaches)
PATHS = [
    ("path_from_internet", {"internet"}, INSIDE),
    ("path_from_edge", {"edge"}, {"data_center", "campus", "branch", "management"}),
    ("path_from_guest", {"guest"}, INSIDE - {"guest"}),
    ("path_from_users", {"campus", "branch"}, {"data_center"}),
    ("path_to_management", {"campus", "branch", "guest", "edge", "lab"}, {"management"}),
    ("path_from_lab", {"lab"}, {"data_center", "campus", "branch", "management"}),
    ("path_from_cloud", {"cloud"}, {"data_center", "campus", "branch", "management"}),
]

LIST_AT_MOST = 5


def kind_class(kind: str) -> str:
    if kind in FIREWALL:
        return "firewall"
    if kind in NETWORK:
        return "network"
    if kind in OUTSIDE_KINDS:
        return "internet"
    if kind in WAN_KINDS:
        return "wan"
    if kind in CLOUD_KINDS:
        return "cloud"
    if kind in SERVER:
        return "server"
    if kind in ENDPOINT:
        return "endpoint"
    return "other"


def _names(names: Iterable[str]) -> str:
    names = sorted(names)
    shown = ", ".join(names[:LIST_AT_MOST])
    return shown + (f" +{len(names) - LIST_AT_MOST}" if len(names) > LIST_AT_MOST else "")


def _end(asset_name: str, interface: Optional[str]) -> str:
    return f"{asset_name} {interface}".strip() if interface else asset_name


class Topology:
    """The active topology as a graph, with the facts every asset's checks read."""

    def __init__(self, assets: List[Asset], places: Dict[int, Optional[str]], links: List[TopologyLink],
                 clouds: Iterable[TopologyCloud] = (), cloud_links: Iterable[TopologyCloudLink] = ()):
        self.assets = {a.id: a for a in assets}
        self.name = {a.id: a.asset_name for a in assets}
        self.kind = {a.id: resolve_icon(a) for a in assets}
        for c in clouds:                                 # external networks: negative ids, never findings
            self.name[-c.id] = c.label
            self.kind[-c.id] = c.kind
        self.nodes = set(self.name)
        self.cls = {aid: kind_class(k) for aid, k in self.kind.items()}
        default_place = {"internet": "internet", "wan": "wan", "cloud": "cloud"}
        self.place = {aid: (places.get(aid) if aid in self.assets else None) or default_place.get(self.cls[aid])
                      for aid in self.nodes}
        self.adj: Dict[int, Set[int]] = defaultdict(set)
        self.degree_all: Dict[int, int] = defaultdict(int)
        self.down: Dict[int, List[str]] = defaultdict(list)
        pairs = [(lk.source_asset_id, lk.destination_asset_id, lk.source_interface, lk.destination_interface,
                  lk.status, lk.missing_since) for lk in links]
        pairs += [(-cl.cloud_id, cl.asset_id, None, cl.interface, cl.status, None) for cl in cloud_links]
        for a, b, a_if, b_if, status, missing_since in pairs:
            if a not in self.nodes or b not in self.nodes or a == b or status == "planned":
                continue
            self.degree_all[a] += 1
            self.degree_all[b] += 1
            if status == "down" or missing_since is not None:
                # reported on the source asset; a cloud's link on the asset (a cloud has no findings)
                self.down[b if a < 0 else a].append(f"{_end(self.name[a], a_if)} - {_end(self.name[b], b_if)}")
            else:
                self.adj[a].add(b)
                self.adj[b].add(a)

    # ── paths ──────────────────────────────────────────────────────────

    def is_storage(self, aid: int) -> bool:
        return self.kind.get(aid) == "storage" or self.place.get(aid) == "storage"

    def unfiltered_paths(self, sources: Set[str], targets: Set[str], storage: bool = False) -> Dict[int, str]:
        """For each host in a target place reachable from a source place without passing a firewall,
        the shortest such path ("a -> b -> c"); with `storage`, for each storage device instead (a
        storage array, or a host in the storage network), wherever it sits."""
        start = sorted(aid for aid, p in self.place.items() if p in sources and self.cls[aid] != "firewall")
        came_from: Dict[int, Optional[int]] = {aid: None for aid in start}
        queue = deque(start)
        while queue:
            node = queue.popleft()
            for nxt in sorted(self.adj.get(node, ())):          # the same path on every run
                if nxt in came_from:
                    continue
                came_from[nxt] = node
                if self.cls[nxt] != "firewall":           # a firewall filters: the path ends there
                    queue.append(nxt)
        out = {}
        for aid, prev in came_from.items():
            if prev is None or self.cls[aid] not in ("server", "endpoint", "other"):
                continue
            if (not self.is_storage(aid)) if storage else (self.place.get(aid) not in targets):
                continue
            hops, node = [], aid
            while node is not None:
                hops.append(self.name[node])
                node = came_from[node]
            out[aid] = " -> ".join(reversed(hops))
        return out

    # ── the Internet edge ──────────────────────────────────────────────

    def _outside(self, aid: int) -> bool:
        return self.place.get(aid) == "internet" or self.cls[aid] == "internet"

    def edge_firewalls(self) -> Set[int]:
        """Firewalls the Internet reaches first (no other firewall on the way)."""
        start = [aid for aid in self.nodes if self._outside(aid) and self.cls[aid] != "firewall"]
        seen, queue, found = set(start), deque(start), set()
        while queue:
            node = queue.popleft()
            for nxt in self.adj.get(node, ()):
                if nxt in seen:
                    continue
                seen.add(nxt)
                if self.cls[nxt] == "firewall":
                    found.add(nxt)
                else:
                    queue.append(nxt)
        return found

    def internet_links(self) -> List[tuple]:
        """Active links from the Internet side to the inside: (inside asset, outside asset)."""
        return [(b, a) for a in self.nodes if self._outside(a)
                for b in self.adj.get(a, ()) if not self._outside(b) and b in self.assets]

    def wan_links(self) -> List[tuple]:
        """Active links from the organisation's WAN (MPLS, a WAN circuit, SD-WAN) to a device:
        (device, WAN node)."""
        return [(b, a) for a in self.nodes if self.cls[a] == "wan"
                for b in self.adj.get(a, ()) if b in self.assets and self.cls[b] != "wan"]

    # ── single points of failure ───────────────────────────────────────

    def _parts_without(self, removed: int) -> List[Set[int]]:
        parts, seen = [], {removed}
        for start in self.adj.get(removed, ()):
            if start in seen:
                continue
            part, queue = {start}, deque([start])
            seen.add(start)
            while queue:
                node = queue.popleft()
                for nxt in self.adj.get(node, ()):
                    if nxt not in seen:
                        seen.add(nxt)
                        part.add(nxt)
                        queue.append(nxt)
            parts.append(part)
        return parts

    def cut_off_by(self, aid: int) -> Set[int]:
        """The assets that lose the rest of the network when network device `aid` fails: every part
        left without it except the main one (the side of the Internet edge, else the one with the most
        network devices, else the largest), counted only when the part holds a network device (a host
        on a single link is its own finding)."""
        if self.cls[aid] not in ("network", "firewall") or len(self.adj.get(aid, ())) < 2:
            return set()

        def weight(part):
            return (any(self._outside(p) for p in part),
                    sum(1 for p in part if self.cls[p] in ("network", "firewall")), len(part), -min(part))
        parts = sorted(self._parts_without(aid), key=weight, reverse=True)
        cut = set()
        for part in parts[1:]:
            if any(self.cls[p] in ("network", "firewall") for p in part):
                cut |= part
        return cut

    # ── per asset ──────────────────────────────────────────────────────

    def facts(self, is_critical: Dict[int, bool]) -> Dict[int, dict]:
        paths = {name: self.unfiltered_paths(src, dst) for name, src, dst in PATHS}
        to_storage = self.unfiltered_paths(STORAGE_REACHED_FROM, set(), storage=True)
        edge_fw = self.edge_firewalls()
        uplinks = self.internet_links()
        wan = self.wan_links()
        out = {}
        for aid in self.assets:
            cls, place = self.cls[aid], self.place.get(aid)
            neighbours = self.adj.get(aid, set())
            cut = self.cut_off_by(aid)
            facts = {
                "kind": self.kind[aid],
                "device_class": cls,
                "place": place,
                "is_critical": bool(is_critical.get(aid)),
                "links": len(neighbours),
                "in_topology": self.degree_all.get(aid, 0) > 0,
                "network_uplinks": sum(1 for n in neighbours if self.cls[n] in ("network", "firewall")),
                "links_down": "; ".join(self.down.get(aid, [])) or None,
                "cut_off": _names(self.name[c] for c in cut) if cut else None,
                "cut_off_critical": any(is_critical.get(c) or self.place.get(c) == "data_center" for c in cut),
                "only_edge_firewall": len(edge_fw) == 1 and aid in edge_fw,
                "only_internet_link": None,
                "is_storage": self.is_storage(aid) and cls in ("server", "other"),
                "path_to_storage": to_storage.get(aid),
                # a WAN circuit ending on something that is not a router, firewall or VPN gateway
                "wan_on_wrong_device": _names(self.name[w] for d, w in wan if d == aid)
                if self.kind[aid] not in WAN_ENDPOINTS and any(d == aid for d, _ in wan) else None,
                "only_wan_link": None,
            }
            for name, _, _ in PATHS:
                facts[name] = paths[name].get(aid)
            out[aid] = facts
        if len(uplinks) == 1:
            inside, outside = uplinks[0]
            out[inside]["only_internet_link"] = f"{self.name[outside]} - {self.name[inside]}"
        if len(wan) == 1:
            device, cloud = wan[0]
            out[device]["only_wan_link"] = f"{self.name[cloud]} - {self.name[device]}"
        return out


def load(db: Session) -> "Topology":
    assets = db.query(Asset).all()
    places = {aid: place_of(zone) for aid, zone in
              db.query(AssetRiskProfile.asset_id, RiskZone)
              .join(RiskZone, RiskZone.id == AssetRiskProfile.zone_id)}
    links = db.query(TopologyLink).all()
    return Topology(assets, places, links, db.query(TopologyCloud).all(), db.query(TopologyCloudLink).all())
