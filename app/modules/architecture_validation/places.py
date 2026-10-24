"""
Places in the network (Cisco SAFE) of the network zones.

Cisco SAFE describes a network by its places in the network (PINs) - Branch, Campus, Data Center, Edge,
WAN and Cloud - and the security each needs, Segmentation, Threat Defense and Management among them.
Architecture Validation checks the topology against that model, so each network zone (app/models/
asset_zone.py) says which place it is: chosen on the zone (Asset Requirements, Network Zones), or read
from its name ("DMZ" is the Edge, "Internal Server Zone" the Data Center). Three places SAFE treats as
parts of others are kept apart because the checks need them: the Internet outside the Edge, guest
networks (Campus with the least trust) and the management network (SAFE's Management domain); lab
networks are isolated by design.
"""
import re
from typing import Optional

PLACES = ("internet", "edge", "data_center", "campus", "branch", "wan", "cloud", "guest", "management", "lab")

# First match wins: "Internal Server Zone" is a data center before it is internal.
_NAME_RULES = [
    (re.compile(r"internet|public|external|outside|untrust|\bisp\b", re.I), "internet"),
    (re.compile(r"\bdmz\b|edge|perimeter", re.I), "edge"),
    (re.compile(r"manag|mgmt|\boob\b|out.of.band", re.I), "management"),
    (re.compile(r"guest|visitor", re.I), "guest"),
    (re.compile(r"\blab\b|isolated|sandbox|\btest", re.I), "lab"),
    (re.compile(r"data ?cent|datacenter|\bdc\b|server", re.I), "data_center"),
    (re.compile(r"branch|remote ?office", re.I), "branch"),
    (re.compile(r"\bwan\b|mpls", re.I), "wan"),
    (re.compile(r"cloud|\baws\b|azure|\bgcp\b", re.I), "cloud"),
    (re.compile(r"user|campus|office|\blan\b|workstation|client|internal|corporate", re.I), "campus"),
]


def place_from_name(name: Optional[str]) -> Optional[str]:
    """The place a zone called `name` is, read from its name; None when the name does not say."""
    for pattern, place in _NAME_RULES:
        if name and pattern.search(name):
            return place
    return None


def place_of(zone) -> Optional[str]:
    """The zone's place: the one chosen on it, else the one its name says."""
    if zone is None:
        return None
    chosen = getattr(zone, "place", None)
    return chosen if chosen in PLACES else place_from_name(zone.name)
