"""
Asset-based design suggestion.

Reads the real Asset inventory, classifies each asset into a SAFE component
role by keyword-matching its asset type name (the same rule set used by the
frontend's DeviceIcon component, so a device gets the same "kind" everywhere
in the app), picks an organization scale from the total asset count (reusing
the same small/medium/large buckets template scales already use), and slots
real assets into the standard SAFE campus shape wherever a matching device
exists.

This never touches the database - it is a read-only preview. Turning a
suggestion into a real Design is just the existing "create from template"
path (DesignService.apply_template) followed by mapping each matched
component to its suggested asset (DesignService.map_component_to_asset),
both already used by the manual template picker.
"""
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from sqlalchemy.orm import Session, joinedload

from app.models.asset import Asset
from app.modules.design.templates import SCALES, build_template

# Mirrors front/src/components/shared/DeviceIcon.jsx's KEYWORD_RULES exactly,
# so a device is classified into the same "kind" on the canvas icon and here.
# Order matters: first match wins, so more specific keywords come first.
KEYWORD_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"firewall|fortigate|fortinet|palo ?alto|asa", re.I), "firewall"),
    (re.compile(r"router|cisco.*ios|gateway", re.I), "router"),
    (re.compile(r"switch", re.I), "switch"),
    (re.compile(r"load ?balanc", re.I), "load_balancer"),
    (re.compile(r"wireless|wifi|access point|\bap\b|wlc", re.I), "wireless"),
    (re.compile(r"cloud", re.I), "cloud"),
    (re.compile(r"server|linux|windows|apache|mongo|mssql|sql|database|\bdb\b", re.I), "server"),
]


def classify_component_type(type_name: Optional[str]) -> Optional[str]:
    """Return the SAFE component_type bucket for an asset type name, or None
    when nothing matches (the asset is not a recognizable network role, e.g.
    a printer or a badge reader - it is simply left out of the suggestion)."""
    if not type_name:
        return None
    for pattern, component_type in KEYWORD_RULES:
        if pattern.search(type_name):
            return component_type
    return None


def determine_scale(total_assets: int) -> str:
    """Small/medium/large purely from total asset count, using the exact
    same thresholds the labels in templates.SCALES already describe."""
    if total_assets < 50:
        return "small"
    if total_assets <= 200:
        return "medium"
    return "large"


@dataclass
class SuggestedComponent:
    key: str
    component_type: str
    label: str
    pos_x: float
    pos_y: float
    zone: str
    suggested_asset_id: Optional[int] = None
    suggested_asset_name: Optional[str] = None
    suggested_asset_port_count: Optional[int] = None


@dataclass
class SuggestedRelationship:
    source_key: str
    destination_key: str
    link_type: str = "ethernet"


@dataclass
class DesignSuggestion:
    scale: str
    scale_label: str
    total_assets: int
    matched_assets: int
    components: list[SuggestedComponent] = field(default_factory=list)
    relationships: list[SuggestedRelationship] = field(default_factory=list)


def suggest_design(db: Session) -> DesignSuggestion:
    assets = db.query(Asset).options(joinedload(Asset.asset_type)).all()
    total_assets = len(assets)
    scale = determine_scale(total_assets)

    # Pool of unused real assets per component_type, in a stable, useful
    # order: assets with more physical ports first (a real 48-port switch is
    # a better fit for "Core Switch" than an 8-port one), so the most
    # capable device on hand gets matched to the most central slot.
    pools: dict[str, list[Asset]] = {}
    for asset in assets:
        component_type = classify_component_type(
            asset.asset_type.type_name if asset.asset_type else None
        )
        if component_type is None:
            continue
        pools.setdefault(component_type, []).append(asset)
    for bucket in pools.values():
        bucket.sort(key=lambda a: (a.port_count or 0), reverse=True)

    component_defs, relationship_defs = build_template("safe_enterprise_campus", scale)

    components: list[SuggestedComponent] = []
    matched_assets = 0
    for comp in component_defs:
        suggested = SuggestedComponent(
            key=comp["_key"],
            component_type=comp["component_type"],
            label=comp["label"],
            pos_x=comp["pos_x"],
            pos_y=comp["pos_y"],
            zone=comp["zone"],
        )
        pool = pools.get(comp["component_type"])
        if pool:
            asset = pool.pop(0)
            suggested.suggested_asset_id = asset.id
            suggested.suggested_asset_name = asset.asset_name
            suggested.suggested_asset_port_count = asset.port_count
            matched_assets += 1
        components.append(suggested)

    relationships = [
        SuggestedRelationship(source_key=r["_source"], destination_key=r["_destination"], link_type=r["link_type"])
        for r in relationship_defs
    ]

    return DesignSuggestion(
        scale=scale,
        scale_label=SCALES[scale]["label"],
        total_assets=total_assets,
        matched_assets=matched_assets,
        components=components,
        relationships=relationships,
    )
