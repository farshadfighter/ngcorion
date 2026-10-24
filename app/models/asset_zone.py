"""
One list of network zones, and an asset's zone in one place.

There were two lists. Asset List picked a zone from network_zones and kept its name on
asset_inventory.asset_role; Risk Intelligence scored from risk_zones (each with an exposure score) and kept
the zone on asset_risk_profiles.zone_id. A zone set in Asset List counted for the risk score only when its
name happened to match a risk zone ("Data Center" or a new "Edge" did not), and nowhere else: risk filters,
asset groups, alert rules, report scope and the dashboards read the profile. A zone set in Risk overrode it
without the asset list showing it.

network_zones is merged into risk_zones (migration e3b5d7f9a1c2); Asset Requirements, Network Zones manages
that one list. This hook keeps the two places an asset's zone is written in step, whatever module writes
it: a zone name set on the asset (form, Excel import) sets the profile's zone, and a profile zone set in
Risk or by a bulk action puts its name on the asset; renaming a zone renames it on its assets.
"""
import re

from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

# Names the old asset list zones had for zones risk_zones calls otherwise.
ALIASES = {"internal": "internalserverzone", "external": "internetpublic"}


def zone_key(name) -> str:
    """"Internet / Public", "internet-public" and "Internet Public" are one zone."""
    key = re.sub(r"[^a-z0-9]", "", str(name or "").lower())
    return ALIASES.get(key, key)


def find_zone(db: Session, name):
    """The zone called `name` (matched as zone_key does), or None."""
    from app.models.risk import RiskZone
    key = zone_key(name)
    if not key:
        return None
    for zone in db.query(RiskZone).all():
        if zone_key(zone.name) == key:
            return zone
    return None


def _profile_of(session: Session, asset):
    from app.models.risk import AssetRiskProfile
    for obj in session.new:
        if isinstance(obj, AssetRiskProfile) and (obj.asset is asset or (asset.id and obj.asset_id == asset.id)):
            return obj
    if asset.id is None:
        return None
    return session.query(AssetRiskProfile).filter(AssetRiskProfile.asset_id == asset.id).first()


def _asset_zone_set(session: Session, asset) -> None:
    from app.models.risk import AssetRiskProfile
    name = (asset.asset_role or "").strip()
    zone = find_zone(session, name) if name else None
    if name and zone is None:
        return              # not a zone (checked where it is typed in); the risk score treats it as unknown
    asset.asset_role = zone.name if zone else None
    profile = _profile_of(session, asset)
    if profile is None:
        if zone is None:
            return
        profile = AssetRiskProfile(asset=asset, criticality_level="medium", criticality_score=50,
                                   criticality_is_default=True)
        session.add(profile)
    profile.zone_id = zone.id if zone else None
    profile.zone = zone
    profile.zone_is_default = zone is None


def _profile_zone_set(session: Session, profile) -> None:
    from app.models.asset import Asset
    from app.models.risk import RiskZone
    asset = profile.asset or (session.get(Asset, profile.asset_id) if profile.asset_id else None)
    if asset is None:
        return
    zone = profile.zone if profile.zone is not None and profile.zone.id == profile.zone_id else (
        session.get(RiskZone, profile.zone_id) if profile.zone_id else None)
    name = zone.name if zone else None
    if asset.asset_role != name:
        asset.asset_role = name


def _zone_renamed(session: Session, zone) -> None:
    from app.models.asset import Asset
    from app.models.risk import AssetRiskProfile
    for asset in (session.query(Asset).join(AssetRiskProfile, AssetRiskProfile.asset_id == Asset.id)
                  .filter(AssetRiskProfile.zone_id == zone.id)):
        asset.asset_role = zone.name


def _changed(obj, attr: str) -> bool:
    return inspect(obj).attrs[attr].history.has_changes()


@event.listens_for(Session, "before_flush")
def _one_zone(session: Session, flush_context, instances) -> None:
    from app.models.asset import Asset
    from app.models.risk import AssetRiskProfile, RiskZone
    pending = list(session.new) + list(session.dirty)
    assets = [o for o in pending if isinstance(o, Asset) and _changed(o, "asset_role")]
    for asset in assets:
        _asset_zone_set(session, asset)
    for obj in pending:
        if isinstance(obj, AssetRiskProfile) and obj.asset not in assets and _changed(obj, "zone_id"):
            if obj in session.new and obj.zone_id is None:
                continue    # a profile the risk engine creates with no zone leaves the asset's alone
            _profile_zone_set(session, obj)
        elif isinstance(obj, RiskZone) and obj not in session.new and _changed(obj, "name"):
            _zone_renamed(session, obj)
