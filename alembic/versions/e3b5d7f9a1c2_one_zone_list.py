"""One list of network zones: network_zones merged into risk_zones

Revision ID: e3b5d7f9a1c2
Revises: d9f1b3c5e7a8
Create Date: 2026-10-24

Asset List picked zones from network_zones and kept the name on asset_inventory.asset_role; Risk scored from
risk_zones and kept the zone on asset_risk_profiles.zone_id, so a zone like "Data Center" or a new "Edge"
set in Asset List counted nowhere in Risk (app/models/asset_zone.py). Here:

- every network zone becomes a risk zone unless one of that name is there ("Internal" is the "Internal
  Server Zone", "External" the "Internet / Public"); a new one gets the score risk gives an asset with no
  zone (unknown_zone_score), which is what its assets were scored with until now;
- an asset gets one zone: where Asset List and Risk name different zones, the one changed last (the
  asset's or its risk profile's update time) stays; a zone name no zone has becomes a zone, so nothing
  typed in is lost;
- network_zones is dropped.
"""
import re
from datetime import datetime
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e3b5d7f9a1c2"
down_revision: Union[str, Sequence[str], None] = "d9f1b3c5e7a8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ALIASES = {"internal": "internalserverzone", "external": "internetpublic"}


def _key(name) -> str:
    key = re.sub(r"[^a-z0-9]", "", str(name or "").lower())
    return ALIASES.get(key, key)


def upgrade() -> None:
    bind = op.get_bind()
    now = datetime.utcnow()
    raw = bind.execute(sa.text(
        "SELECT setting_value FROM risk_settings WHERE setting_key = 'unknown_zone_score'")).scalar()
    try:
        default_score = max(0.0, min(float(raw), 100.0))
    except (TypeError, ValueError):
        default_score = 50.0

    zones = {}                                   # key -> (id, name)
    for zid, name in bind.execute(sa.text("SELECT id, name FROM risk_zones")):
        zones.setdefault(_key(name), (zid, name))

    def zone_for(name, description=None):
        key = _key(name)
        if not key:
            return None
        if key not in zones:
            zid = bind.execute(sa.text(
                "INSERT INTO risk_zones (name, description, score, status, created_at, updated_at) "
                "VALUES (:n, :d, :s, 'active', :t, :t) RETURNING id"),
                {"n": str(name).strip()[:100], "d": (description or None) and str(description)[:500],
                 "s": default_score, "t": now}).scalar()
            zones[key] = (zid, str(name).strip()[:100])
        return zones[key]

    if sa.inspect(bind).has_table("network_zones"):
        for name, description in bind.execute(sa.text("SELECT zone_name, description FROM network_zones")):
            zone_for(name, description)

    rows = bind.execute(sa.text(
        "SELECT a.id, a.asset_role, a.updated_at, p.id, p.zone_id, z.name, p.updated_at FROM asset_inventory a "
        "LEFT JOIN asset_risk_profiles p ON p.asset_id = a.id "
        "LEFT JOIN risk_zones z ON z.id = p.zone_id")).fetchall()
    for asset_id, role, asset_changed, profile_id, zone_id, zone_name, profile_changed in rows:
        risk_is_newer = profile_changed is not None and (asset_changed is None or profile_changed >= asset_changed)
        if zone_id is not None and (not _key(role) or _key(role) == _key(zone_name) or risk_is_newer):
            name = zone_name
        else:
            zone = zone_for(role)
            if zone is None:
                continue
            zone_id, name = zone
            if profile_id is None:
                bind.execute(sa.text(
                    "INSERT INTO asset_risk_profiles (asset_id, criticality_level, criticality_score, zone_id, "
                    "criticality_is_default, zone_is_default, created_at, updated_at) "
                    "VALUES (:a, 'medium', 50, :z, true, false, :t, :t)"), {"a": asset_id, "z": zone_id, "t": now})
            else:
                bind.execute(sa.text(
                    "UPDATE asset_risk_profiles SET zone_id = :z, zone_is_default = false WHERE id = :p"),
                    {"z": zone_id, "p": profile_id})
        if role != name:
            bind.execute(sa.text("UPDATE asset_inventory SET asset_role = :n WHERE id = :a"),
                         {"n": name, "a": asset_id})

    if sa.inspect(bind).has_table("network_zones"):
        op.drop_index("ix_network_zones_zone_name", table_name="network_zones")
        op.drop_table("network_zones")


def downgrade() -> None:
    op.create_table(
        "network_zones",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False, comment="Unique identifier"),
        sa.Column("zone_name", sa.String(length=100), nullable=False,
                  comment="Network zone name (e.g., DMZ, Internal, Management)"),
        sa.Column("description", sa.Text(), nullable=True,
                  comment="Description of the zone purpose and characteristics"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_network_zones_zone_name", "network_zones", ["zone_name"], unique=True)
    op.execute("INSERT INTO network_zones (zone_name, description) SELECT name, description FROM risk_zones")
