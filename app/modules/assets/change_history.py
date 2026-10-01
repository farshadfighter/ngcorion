"""
Asset field-change history.

Computes a human-readable, per-field diff whenever AssetService.update_asset
changes an Asset row, so AssetLog's existing "update" entries (see
app/models/asset_log.py) carry enough detail to render a real change
timeline - not just the list of field names that were touched.

Deliberately reuses the existing AssetLog table/endpoints rather than adding
a new model: an "update" AssetLog row's `details.changes` now holds
[{"field", "label", "category", "old", "new"}, ...] instead of a bare list
of field names. Nothing else reads that shape today, so this is additive.
"""
from datetime import date, datetime
from sqlalchemy.orm import Session

from app.models import Asset, AssetType, AssetOwner, AssetLocation

# (label, category) per editable Asset field - category matches the four
# tabs on the Asset List page (Overview / Network & System / Location &
# Owner / Security & Audit) so the change-history UI can filter the same way.
FIELD_META = {
    "asset_name":    ("Asset Name", "overview"),
    "hostname":      ("Hostname", "overview"),
    "asset_type_id": ("Asset Type", "overview"),
    "asset_role":    ("Network Zone", "overview"),
    "manufacturer":  ("Vendor", "overview"),
    "model":         ("Model", "overview"),
    "serial_number": ("Serial Number", "network"),
    "os_name":       ("Operating System", "network"),
    "os_version":    ("OS Version", "network"),
    "ip_address":    ("IP Address", "network"),
    "mac_address":   ("MAC Address", "network"),
    "port_count":    ("Physical Port Count", "network"),
    "icon":          ("Icon", "overview"),
    "location_id":       ("Location", "location"),
    "owner_id":          ("Owner", "location"),
    "status":            ("Status", "location"),
    "hosted_on_asset_id": ("Hosted On", "location"),
    "hosted_vlan":        ("VLAN", "location"),
    "confidentiality_level": ("Confidentiality Level", "security"),
    "risk_level":            ("Risk Level", "security"),
    "last_patch_date":       ("Last Patch Date", "security"),
    "asset_value":           ("Asset Value (USD)", "security"),
    "description":           ("Description", "security"),
    # last_audit_date is deliberately excluded: update_asset auto-stamps it
    # on *every* update, so diffing it would add a noisy, meaningless entry
    # to every single change instead of a real one.
}


def _display_value(db: Session, field: str, value):
    """Render one field's raw value the way a human reads it - resolving a
    foreign key to the name it pointed at *at that time* (stored denormalized
    in the log, so history stays accurate even if that row is later renamed
    or deleted) rather than leaving an opaque id in the diff."""
    if value is None:
        return None
    if field == "asset_type_id":
        row = db.query(AssetType).filter(AssetType.id == value).first()
        return row.type_name if row else f"#{value}"
    if field == "location_id":
        row = db.query(AssetLocation).filter(AssetLocation.id == value).first()
        return row.site_name if row else f"#{value}"
    if field == "owner_id":
        row = db.query(AssetOwner).filter(AssetOwner.id == value).first()
        return row.full_name if row else f"#{value}"
    if field == "hosted_on_asset_id":
        row = db.query(Asset).filter(Asset.id == value).first()
        return row.asset_name if row else f"#{value}"
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if hasattr(value, "value"):  # StatusEnum / ConfidentialityLevelEnum / RiskLevelEnum
        return value.value
    return value


def compute_field_changes(db: Session, asset: Asset, old_values: dict) -> list[dict]:
    """Compare `old_values` (a field -> raw-value snapshot taken *before* the
    update was applied) against `asset`'s current (post-update) values.
    Returns one entry per field whose displayed value actually changed."""
    changes = []
    for field, old_raw in old_values.items():
        if field not in FIELD_META:
            continue
        new_raw = getattr(asset, field, None)
        old_display = _display_value(db, field, old_raw)
        new_display = _display_value(db, field, new_raw)
        if old_display == new_display:
            continue
        label, category = FIELD_META[field]
        changes.append({
            "field": field,
            "label": label,
            "category": category,
            "old": old_display,
            "new": new_display,
        })
    return changes
