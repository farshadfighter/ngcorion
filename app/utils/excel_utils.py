"""
Excel Import/Export Utilities

Handles Excel file operations for Asset and Asset Requirement data.
"""

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from datetime import datetime
from typing import List, Dict, Any
from io import BytesIO


def create_styled_workbook(title: str) -> Workbook:
    """Create a new workbook with basic styling"""
    wb = Workbook()
    ws = wb.active
    ws.title = title
    return wb


def style_header_row(ws, columns: List[str]):
    """Apply styling to header row"""
    header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF", size=11)
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )

    # Write headers
    for col_idx, column_name in enumerate(columns, 1):
        cell = ws.cell(row=1, column=col_idx, value=column_name)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border

        # Auto-width
        ws.column_dimensions[get_column_letter(col_idx)].width = max(len(column_name) + 2, 15)


def export_assets_to_excel(assets: List[Any], include_data: bool = True) -> BytesIO:
    """
    Export assets to Excel file

    Args:
        assets: List of Asset objects
        include_data: If False, creates empty template. If True, includes asset data.

    Returns:
        BytesIO object containing the Excel file
    """
    wb = create_styled_workbook("Assets")
    ws = wb.active

    # Define columns - ALL fields from Asset model
    columns = [
        "ID",
        "Asset Name",
        "Hostname",
        "Asset Type",
        "Asset Role",
        "Manufacturer",
        "Model",
        "Serial Number",
        "OS Name",
        "OS Version",
        "IP Address",
        "MAC Address",
        "Location",
        "Owner",
        "Status",
        "Confidentiality Level",
        "Risk Level",
        "Last Audit Date",
        "Last Patch Date",
        "Asset Value",
        "Description",
        "Created At",
        "Updated At"
    ]

    # Style header
    style_header_row(ws, columns)

    # Add data if requested
    if include_data and assets:
        for row_idx, asset in enumerate(assets, 2):
            ws.cell(row=row_idx, column=1, value=asset.id)
            ws.cell(row=row_idx, column=2, value=asset.asset_name)
            ws.cell(row=row_idx, column=3, value=asset.hostname)
            ws.cell(row=row_idx, column=4, value=asset.asset_type.type_name if asset.asset_type else "")
            ws.cell(row=row_idx, column=5, value=asset.asset_role)
            ws.cell(row=row_idx, column=6, value=asset.manufacturer)
            ws.cell(row=row_idx, column=7, value=asset.model)
            ws.cell(row=row_idx, column=8, value=asset.serial_number)
            ws.cell(row=row_idx, column=9, value=asset.os_name)
            ws.cell(row=row_idx, column=10, value=asset.os_version)
            ws.cell(row=row_idx, column=11, value=asset.ip_address)
            ws.cell(row=row_idx, column=12, value=asset.mac_address)
            ws.cell(row=row_idx, column=13, value=asset.location.site_name if asset.location else "")
            ws.cell(row=row_idx, column=14, value=asset.owner.full_name if asset.owner else "")
            ws.cell(row=row_idx, column=15, value=asset.status.value if asset.status else "")
            ws.cell(row=row_idx, column=16, value=asset.confidentiality_level.value if asset.confidentiality_level else "")
            ws.cell(row=row_idx, column=17, value=asset.risk_level.value if asset.risk_level else "")
            ws.cell(row=row_idx, column=18, value=asset.last_audit_date.strftime('%Y-%m-%d') if asset.last_audit_date else "")
            ws.cell(row=row_idx, column=19, value=asset.last_patch_date.strftime('%Y-%m-%d') if asset.last_patch_date else "")
            ws.cell(row=row_idx, column=20, value=float(asset.asset_value) if asset.asset_value else "")
            ws.cell(row=row_idx, column=21, value=asset.description)
            ws.cell(row=row_idx, column=22, value=asset.created_at.strftime('%Y-%m-%d %H:%M:%S') if asset.created_at else "")
            ws.cell(row=row_idx, column=23, value=asset.updated_at.strftime('%Y-%m-%d %H:%M:%S') if asset.updated_at else "")

    # Save to BytesIO
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    return output


def create_asset_template() -> BytesIO:
    """
    Create an empty Excel template for asset import

    Returns:
        BytesIO object containing the template Excel file
    """
    return export_assets_to_excel([], include_data=False)


def import_assets_from_excel(file_content: BytesIO, db_session, current_user) -> Dict[str, Any]:
    """
    Import assets from an Excel file

    Args:
        file_content: BytesIO object containing the Excel file
        db_session: Database session
        current_user: Current authenticated user

    Returns:
        Dictionary with import results:
        - created: Number of assets created
        - updated: Number of assets updated
        - errors: List of error messages
        - details: Detailed results for each row
    """
    from openpyxl import load_workbook
    from app.models import Asset, AssetType, AssetLocation, AssetOwner
    from app.models.enums import StatusEnum, ConfidentialityLevelEnum, RiskLevelEnum
    from datetime import datetime

    results = {
        "created": 0,
        "updated": 0,
        "skipped": 0,
        "errors": [],
        "details": []
    }

    try:
        # Load workbook
        wb = load_workbook(file_content, data_only=True)
        ws = wb.active

        # Get header row
        headers = [cell.value for cell in ws[1]]

        # Map headers to field names
        header_map = {
            "ID": "id",
            "Asset Name": "asset_name",
            "Hostname": "hostname",
            "Asset Type": "asset_type",
            "Asset Role": "asset_role",
            "Manufacturer": "manufacturer",
            "Model": "model",
            "Serial Number": "serial_number",
            "OS Name": "os_name",
            "OS Version": "os_version",
            "IP Address": "ip_address",
            "MAC Address": "mac_address",
            "Location": "location",
            "Owner": "owner",
            "Status": "status",
            "Confidentiality Level": "confidentiality_level",
            "Risk Level": "risk_level",
            "Last Audit Date": "last_audit_date",
            "Last Patch Date": "last_patch_date",
            "Asset Value": "asset_value",
            "Description": "description"
        }

        # Process each row (skip header)
        for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
            try:
                # Build data dictionary
                row_data = {}
                for col_idx, value in enumerate(row):
                    if col_idx < len(headers) and headers[col_idx] in header_map:
                        field_name = header_map[headers[col_idx]]
                        if value is not None and value != "":
                            row_data[field_name] = value

                # Skip empty rows
                if not row_data or not row_data.get("asset_name"):
                    results["skipped"] += 1
                    continue

                # Resolve foreign keys
                asset_type_id = None
                if "asset_type" in row_data:
                    asset_type = db_session.query(AssetType).filter(
                        AssetType.type_name == row_data["asset_type"]
                    ).first()
                    if asset_type:
                        asset_type_id = asset_type.id
                    else:
                        results["errors"].append(f"Row {row_idx}: Asset type '{row_data['asset_type']}' not found")
                        continue
                    del row_data["asset_type"]

                location_id = None
                if "location" in row_data:
                    location = db_session.query(AssetLocation).filter(
                        AssetLocation.site_name == row_data["location"]
                    ).first()
                    if location:
                        location_id = location.id
                    del row_data["location"]

                owner_id = None
                if "owner" in row_data:
                    owner = db_session.query(AssetOwner).filter(
                        AssetOwner.full_name == row_data["owner"]
                    ).first()
                    if owner:
                        owner_id = owner.id
                    del row_data["owner"]

                # Convert enums
                if "status" in row_data:
                    try:
                        row_data["status"] = StatusEnum(row_data["status"])
                    except ValueError:
                        results["errors"].append(f"Row {row_idx}: Invalid status '{row_data['status']}'")
                        del row_data["status"]

                if "confidentiality_level" in row_data:
                    try:
                        row_data["confidentiality_level"] = ConfidentialityLevelEnum(row_data["confidentiality_level"])
                    except ValueError:
                        del row_data["confidentiality_level"]

                if "risk_level" in row_data:
                    try:
                        row_data["risk_level"] = RiskLevelEnum(row_data["risk_level"])
                    except ValueError:
                        del row_data["risk_level"]

                # Convert dates
                for date_field in ["last_audit_date", "last_patch_date"]:
                    if date_field in row_data and isinstance(row_data[date_field], str):
                        try:
                            row_data[date_field] = datetime.strptime(row_data[date_field], '%Y-%m-%d').date()
                        except ValueError:
                            del row_data[date_field]

                # Add foreign keys
                if asset_type_id:
                    row_data["asset_type_id"] = asset_type_id
                if location_id:
                    row_data["location_id"] = location_id
                if owner_id:
                    row_data["owner_id"] = owner_id

                # Check if asset exists (by ID, asset_name, or IP)
                existing_asset = None
                if "id" in row_data and row_data["id"]:
                    existing_asset = db_session.query(Asset).filter(Asset.id == row_data["id"]).first()
                elif "ip_address" in row_data:
                    existing_asset = db_session.query(Asset).filter(
                        Asset.ip_address == row_data["ip_address"],
                        Asset.user_id == current_user.id
                    ).first()

                if not existing_asset and "asset_name" in row_data:
                    existing_asset = db_session.query(Asset).filter(
                        Asset.asset_name == row_data["asset_name"],
                        Asset.user_id == current_user.id
                    ).first()

                # Remove ID from row_data for new assets
                if "id" in row_data and not existing_asset:
                    del row_data["id"]

                if existing_asset:
                    # Update existing asset
                    if "id" in row_data:
                        del row_data["id"]  # Don't update ID
                    for key, value in row_data.items():
                        if hasattr(existing_asset, key):
                            setattr(existing_asset, key, value)

                    results["updated"] += 1
                    results["details"].append({
                        "row": row_idx,
                        "action": "updated",
                        "asset_name": row_data.get("asset_name", existing_asset.asset_name),
                        "id": existing_asset.id
                    })
                else:
                    # Create new asset
                    if not asset_type_id:
                        results["errors"].append(f"Row {row_idx}: Asset type is required for new assets")
                        continue

                    row_data["user_id"] = current_user.id
                    new_asset = Asset(**row_data)
                    db_session.add(new_asset)
                    db_session.flush()  # Get ID before commit

                    results["created"] += 1
                    results["details"].append({
                        "row": row_idx,
                        "action": "created",
                        "asset_name": row_data.get("asset_name"),
                        "id": new_asset.id
                    })

            except Exception as e:
                results["errors"].append(f"Row {row_idx}: {str(e)}")
                continue

        # Commit all changes
        db_session.commit()

    except Exception as e:
        db_session.rollback()
        results["errors"].append(f"Fatal error: {str(e)}")

    return results


# ====================================
# Asset Requirements Export Functions
# ====================================

def export_asset_requirements_to_excel(data_dict: Dict[str, List[Any]]) -> BytesIO:
    """
    Export all asset requirements to a single Excel file with multiple sheets

    Args:
        data_dict: Dictionary with sheet names as keys and data lists as values
            Expected keys: asset_types, owners, locations, zones, os_catalog, vendors, dependencies

    Returns:
        BytesIO object containing the Excel file
    """
    wb = Workbook()
    # Remove default sheet
    wb.remove(wb.active)

    # Export Asset Types
    if "asset_types" in data_dict and data_dict["asset_types"]:
        ws = wb.create_sheet("Asset Types")
        columns = ["ID", "Type Name", "Category", "Description"]
        style_header_row(ws, columns)

        for row_idx, item in enumerate(data_dict["asset_types"], 2):
            ws.cell(row=row_idx, column=1, value=item.id)
            ws.cell(row=row_idx, column=2, value=item.type_name)
            ws.cell(row=row_idx, column=3, value=item.category)
            ws.cell(row=row_idx, column=4, value=item.description)

    # Export Owners
    if "owners" in data_dict and data_dict["owners"]:
        ws = wb.create_sheet("Owners")
        columns = ["ID", "Full Name", "Department", "Role", "Email", "Phone"]
        style_header_row(ws, columns)

        for row_idx, item in enumerate(data_dict["owners"], 2):
            ws.cell(row=row_idx, column=1, value=item.id)
            ws.cell(row=row_idx, column=2, value=item.full_name)
            ws.cell(row=row_idx, column=3, value=item.department)
            ws.cell(row=row_idx, column=4, value=item.role)
            ws.cell(row=row_idx, column=5, value=item.email)
            ws.cell(row=row_idx, column=6, value=item.phone)

    # Export Locations
    if "locations" in data_dict and data_dict["locations"]:
        ws = wb.create_sheet("Locations")
        columns = ["ID", "Site Name", "Rack Name", "Room", "Floor", "Network Zone", "VLAN ID", "Subnet"]
        style_header_row(ws, columns)

        for row_idx, item in enumerate(data_dict["locations"], 2):
            ws.cell(row=row_idx, column=1, value=item.id)
            ws.cell(row=row_idx, column=2, value=item.site_name)
            ws.cell(row=row_idx, column=3, value=item.rack_name)
            ws.cell(row=row_idx, column=4, value=item.room)
            ws.cell(row=row_idx, column=5, value=item.floor)
            ws.cell(row=row_idx, column=6, value=item.network_zone)
            ws.cell(row=row_idx, column=7, value=item.vlan_id)
            ws.cell(row=row_idx, column=8, value=item.subnet)

    # Export Network Zones
    if "zones" in data_dict and data_dict["zones"]:
        ws = wb.create_sheet("Network Zones")
        columns = ["ID", "Zone Name"]
        style_header_row(ws, columns)

        for row_idx, item in enumerate(data_dict["zones"], 2):
            ws.cell(row=row_idx, column=1, value=item.id)
            ws.cell(row=row_idx, column=2, value=item.zone_name)

    # Export OS Catalog
    if "os_catalog" in data_dict and data_dict["os_catalog"]:
        ws = wb.create_sheet("OS Catalog")
        columns = ["ID", "OS Name"]
        style_header_row(ws, columns)

        for row_idx, item in enumerate(data_dict["os_catalog"], 2):
            ws.cell(row=row_idx, column=1, value=item.id)
            ws.cell(row=row_idx, column=2, value=item.os_name)

    # Export Vendors
    if "vendors" in data_dict and data_dict["vendors"]:
        ws = wb.create_sheet("Vendors")
        columns = ["ID", "Vendor Name"]
        style_header_row(ws, columns)

        for row_idx, item in enumerate(data_dict["vendors"], 2):
            ws.cell(row=row_idx, column=1, value=item.id)
            ws.cell(row=row_idx, column=2, value=item.vendor_name)

    # Export Dependencies
    # if "dependencies" in data_dict and data_dict["dependencies"]:
    #     ws = wb.create_sheet("Dependencies")
    #     columns = ["ID", "Asset ID", "Depends On ID", "Relation Type", "Description"]
    #     style_header_row(ws, columns)

    #     for row_idx, item in enumerate(data_dict["dependencies"], 2):
    #         ws.cell(row=row_idx, column=1, value=item.id)
    #         ws.cell(row=row_idx, column=2, value=item.asset_id)
    #         ws.cell(row=row_idx, column=3, value=item.depends_on_id)
    #         ws.cell(row=row_idx, column=4, value=item.relation_type.value if hasattr(item.relation_type, 'value') else item.relation_type)
    #         ws.cell(row=row_idx, column=5, value=item.description)

    # If no sheets were created, create an empty one
    if len(wb.worksheets) == 0:
        ws = wb.create_sheet("Empty")
        ws.cell(row=1, column=1, value="No data to export")

    # Save to BytesIO
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    return output


def create_asset_requirements_template() -> BytesIO:
    """
    Create an empty Excel template for asset requirements import

    Returns:
        BytesIO object containing the template Excel file with all sheets
    """
    wb = Workbook()
    # Remove default sheet
    wb.remove(wb.active)

    # Asset Types template
    ws = wb.create_sheet("Asset Types")
    columns = ["ID", "Type Name", "Category", "Description"]
    style_header_row(ws, columns)

    # Owners template
    ws = wb.create_sheet("Owners")
    columns = ["ID", "Full Name", "Department", "Role", "Email", "Phone"]
    style_header_row(ws, columns)

    # Locations template
    ws = wb.create_sheet("Locations")
    columns = ["ID", "Site Name", "Rack Name", "Room", "Floor", "Network Zone", "VLAN ID", "Subnet"]
    style_header_row(ws, columns)

    # Network Zones template
    ws = wb.create_sheet("Network Zones")
    columns = ["ID", "Zone Name"]
    style_header_row(ws, columns)

    # OS Catalog template
    ws = wb.create_sheet("OS Catalog")
    columns = ["ID", "OS Name"]
    style_header_row(ws, columns)

    # Vendors template
    ws = wb.create_sheet("Vendors")
    columns = ["ID", "Vendor Name"]
    style_header_row(ws, columns)

    # Dependencies template
    # ws = wb.create_sheet("Dependencies")
    # columns = ["ID", "Asset ID", "Depends On ID", "Relation Type", "Description"]
    # style_header_row(ws, columns)

    # Save to BytesIO
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    return output


def import_asset_requirements_from_excel(file_content: BytesIO, db_session, current_user) -> Dict[str, Any]:
    """
    Import asset requirements from an Excel file with multiple sheets

    Args:
        file_content: BytesIO object containing the Excel file
        db_session: Database session
        current_user: Current authenticated user

    Returns:
        Dictionary with import results for each sheet
    """
    from openpyxl import load_workbook
    from app.models import AssetType, AssetOwner, AssetLocation, NetworkZone, OSCatalog, VendorCatalog, AssetDependency
    from app.models.enums import RelationTypeEnum

    results = {
        "asset_types": {"created": 0, "updated": 0, "skipped": 0, "errors": []},
        "owners": {"created": 0, "updated": 0, "skipped": 0, "errors": []},
        "locations": {"created": 0, "updated": 0, "skipped": 0, "errors": []},
        "zones": {"created": 0, "updated": 0, "skipped": 0, "errors": []},
        "os_catalog": {"created": 0, "updated": 0, "skipped": 0, "errors": []},
        "vendors": {"created": 0, "updated": 0, "skipped": 0, "errors": []},
        # "dependencies": {"created": 0, "updated": 0, "skipped": 0, "errors": []},
    }

    try:
        wb = load_workbook(file_content, data_only=True)

        # Process Asset Types sheet
        if "Asset Types" in wb.sheetnames:
            ws = wb["Asset Types"]
            for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
                try:
                    if not row[1]:  # Skip if Type Name is empty
                        results["asset_types"]["skipped"] += 1
                        continue

                    data = {
                        "type_name": row[1],
                        "category": row[2],
                        "description": row[3] if len(row) > 3 else None
                    }

                    # Check if exists by ID or name
                    existing = None
                    if row[0]:  # ID provided
                        existing = db_session.query(AssetType).filter(AssetType.id == row[0]).first()
                    if not existing:
                        existing = db_session.query(AssetType).filter(AssetType.type_name == data["type_name"]).first()

                    if existing:
                        for key, value in data.items():
                            if value is not None:
                                setattr(existing, key, value)
                        results["asset_types"]["updated"] += 1
                    else:
                        new_item = AssetType(**data)
                        db_session.add(new_item)
                        results["asset_types"]["created"] += 1

                except Exception as e:
                    results["asset_types"]["errors"].append(f"Row {row_idx}: {str(e)}")

        # Process Owners sheet
        if "Owners" in wb.sheetnames:
            ws = wb["Owners"]
            for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
                try:
                    if not row[1]:  # Skip if Full Name is empty
                        results["owners"]["skipped"] += 1
                        continue

                    data = {
                        "full_name": row[1],
                        "department": row[2] if len(row) > 2 else None,
                        "role": row[3] if len(row) > 3 else None,
                        "email": row[4] if len(row) > 4 else None,
                        "phone": row[5] if len(row) > 5 else None,
                        "user_id": current_user.id
                    }

                    existing = None
                    if row[0]:
                        existing = db_session.query(AssetOwner).filter(AssetOwner.id == row[0]).first()
                    if not existing:
                        existing = db_session.query(AssetOwner).filter(
                            AssetOwner.full_name == data["full_name"],
                            AssetOwner.user_id == current_user.id
                        ).first()

                    if existing:
                        for key, value in data.items():
                            if value is not None and key != "user_id":
                                setattr(existing, key, value)
                        results["owners"]["updated"] += 1
                    else:
                        new_item = AssetOwner(**data)
                        db_session.add(new_item)
                        results["owners"]["created"] += 1

                except Exception as e:
                    results["owners"]["errors"].append(f"Row {row_idx}: {str(e)}")

        # Process Locations sheet
        if "Locations" in wb.sheetnames:
            ws = wb["Locations"]
            for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
                try:
                    if not row[1]:  # Skip if Site Name is empty
                        results["locations"]["skipped"] += 1
                        continue

                    data = {
                        "site_name": row[1],
                        "rack_name": row[2] if len(row) > 2 else None,
                        "room": row[3] if len(row) > 3 else None,
                        "floor": row[4] if len(row) > 4 else None,
                        "network_zone": row[5] if len(row) > 5 else None,
                        "vlan_id": row[6] if len(row) > 6 else None,
                        "subnet": row[7] if len(row) > 7 else None,
                        "user_id": current_user.id
                    }

                    existing = None
                    if row[0]:
                        existing = db_session.query(AssetLocation).filter(AssetLocation.id == row[0]).first()
                    if not existing:
                        existing = db_session.query(AssetLocation).filter(
                            AssetLocation.site_name == data["site_name"],
                            AssetLocation.user_id == current_user.id
                        ).first()

                    if existing:
                        for key, value in data.items():
                            if value is not None and key != "user_id":
                                setattr(existing, key, value)
                        results["locations"]["updated"] += 1
                    else:
                        new_item = AssetLocation(**data)
                        db_session.add(new_item)
                        results["locations"]["created"] += 1

                except Exception as e:
                    results["locations"]["errors"].append(f"Row {row_idx}: {str(e)}")

        # Process Network Zones sheet
        if "Network Zones" in wb.sheetnames:
            ws = wb["Network Zones"]
            for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
                try:
                    if not row[1]:  # Skip if Zone Name is empty
                        results["zones"]["skipped"] += 1
                        continue

                    data = {
                        "zone_name": row[1]
                    }

                    existing = None
                    if row[0]:
                        existing = db_session.query(NetworkZone).filter(NetworkZone.id == row[0]).first()
                    if not existing:
                        existing = db_session.query(NetworkZone).filter(NetworkZone.zone_name == data["zone_name"]).first()

                    if existing:
                        for key, value in data.items():
                            if value is not None:
                                setattr(existing, key, value)
                        results["zones"]["updated"] += 1
                    else:
                        new_item = NetworkZone(**data)
                        db_session.add(new_item)
                        results["zones"]["created"] += 1

                except Exception as e:
                    results["zones"]["errors"].append(f"Row {row_idx}: {str(e)}")

        # Process OS Catalog sheet
        if "OS Catalog" in wb.sheetnames:
            ws = wb["OS Catalog"]
            for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
                try:
                    if not row[1]:  # Skip if OS Name is empty
                        results["os_catalog"]["skipped"] += 1
                        continue

                    data = {
                        "os_name": row[1]
                    }

                    existing = None
                    if row[0]:
                        existing = db_session.query(OSCatalog).filter(OSCatalog.id == row[0]).first()
                    if not existing:
                        existing = db_session.query(OSCatalog).filter(OSCatalog.os_name == data["os_name"]).first()

                    if existing:
                        for key, value in data.items():
                            if value is not None:
                                setattr(existing, key, value)
                        results["os_catalog"]["updated"] += 1
                    else:
                        new_item = OSCatalog(**data)
                        db_session.add(new_item)
                        results["os_catalog"]["created"] += 1

                except Exception as e:
                    results["os_catalog"]["errors"].append(f"Row {row_idx}: {str(e)}")

        # Process Vendors sheet
        if "Vendors" in wb.sheetnames:
            ws = wb["Vendors"]
            for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
                try:
                    if not row[1]:  # Skip if Vendor Name is empty
                        results["vendors"]["skipped"] += 1
                        continue

                    data = {
                        "vendor_name": row[1]
                    }

                    existing = None
                    if row[0]:
                        existing = db_session.query(VendorCatalog).filter(VendorCatalog.id == row[0]).first()
                    if not existing:
                        existing = db_session.query(VendorCatalog).filter(VendorCatalog.vendor_name == data["vendor_name"]).first()

                    if existing:
                        for key, value in data.items():
                            if value is not None:
                                setattr(existing, key, value)
                        results["vendors"]["updated"] += 1
                    else:
                        new_item = VendorCatalog(**data)
                        db_session.add(new_item)
                        results["vendors"]["created"] += 1

                except Exception as e:
                    results["vendors"]["errors"].append(f"Row {row_idx}: {str(e)}")

        # Process Dependencies sheet
        # if "Dependencies" in wb.sheetnames:
        #     ws = wb["Dependencies"]
        #     for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
        #         try:
        #             if not row[1] or not row[2]:  # Skip if Asset ID or Depends On ID is empty
        #                 results["dependencies"]["skipped"] += 1
        #                 continue

        #             # Convert relation type to enum
        #             relation_type = row[3] if len(row) > 3 else None
        #             if relation_type and isinstance(relation_type, str):
        #                 try:
        #                     relation_type = RelationTypeEnum(relation_type)
        #                 except ValueError:
        #                     relation_type = None

        #             data = {
        #                 "asset_id": int(row[1]),
        #                 "depends_on_id": int(row[2]),
        #                 "relation_type": relation_type,
        #                 "description": row[4] if len(row) > 4 else None
        #             }

        #             existing = None
        #             if row[0]:
        #                 existing = db_session.query(AssetDependency).filter(AssetDependency.id == row[0]).first()
        #             if not existing:
        #                 existing = db_session.query(AssetDependency).filter(
        #                     AssetDependency.asset_id == data["asset_id"],
        #                     AssetDependency.depends_on_id == data["depends_on_id"]
        #                 ).first()

        #             if existing:
        #                 for key, value in data.items():
        #                     if value is not None:
        #                         setattr(existing, key, value)
        #                 results["dependencies"]["updated"] += 1
        #             else:
        #                 new_item = AssetDependency(**data)
        #                 db_session.add(new_item)
        #                 results["dependencies"]["created"] += 1

        #         except Exception as e:
        #             results["dependencies"]["errors"].append(f"Row {row_idx}: {str(e)}")

        # Commit all changes
        db_session.commit()

    except Exception as e:
        db_session.rollback()
        for sheet in results:
            results[sheet]["errors"].append(f"Fatal error: {str(e)}")

    return results
