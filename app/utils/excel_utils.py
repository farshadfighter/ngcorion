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
