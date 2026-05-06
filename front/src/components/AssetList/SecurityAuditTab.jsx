import React, { useState } from "react";

export const SecurityAuditTab = ({ assets, onEdit, onDelete, isNewAsset }) => {
    const [sortColumn, setSortColumn] = useState(null);
    const [sortDirection, setSortDirection] = useState("asc");

    const handleSort = (column) => {
        if (sortColumn === column) {
            setSortDirection(sortDirection === "asc" ? "desc" : "asc");
        } else {
            setSortColumn(column);
            setSortDirection("asc");
        }
    };

    const renderSortIcon = (column) => {
        if (sortColumn !== column) return " ↕";
        return sortDirection === "asc" ? " ↑" : " ↓";
    };

    const sortedAssets = [...assets].sort((a, b) => {
        if (!sortColumn) return 0;

        const aValue = a[sortColumn] || "";
        const bValue = b[sortColumn] || "";

        if (aValue < bValue) return sortDirection === "asc" ? -1 : 1;
        if (aValue > bValue) return sortDirection === "asc" ? 1 : -1;
        return 0;
    });

    return (
        <div className="asset-table-container">
            <table className="assets-table">
                <thead>
                <tr>
                    <th onClick={() => handleSort("id")} style={{ cursor: "pointer" }}>
                        ID {renderSortIcon("id")}
                    </th>
                    <th onClick={() => handleSort("asset_name")} style={{ cursor: "pointer" }}>
                        Asset Name {renderSortIcon("asset_name")}
                    </th>
                    <th onClick={() => handleSort("confidentiality_level")} style={{ cursor: "pointer" }}>
                        Confidentiality Level {renderSortIcon("confidentiality_level")}
                    </th>
                    <th onClick={() => handleSort("risk_level")} style={{ cursor: "pointer" }}>
                        Risk Level {renderSortIcon("risk_level")}
                    </th>
                    <th onClick={() => handleSort("last_audit_date")} style={{ cursor: "pointer" }}>
                        Last Audit Date {renderSortIcon("last_audit_date")}
                    </th>
                    <th onClick={() => handleSort("last_patch_date")} style={{ cursor: "pointer" }}>
                        Last Patch Date {renderSortIcon("last_patch_date")}
                    </th>
                    <th>Actions</th>
                </tr>
                </thead>
                <tbody>
                {sortedAssets.map((asset) => (
                    <tr key={asset.id} className={isNewAsset(asset.id) ? "new-asset-row" : ""}>
                        <td>{asset.id}</td>
                        <td>{asset.asset_name}</td>
                        <td>{asset.confidentiality_level || "-"}</td>
                        <td>{asset.risk_level || "-"}</td>
                        <td>{asset.last_audit_date || "-"}</td>
                        <td>{asset.last_patch_date || "-"}</td>
                        <td className="actions-cell">
                            <button className="btn-icon" onClick={() => onEdit(asset)}>
                                <i className="fa-solid fa-pen"></i>
                            </button>
                            <button className="btn-icon" onClick={() => onDelete(asset.id)}><i className="fa-solid fa-trash"></i>
                            </button>
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>
        </div>
    );
};
