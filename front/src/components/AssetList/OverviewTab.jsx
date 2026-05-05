import React, { useState } from "react";

export const OverviewTab = ({ assets, onEdit, onDelete, isNewAsset }) => {
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
                    <th onClick={() => handleSort("hostname")} style={{ cursor: "pointer" }}>
                        Hostname {renderSortIcon("hostname")}
                    </th>
                    <th onClick={() => handleSort("asset_type_name")} style={{ cursor: "pointer" }}>
                        Type {renderSortIcon("asset_type_name")}
                    </th>
                    <th onClick={() => handleSort("asset_role")} style={{ cursor: "pointer" }}>
                        Role {renderSortIcon("asset_role")}
                    </th>
                    <th onClick={() => handleSort("manufacturer")} style={{ cursor: "pointer" }}>
                        Manufacturer {renderSortIcon("manufacturer")}
                    </th>
                    <th onClick={() => handleSort("model")} style={{ cursor: "pointer" }}>
                        Model {renderSortIcon("model")}
                    </th>
                    <th>Actions</th>
                </tr>
                </thead>
                <tbody>
                {sortedAssets.map((asset) => (
                    <tr key={asset.id} className={isNewAsset(asset.id) ? "new-asset-row" : ""}>
                        <td>{asset.id}</td>
                        <td>{asset.asset_name}</td>
                        <td>{asset.hostname || "-"}</td>
                        <td>{asset.asset_type_name || "-"}</td>
                        <td>{asset.asset_role || "-"}</td>
                        <td>{asset.manufacturer || "-"}</td>
                        <td>{asset.model || "-"}</td>
                        <td className="actions-cell">
                            <button className="btn-edit" onClick={() => onEdit(asset)}>Edit</button>
                            <button className="btn-delete" onClick={() => onDelete(asset.id)}>Delete</button>
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>
        </div>
    );
};
