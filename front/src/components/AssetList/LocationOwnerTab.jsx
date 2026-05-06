import React, { useState } from "react";

export const LocationOwnerTab = ({ assets, onEdit, onDelete, isNewAsset }) => {
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
                    <th onClick={() => handleSort("location_name")} style={{ cursor: "pointer" }}>
                        Location {renderSortIcon("location_name")}
                    </th>
                    <th onClick={() => handleSort("owner_name")} style={{ cursor: "pointer" }}>
                        Owner {renderSortIcon("owner_name")}
                    </th>
                    <th onClick={() => handleSort("status")} style={{ cursor: "pointer" }}>
                        Status {renderSortIcon("status")}
                    </th>
                    <th>Actions</th>
                </tr>
                </thead>
                <tbody>
                {sortedAssets.map((asset) => (
                    <tr key={asset.id} className={isNewAsset(asset.id) ? "new-asset-row" : ""}>
                        <td>{asset.id}</td>
                        <td>{asset.asset_name}</td>
                        <td>{asset.location_name || "-"}</td>
                        <td>{asset.owner_name || "-"}</td>
                        <td>
                <span className={`status-badge status-${(asset.status || "unknown").toLowerCase().replace(/\s+/g, '-')}`}>
                  {asset.status || "Unknown"}
                </span>
                        </td>
                        <td className="actions-cell">
                            <button className="btn-icon" onClick={() => onEdit(asset)}><i className="fa-solid fa-pen"></i>
                            </button>
                            <button className="btn-icon" onClick={() => onDelete(asset.id)}>
                                <i className="fa-solid fa-trash"></i>
                            </button>
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>
        </div>
    );
};
