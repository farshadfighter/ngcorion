import React, { useState } from "react";
import { isAssetComplete } from "./assetCompleteness";

export const OverviewTab = ({ assets, onEdit, onDelete, isNewAsset, selectedIds, onToggleSelect, onToggleAll, allSelected }) => {
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

    // Spreading a non-array throws, and the caller's data is only as
    // reliable as the API response it came from.
    const rows = Array.isArray(assets) ? assets : [];
    const sortedAssets = [...rows].sort((a, b) => {
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
                    <th style={{ width: "4px", padding: 0 }}></th>
                    <th style={{ width: "40px" }}>
                        <input type="checkbox" checked={allSelected} onChange={onToggleAll}
                               title="Select all" style={{ cursor: "pointer", accentColor: "#1e3a5f" }} />
                    </th>
                    <th>Number</th>
                    <th onClick={() => handleSort("asset_name")} style={{ cursor: "pointer" }}>Asset Name {renderSortIcon("asset_name")}</th>
                    <th onClick={() => handleSort("hostname")} style={{ cursor: "pointer" }}>Hostname {renderSortIcon("hostname")}</th>
                    <th onClick={() => handleSort("asset_type_name")} style={{ cursor: "pointer" }}>Type {renderSortIcon("asset_type_name")}</th>
                    <th onClick={() => handleSort("asset_role")} style={{ cursor: "pointer" }}>Zone {renderSortIcon("asset_role")}</th>
                    <th onClick={() => handleSort("manufacturer")} style={{ cursor: "pointer" }}>Manufacturer {renderSortIcon("manufacturer")}</th>
                    <th onClick={() => handleSort("model")} style={{ cursor: "pointer" }}>Model {renderSortIcon("model")}</th>
                    <th>Actions</th>
                </tr>
                </thead>
                <tbody>
                {sortedAssets.map((asset, index) => {
                    const complete = isAssetComplete(asset);
                    return (
                        <tr
                            key={asset.id}
                            className={`${isNewAsset(asset) ? "new-asset-row" : ""} ${selectedIds.has(asset.id) ? "selected-row" : ""}`}
                            style={{ background: selectedIds.has(asset.id) ? "#eef2f7" : undefined }}
                        >
                            {/* نوار رنگی completeness */}
                            <td className={`completeness-indicator ${complete ? "complete" : "incomplete"}`}></td>
                            <td>
                                <input type="checkbox" checked={selectedIds.has(asset.id)} onChange={() => onToggleSelect(asset.id)}
                                       style={{ cursor: "pointer", accentColor: "#1e3a5f" }} />
                            </td>
                            <td>{index + 1}</td>
                            <td>{asset.asset_name}</td>
                            <td>{asset.hostname || "-"}</td>
                            <td>{asset.asset_type_name || "-"}</td>
                            <td>{asset.asset_role || "-"}</td>
                            <td>{asset.manufacturer || "-"}</td>
                            <td>{asset.model || "-"}</td>
                            <td className="actions-cell">
                                <button className="btn-icon" title="Edit" onClick={() => onEdit(asset)}>
                                    <i className="fa-solid fa-pen"></i>
                                </button>
                                <button className="btn-icon" title="Delete" onClick={() => onDelete(asset.id)}>
                                    <i className="fa-solid fa-trash"></i>
                                </button>
                            </td>
                        </tr>
                    );
                })}
                </tbody>
            </table>
        </div>
    );
};