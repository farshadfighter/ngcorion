import React, { useState } from "react";
import { ManagePortsModal } from "./ManagePortsModal";
import { isAssetComplete } from "./assetCompleteness";

export const NetworkSystemTab = ({ assets, onEdit, onDelete, isNewAsset, selectedIds, onToggleSelect, onToggleAll, allSelected, canDelete = true }) => {
    const [selectedAsset, setSelectedAsset] = useState(null);
    const [showPortsModal, setShowPortsModal] = useState(false);
    const [sortColumn, setSortColumn] = useState(null);
    const [sortDirection, setSortDirection] = useState("asc");

    const handleManagePorts = (asset) => { setSelectedAsset(asset); setShowPortsModal(true); };
    const handleClosePortsModal = () => { setSelectedAsset(null); setShowPortsModal(false); };

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
                    <th onClick={() => handleSort("serial_number")} style={{ cursor: "pointer" }}>Serial {renderSortIcon("serial_number")}</th>
                    <th onClick={() => handleSort("os_name")} style={{ cursor: "pointer" }}>OS {renderSortIcon("os_name")}</th>
                    <th onClick={() => handleSort("ip_address")} style={{ cursor: "pointer" }}>IP Address {renderSortIcon("ip_address")}</th>
                    <th onClick={() => handleSort("mac_address")} style={{ cursor: "pointer" }}>MAC Address {renderSortIcon("mac_address")}</th>
                    <th onClick={() => handleSort("port_count")} style={{ cursor: "pointer" }}>Physical Ports {renderSortIcon("port_count")}</th>
                    <th>Ports</th>
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
                            <td className={`completeness-indicator ${complete ? "complete" : "incomplete"}`}></td>
                            <td>
                                <input type="checkbox" checked={selectedIds.has(asset.id)} onChange={() => onToggleSelect(asset.id)}
                                       style={{ cursor: "pointer", accentColor: "#1e3a5f" }} />
                            </td>
                            <td>{index + 1}</td>
                            <td>{asset.asset_name}</td>
                            <td>{asset.serial_number || "-"}</td>
                            <td>{asset.os_name ? [asset.os_name, asset.os_version].filter(Boolean).join(" ") : "-"}</td>
                            <td>{asset.ip_address || "-"}</td>
                            <td>{asset.mac_address || "-"}</td>
                            <td>{asset.port_count ?? "-"}</td>
                            <td>
                                <button className="btn-icon" onClick={() => handleManagePorts(asset)}>
                                    <i className="fa-solid fa-eye"></i>
                                </button>
                            </td>
                            <td className="actions-cell">
                                <button className="btn-icon" onClick={() => onEdit(asset)}>
                                    <i className="fa-solid fa-pen"></i>
                                </button>
                                {canDelete && (<button className="btn-icon" onClick={() => onDelete(asset.id)}>
                                    <i className="fa-solid fa-trash"></i>
                                </button>)}
                            </td>
                        </tr>
                    );
                })}
                </tbody>
            </table>
            {showPortsModal && selectedAsset && (
                <ManagePortsModal asset={selectedAsset} onClose={handleClosePortsModal} />
            )}
        </div>
    );
};