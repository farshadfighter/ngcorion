import React, { useState } from "react";
import { ManagePortsModal } from "./ManagePortsModal";

export const NetworkSystemTab = ({ assets, onEdit, onDelete, isNewAsset }) => {
    const [selectedAsset, setSelectedAsset] = useState(null);
    const [showPortsModal, setShowPortsModal] = useState(false);

    // Sort states
    const [sortColumn, setSortColumn] = useState(null);
    const [sortDirection, setSortDirection] = useState("asc");

    const handleManagePorts = (asset) => {
        setSelectedAsset(asset);
        setShowPortsModal(true);
    };

    const handleClosePortsModal = () => {
        setSelectedAsset(null);
        setShowPortsModal(false);
    };

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
                    <th onClick={() => handleSort("serial_number")} style={{ cursor: "pointer" }}>
                        Serial {renderSortIcon("serial_number")}
                    </th>
                    <th onClick={() => handleSort("os_name")} style={{ cursor: "pointer" }}>
                        OS {renderSortIcon("os_name")}
                    </th>
                    <th onClick={() => handleSort("ip_address")} style={{ cursor: "pointer" }}>
                        IP Address {renderSortIcon("ip_address")}
                    </th>
                    <th onClick={() => handleSort("mac_address")} style={{ cursor: "pointer" }}>
                        MAC Address {renderSortIcon("mac_address")}
                    </th>
                    <th>Ports</th>
                    <th>Actions</th>
                </tr>
                </thead>
                <tbody>
                {sortedAssets.map((asset) => (
                    <tr key={asset.id} className={isNewAsset(asset.id) ? "new-asset-row" : ""}>
                        <td>{asset.id}</td>
                        <td>{asset.asset_name}</td>
                        <td>{asset.serial_number || "-"}</td>
                        <td>{asset.os_name || "-"}</td>
                        <td>{asset.ip_address || "-"}</td>
                        <td>{asset.mac_address || "-"}</td>
                        <td>
                            <button className="btn-ports" onClick={() => handleManagePorts(asset)}>
                                Manage Ports
                            </button>
                        </td>
                        <td className="actions-cell">
                            <button className="btn-edit" onClick={() => onEdit(asset)}>Edit</button>
                            <button className="btn-delete" onClick={() => onDelete(asset.id)}>Delete</button>
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>

            {showPortsModal && selectedAsset && (
                <ManagePortsModal
                    asset={selectedAsset}
                    onClose={handleClosePortsModal}
                />
            )}
        </div>
    );
};
