import React, { useState } from "react";
import { ManagePortsModal } from "./ManagePortsModal";

export const NetworkSystemTab = ({ assets, onEdit, onDelete, isNewAsset }) => {
    const [selectedAsset, setSelectedAsset] = useState(null);
    const [showPortsModal, setShowPortsModal] = useState(false);

    const handleManagePorts = (asset) => {
        setSelectedAsset(asset);
        setShowPortsModal(true);
    };

    const handleClosePortsModal = () => {
        setShowPortsModal(false);
        setSelectedAsset(null);
    };


    return (
        <>
            <div className="asset-table-container">
                <table className="assets-table">
                    <thead>
                    <tr>
                        <th>ID</th>
                        <th>Asset Name</th>
                        <th>Serial</th>
                        <th>OS</th>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Ports</th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {assets.map((asset) => (
                        <tr
                            key={asset.id}
                            className={isNewAsset(asset) ? "row-new" : "row-normal"}
                        >
                            <td>{asset.id}</td>
                            <td>{asset.asset_name}</td>
                            <td>{asset.serial_number || "-"}</td>
                            <td>{asset.os_name || "-"}</td>
                            <td>{asset.ip_address || "-"}</td>
                            <td>{asset.mac_address || "-"}</td>
                            <td>
                                <button
                                    className="btn-icon btn-ports"
                                    onClick={() => {
                                        handleManagePorts(asset);
                                    }}
                                    title="Manage Ports"
                                >
                                    <img src="/icons/networkPort.png" alt="ports" style={{width: '20px', height: '20px'}} />
                                </button>
                            </td>
                            <td>
                                <button className="btn-icon btn-edit" onClick={() => onEdit(asset)}>
                                    <img src="/icons/edetie.svg" alt="edit" />
                                </button>
                                <button className="btn-icon btn-delete" onClick={() => onDelete(asset)}>
                                    <img src="/icons/delete.svg" alt="delete" />
                                </button>
                            </td>
                        </tr>
                    ))}
                    </tbody>
                </table>
            </div>

            {showPortsModal && selectedAsset && (
                <ManagePortsModal
                    asset={selectedAsset}
                    onClose={handleClosePortsModal}
                />
            )}
        </>
    );
};