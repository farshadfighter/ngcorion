import React from "react";

export const LocationOwnerTab = ({ assets, onEdit, onDelete, isNewAsset }) => {
    return (
        <div className="asset-table-container">
            <table className="assets-table">
                <thead>
                <tr>
                    <th>ID</th>
                    <th>Asset Name</th>
                    <th>Location</th>
                    <th>Owner</th>
                    <th>Status</th>
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
                        <td>{asset.location_id || "-"}</td>
                        <td>{asset.owner_id || "-"}</td>
                        <td>
                            <span className={`status-badge status-${asset.status}`}>
                                {asset.status || "unknown"}
                            </span>
                        </td>
                        <td>
                            <button className="btn-icon btn-edit" onClick={() => onEdit(asset)}>
                                <img src={"/icons/edetie.svg"} alt={"edit"} />
                            </button>
                            <button className="btn-icon btn-delete" onClick={() => onDelete(asset)}>
                                <img src={"/icons/delete.svg"} alt={"delete"} />
                            </button>
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>
        </div>
    );
};
