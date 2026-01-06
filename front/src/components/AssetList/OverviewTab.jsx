import React from "react";

export const OverviewTab = ({ assets, onEdit, onDelete, isNewAsset }) => {
    return (
        <div className="asset-table-container">
            <table className="assets-table">
                <thead>
                <tr>
                    <th>ID</th>
                    <th>Asset Name</th>
                    <th>Hostname</th>
                    <th>Type</th>
                    <th>Network Zone</th>
                    <th>Vendor</th>
                    <th>Model</th>
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
                        <td>{asset.hostname || "-"}</td>
                        <td>{asset.asset_type_name || "-"}</td>
                        <td>{asset.asset_role || "-"}</td>
                        <td>{asset.manufacturer || "-"}</td>
                        <td>{asset.model || "-"}</td>
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