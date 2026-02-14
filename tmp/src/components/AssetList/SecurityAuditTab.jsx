import React from "react";

export const SecurityAuditTab = ({ assets, onEdit, onDelete, isNewAsset }) => {
    return (
        <div className="table-container">
            <table className="assets-table">
                <thead>
                <tr>
                    <th>ID</th>
                    <th>Asset Name</th>
                    <th>Confidentiality</th>
                    <th>Risk Level</th>
                    <th>Last Audit</th>
                    <th>Last Patch</th>
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
                        <td>{asset.confidentiality_level || "-"}</td>
                        <td>
                            <span className={`risk-badge risk-${asset.risk_level}`}>
                                {asset.risk_level || "-"}
                            </span>
                        </td>
                        <td>{asset.last_audit_date || "-"}</td>
                        <td>{asset.last_patch_date || "-"}</td>
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
