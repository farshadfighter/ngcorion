import React, { useState } from "react";

const DescriptionModal = ({ description, assetName, onClose }) => (
    <div style={{ position: "fixed", inset: 0, backgroundColor: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }} onClick={onClose}>
        <div style={{ backgroundColor: "#fff", borderRadius: "12px", width: "420px", maxWidth: "90vw", boxShadow: "0 20px 60px rgba(0,0,0,0.3)", overflow: "hidden" }} onClick={(e) => e.stopPropagation()}>
            <div style={{ backgroundColor: "#1e3a5f", padding: "16px 20px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <i className="fa-solid fa-circle-info" style={{ color: "#fff", fontSize: "16px" }}></i>
                    <span style={{ color: "#fff", fontWeight: "600", fontSize: "15px" }}>Description</span>
                </div>
                <button onClick={onClose} style={{ background: "rgba(255,255,255,0.15)", border: "none", borderRadius: "6px", color: "#fff", width: "28px", height: "28px", cursor: "pointer", fontSize: "14px", display: "flex", alignItems: "center", justifyContent: "center" }}>✕</button>
            </div>
            <div style={{ backgroundColor: "#f0f4f8", padding: "10px 20px", borderBottom: "1px solid #e2e8f0" }}>
                <span style={{ fontSize: "12px", color: "#64748b", fontWeight: "500" }}>Asset:</span>
                <span style={{ fontSize: "13px", color: "#1e3a5f", fontWeight: "600", marginLeft: "6px" }}>{assetName}</span>
            </div>
            <div style={{ padding: "20px" }}>
                <p style={{ margin: 0, fontSize: "14px", color: "#374151", lineHeight: "1.7", whiteSpace: "pre-wrap" }}>{description}</p>
            </div>
            <div style={{ padding: "12px 20px", borderTop: "1px solid #e2e8f0", display: "flex", justifyContent: "flex-end" }}>
                <button onClick={onClose} style={{ backgroundColor: "#1e3a5f", color: "#fff", border: "none", borderRadius: "8px", padding: "8px 20px", fontSize: "13px", fontWeight: "500", cursor: "pointer" }}>Close</button>
            </div>
        </div>
    </div>
);

export const SecurityAuditTab = ({ assets, onEdit, onDelete, isNewAsset, selectedIds, onToggleSelect, onToggleAll, allSelected }) => {
    const [sortColumn, setSortColumn] = useState(null);
    const [sortDirection, setSortDirection] = useState("asc");
    const [selectedDescription, setSelectedDescription] = useState(null);
    const [selectedAssetName, setSelectedAssetName] = useState("");

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
        <>
            <div className="asset-table-container">
                <table className="assets-table">
                    <thead>
                    <tr>
                        <th style={{ width: "40px" }}>
                            <input type="checkbox" checked={allSelected} onChange={onToggleAll}
                                   title="Select all" style={{ cursor: "pointer", accentColor: "#1e3a5f" }} />
                        </th>
                        <th>Number</th>
                        <th onClick={() => handleSort("asset_name")} style={{ cursor: "pointer" }}>Asset Name {renderSortIcon("asset_name")}</th>
                        <th onClick={() => handleSort("confidentiality_level")} style={{ cursor: "pointer" }}>Confidentiality Level {renderSortIcon("confidentiality_level")}</th>
                        <th onClick={() => handleSort("risk_level")} style={{ cursor: "pointer" }}>Risk Level {renderSortIcon("risk_level")}</th>
                        <th onClick={() => handleSort("last_audit_date")} style={{ cursor: "pointer" }}>Last Audit Date {renderSortIcon("last_audit_date")}</th>
                        <th onClick={() => handleSort("last_patch_date")} style={{ cursor: "pointer" }}>Last Patch Date {renderSortIcon("last_patch_date")}</th>
                        <th onClick={() => handleSort("asset_value")} style={{ cursor: "pointer" }}>Asset Value {renderSortIcon("asset_value")}</th>
                        <th>Description</th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {sortedAssets.map((asset, index) => (
                        <tr key={asset.id} className={`${isNewAsset(asset) ? "new-asset-row" : ""} ${selectedIds.has(asset.id) ? "selected-row" : ""}`}
                            style={{ background: selectedIds.has(asset.id) ? "#eef2f7" : undefined }}>
                            <td>
                                <input type="checkbox" checked={selectedIds.has(asset.id)} onChange={() => onToggleSelect(asset.id)}
                                       style={{ cursor: "pointer", accentColor: "#1e3a5f" }} />
                            </td>
                            <td>{index + 1}</td>
                            <td>{asset.asset_name}</td>
                            <td>{asset.confidentiality_level || "-"}</td>
                            <td>{asset.risk_level || "-"}</td>
                            <td>{asset.last_audit_date || "-"}</td>
                            <td>{asset.last_patch_date || "-"}</td>
                            <td>{asset.asset_value ? `$${asset.asset_value}` : "-"}</td>
                            <td>
                                {asset.description ? (
                                    <button className="btn-icon" onClick={() => { setSelectedDescription(asset.description); setSelectedAssetName(asset.asset_name); }} title="View description">
                                        <i className="fa-solid fa-circle-info" style={{ color: "#1e3a5f" }}></i>
                                    </button>
                                ) : "-"}
                            </td>
                            <td className="actions-cell">
                                <button className="btn-icon" onClick={() => onEdit(asset)}>
                                    <i className="fa-solid fa-pen"></i>
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
            {selectedDescription && (
                <DescriptionModal description={selectedDescription} assetName={selectedAssetName}
                                  onClose={() => { setSelectedDescription(null); setSelectedAssetName(""); }} />
            )}
        </>
    );
};