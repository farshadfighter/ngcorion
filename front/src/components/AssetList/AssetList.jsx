import { useEffect, useState, useRef } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssets, deleteAsset, clearMessages } from "../../store/assetSlice";
import api from "../../config/api";
import { OverviewTab } from "./OverviewTab";
import { NetworkSystemTab } from "./NetworkSystemTab";
import { LocationOwnerTab } from "./LocationOwnerTab";
import { SecurityAuditTab } from "./SecurityAuditTab";
import { EditAssetModal } from "./EditAssetModal";
import { AddAssetModal } from "./AddAssetModal";
import "../../assets/AssetList.css"
export const AssetList = () => {
    const dispatch = useDispatch();
    const { assets, isLoading, error, successMessage } = useSelector(
        (state) => state.assets
    );

    const [activeTab, setActiveTab] = useState("overview");
    const [searchQuery, setSearchQuery] = useState("");
    const [sortDir, setSortDir] = useState("asc");
    const [selectedAsset, setSelectedAsset] = useState(null);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [showEditModal, setShowEditModal] = useState(false);
    const [showAddModal, setShowAddModal] = useState(false);
    const [uploading, setUploading] = useState(false);

    const fileInputRef = useRef(null);

    useEffect(() => {
        dispatch(fetchAssets());
    }, [dispatch]);

    useEffect(() => {
        if (successMessage || error) {
            const timer = setTimeout(() => dispatch(clearMessages()), 3000);
            return () => clearTimeout(timer);
        }
    }, [successMessage, error, dispatch]);

    const filteredAssets = Array.isArray(assets)
        ? assets.filter((asset) => {
            const q = searchQuery.toLowerCase();
            return (
                asset.asset_name?.toLowerCase().includes(q) ||
                asset.hostname?.toLowerCase().includes(q) ||
                asset.ip_address?.toLowerCase().includes(q) ||
                asset.serial_number?.toLowerCase().includes(q)
            );
        })
        : [];

    const sortedAssets = [...filteredAssets].sort((a, b) => {
        const aVal = String(a.asset_name || "").toLowerCase();
        const bVal = String(b.asset_name || "").toLowerCase();
        return sortDir === "asc" ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
    });

    const handleEdit = (asset) => {
        setSelectedAsset(asset);
        setShowEditModal(true);
    };

    const handleDeleteClick = (asset) => {
        setSelectedAsset(asset);
        setShowDeleteModal(true);
    };

    const handleDeleteConfirm = () => {
        if (selectedAsset) {
            dispatch(deleteAsset(selectedAsset.id));
            setShowDeleteModal(false);
            setSelectedAsset(null);
        }
    };

    // Check if asset is new (created in last 24 hours)
    const isNewAsset = (asset) => {
        if (!asset.created_at) return false;
        const createdDate = new Date(asset.created_at);
        const now = new Date();
        const hoursDiff = (now - createdDate) / (1000 * 60 * 60);
        return hoursDiff < 24;
    };

    return (
        <div className="asset-list-container">
            {/* Header */}
            <div className="asset-list-header">
                <h1 className="page-title">Asset List</h1>
                <div className="header-actions">
                    <button
                        className="btn-header"
                        onClick={() => fileInputRef.current?.click()}
                        disabled={uploading}
                    >
                        {uploading ? "⏳ Importing..." : "⬇ Import"}
                    </button>

                    <button
                        className="btn-header"
                        onClick={async () => {
                            const res = await api.get("/api/assets/export/excel", { responseType: "blob" });
                            const url = window.URL.createObjectURL(new Blob([res.data]));
                            const link = document.createElement("a");
                            link.href = url;
                            link.setAttribute("download", `assets-${Date.now()}.xlsx`);
                            document.body.appendChild(link);
                            link.click();
                            link.remove();
                            window.URL.revokeObjectURL(url);
                        }}
                    >
                        ⬆ Export
                    </button>

                    <button
                        className="btn-header btn-primary"
                        onClick={() => setShowAddModal(true)}
                    >
                        + Add Asset
                    </button>
                </div>
            </div>

            <input
                ref={fileInputRef}
                type="file"
                accept=".xlsx,.xls"
                style={{ display: "none" }}
                onChange={async (e) => {
                    const file = e.target.files?.[0];
                    if (!file) return;
                    setUploading(true);
                    const formData = new FormData();
                    formData.append("file", file);
                    await api.post("/api/assets/import/excel", formData);
                    await dispatch(fetchAssets());
                    setUploading(false);
                    e.target.value = "";
                }}
            />

            {successMessage && <div className="alert alert-success">{successMessage}</div>}
            {error && <div className="alert alert-error">{error}</div>}

            {/* Tabs - Beautiful Style */}
            <div className="asset-tabs">
                {[
                    { id: "overview", label: "Overview" },
                    { id: "network", label: "Network & System" },
                    { id: "location", label: "Location & Owner" },
                    { id: "security", label: "Security & Audit" },
                ].map((tab) => (
                    <button
                        key={tab.id}
                        className={`asset-tab ${activeTab === tab.id ? "active" : ""}`}
                        onClick={() => setActiveTab(tab.id)}
                    >
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* Search + Sort */}
            <div className="search-sort-container">
                <div className="search-box">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="11" cy="11" r="8" />
                        <path d="M21 21l-4.35-4.35" />
                    </svg>
                    <input
                        className="search-input"
                        placeholder="Search Asset"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                    />
                </div>

                <button
                    className="btn-sort"
                    onClick={() => setSortDir(d => d === "asc" ? "desc" : "asc")}
                >
                    Sort {sortDir === "asc" ? "↑" : "↓"}
                </button>
            </div>

            {isLoading && <div className="loading-spinner">Loading assets...</div>}

            {!isLoading && activeTab === "overview" && (
                <OverviewTab
                    assets={sortedAssets}
                    onEdit={handleEdit}
                    onDelete={handleDeleteClick}
                    isNewAsset={isNewAsset}
                />
            )}
            {!isLoading && activeTab === "network" && (
                <NetworkSystemTab
                    assets={sortedAssets}
                    onEdit={handleEdit}
                    onDelete={handleDeleteClick}
                    isNewAsset={isNewAsset}
                />
            )}
            {!isLoading && activeTab === "location" && (
                <LocationOwnerTab
                    assets={sortedAssets}
                    onEdit={handleEdit}
                    onDelete={handleDeleteClick}
                    isNewAsset={isNewAsset}
                />
            )}
            {!isLoading && activeTab === "security" && (
                <SecurityAuditTab
                    assets={sortedAssets}
                    onEdit={handleEdit}
                    onDelete={handleDeleteClick}
                    isNewAsset={isNewAsset}
                />
            )}

            {/* Delete Modal */}
            {showDeleteModal && (
                <div className="modal-overlay" onClick={() => setShowDeleteModal(false)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Confirm Delete</h3>
                            <button className="modal-close" onClick={() => setShowDeleteModal(false)}>
                                ✕
                            </button>
                        </div>
                        <div className="modal-body">
                            <p>Are you sure you want to delete "{selectedAsset?.asset_name}"?</p>
                            <p style={{ color: "#dc3545", fontSize: "13px", marginTop: "8px" }}>
                                This action cannot be undone.
                            </p>
                        </div>
                        <div className="modal-actions">
                            <button className="btn-cancel" onClick={() => setShowDeleteModal(false)}>
                                Cancel
                            </button>
                            <button className="btn-delete" onClick={handleDeleteConfirm}>
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {showEditModal && selectedAsset && (
                <EditAssetModal
                    asset={selectedAsset}
                    isOpen={showEditModal}
                    onClose={() => {
                        setShowEditModal(false);
                        setSelectedAsset(null);
                    }}
                />
            )}

            <AddAssetModal isOpen={showAddModal} onClose={() => setShowAddModal(false)} />
        </div>
    );
};
