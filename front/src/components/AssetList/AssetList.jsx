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

    const sortedAssets = [...filteredAssets].sort((a, b) =>
        sortDir === "asc"
            ? a.asset_name.localeCompare(b.asset_name)
            : b.asset_name.localeCompare(a.asset_name)
    );

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

    return (
        <div className="asset-requirement-container">
            {/* Header */}
            <div className="requirement-header">
                <div className="requirement-actions">
                    <button
                        className="btn-import"
                        onClick={() => fileInputRef.current?.click()}
                        disabled={uploading}
                    >
                        {uploading ? "⏳ Importing..." : "⬇ Import"}
                    </button>

                    <button className="btn-export" onClick={async () => {
                        const res = await api.get("/api/assets/export/excel", { responseType: "blob" });
                        const url = window.URL.createObjectURL(new Blob([res.data]));
                        const link = document.createElement("a");
                        link.href = url;
                        link.setAttribute("download", `assets-${Date.now()}.xlsx`);
                        document.body.appendChild(link);
                        link.click();
                        link.remove();
                        window.URL.revokeObjectURL(url);
                    }}>
                        ⬆ Export
                    </button>

                    <button className="btn-add" onClick={() => setShowAddModal(true)}>
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
                    dispatch(fetchAssets());
                    setUploading(false);
                    e.target.value = "";
                }}
            />

            {successMessage && <div className="alert alert-success">{successMessage}</div>}
            {error && <div className="alert alert-error">{error}</div>}

            {/* Tabs */}
            <div className="requirement-tabs">
                {[
                    { id: "overview", label: "Overview" },
                    { id: "network", label: "Network & System" },
                    { id: "location", label: "Location & Owner" },
                    { id: "security", label: "Security & Audit" },
                ].map((tab) => (
                    <div
                        key={tab.id}
                        className={`requirement-tab ${activeTab === tab.id ? "active" : ""}`}
                        onClick={() => setActiveTab(tab.id)}
                    >
                        {tab.label}
                    </div>
                ))}
            </div>

            {/* Search + Sort */}
            <div className="search-box-container">
                <input
                    className="search-input"
                    placeholder="Search Asset"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                />

                <button
                    style={{ marginLeft: "8px", padding: "6px 12px" }}

                    className="btn-secondary"
                    onClick={() => setSortDir(d => (d === "asc" ? "desc" : "asc"))}
                >
                    Sort {sortDir === "asc" ? "↑" : "↓"}
                </button>
            </div>

            {isLoading && <div className="loading-spinner">Loading assets...</div>}

            {!isLoading && activeTab === "overview" && (
                <OverviewTab assets={sortedAssets} onEdit={handleEdit} onDelete={handleDeleteClick} />
            )}
            {!isLoading && activeTab === "network" && (
                <NetworkSystemTab assets={sortedAssets} onEdit={handleEdit} onDelete={handleDeleteClick} />
            )}
            {!isLoading && activeTab === "location" && (
                <LocationOwnerTab assets={sortedAssets} onEdit={handleEdit} onDelete={handleDeleteClick} />
            )}
            {!isLoading && activeTab === "security" && (
                <SecurityAuditTab assets={sortedAssets} onEdit={handleEdit} onDelete={handleDeleteClick} />
            )}

            {!isLoading && sortedAssets.length === 0 && (
                <div className="no-data">No assets found</div>
            )}

            {showDeleteModal && selectedAsset && (
                <div className="modal-overlay" onClick={() => setShowDeleteModal(false)}>
                    <div className="modal-content modal-small" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Confirm Delete</h3>
                            <button className="modal-close" onClick={() => setShowDeleteModal(false)}>✕</button>
                        </div>
                        <div className="modal-body">
                            Are you sure you want to delete <strong>{selectedAsset.asset_name}</strong>?
                        </div>
                        <div className="modal-footer">
                            <button className="btn-cancel" onClick={() => setShowDeleteModal(false)}>Cancel</button>
                            <button className="btn-delete-confirm" onClick={handleDeleteConfirm}>Delete</button>
                        </div>
                    </div>
                </div>
            )}

            {showEditModal && selectedAsset && (
                <EditAssetModal asset={selectedAsset} onClose={() => setShowEditModal(false)} />
            )}

            <AddAssetModal isOpen={showAddModal} onClose={() => setShowAddModal(false)} />
        </div>
    );
};
