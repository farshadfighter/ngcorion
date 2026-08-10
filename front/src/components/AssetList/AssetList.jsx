import { useEffect, useState, useRef } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssets, deleteAsset, clearMessages } from "../../store/assetSlice";
import api from "../../config/api";
import { OverviewTab } from "./OverviewTab";
import { NetworkSystemTab } from "./NetworkSystemTab";
import { LocationOwnerTab } from "./LocationOwnerTab";
import { SecurityAuditTab } from "./SecurityAuditTab";
import { EditOverviewModal } from "./EditOverviewModal";
import { EditNetworkModal } from "./EditNetworkModal";
import { EditLocationModal } from "./EditLocationModal";
import { EditSecurityModal } from "./EditSecurityModal";
import { AddAssetModal } from "./AddAssetModal";
import { useAssetFormOptions } from "./useAssetFormOptions";

import "../../assets/AssetList.css"

const PRIMARY = "#1e3a5f";

// Asset Management has no license entitlement, so this list is not
// license-gated (no LicenseLimitModal here).
export const AssetList = () => {
    const dispatch = useDispatch();
    const { assets, isLoading, error, successMessage } = useSelector((state) => state.assets);
    const { assetTypes, locations, owners } = useAssetFormOptions();

    const [activeTab, setActiveTab]           = useState("overview");
    const [searchQuery, setSearchQuery]       = useState("");
    const [sortDir, setSortDir]               = useState("asc");
    const [selectedAsset, setSelectedAsset]   = useState(null);

    // ── Single delete ──────────────────────────────────────────────────────────
    const [showDeleteModal, setShowDeleteModal] = useState(false);

    // ── Multi-select delete ────────────────────────────────────────────────────
    const [selectedIds, setSelectedIds]               = useState(new Set());
    const [showDeleteSelectedModal, setShowDeleteSelectedModal] = useState(false);
    const [isDeletingSelected, setIsDeletingSelected] = useState(false);

    // ── Edit modals ────────────────────────────────────────────────────────────
    const [showEditOverviewModal,  setShowEditOverviewModal]  = useState(false);
    const [showEditNetworkModal,   setShowEditNetworkModal]   = useState(false);
    const [showEditLocationModal,  setShowEditLocationModal]  = useState(false);
    const [showEditSecurityModal,  setShowEditSecurityModal]  = useState(false);
    const [showAddModal,           setShowAddModal]           = useState(false);

    const [uploading, setUploading] = useState(false);
    const fileInputRef = useRef(null);

    const resolveAssetId = (asset) => {
        if (asset == null) return null;
        if (typeof asset === "number" || typeof asset === "string") return asset;
        return asset.id ?? asset.asset_id ?? asset.assetId;
    };

    useEffect(() => { dispatch(fetchAssets()); }, [dispatch]);

    useEffect(() => {
        if (successMessage || error) {
            const timer = setTimeout(() => dispatch(clearMessages()), 3000);
            return () => clearTimeout(timer);
        }
    }, [successMessage, error, dispatch]);

    // ── Filtering & sorting ────────────────────────────────────────────────────
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

    const enrichedAssets = sortedAssets.map(asset => {
        const assetType = assetTypes.find(t => t.id === asset.asset_type_id);
        const location  = locations.find(l => l.id === asset.location_id);
        const owner     = owners.find(o => o.id === asset.owner_id);
        return {
            ...asset,
            asset_type_name: assetType?.type_name || asset.asset_type_id || "-",
            location_name:   location?.site_name || location?.location_name || asset.location_id || "-",
            owner_name:      owner?.full_name || asset.owner_id || "-",
        };
    });

    // ── Selection helpers ──────────────────────────────────────────────────────
    const allIds         = enrichedAssets.map(a => a.id);
    const allSelected    = allIds.length > 0 && allIds.every(id => selectedIds.has(id));
    const someSelected   = selectedIds.size > 0;

    const toggleSelectAll = () => {
        if (allSelected) {
            setSelectedIds(new Set());
        } else {
            setSelectedIds(new Set(allIds));
        }
    };

    const toggleSelectOne = (id) => {
        setSelectedIds(prev => {
            const next = new Set(prev);
            next.has(id) ? next.delete(id) : next.add(id);
            return next;
        });
    };

    // ── Edit ───────────────────────────────────────────────────────────────────
    const handleEdit = (asset) => {
        setSelectedAsset(asset);
        switch (activeTab) {
            case "overview":  setShowEditOverviewModal(true);  break;
            case "network":   setShowEditNetworkModal(true);   break;
            case "location":  setShowEditLocationModal(true);  break;
            case "security":  setShowEditSecurityModal(true);  break;
            default:          setShowEditOverviewModal(true);
        }
    };

    // ── Single delete ──────────────────────────────────────────────────────────
    const handleDeleteClick = (asset) => {
        const matched = typeof asset === "object" && asset
            ? asset
            : enrichedAssets.find((a) => String(resolveAssetId(a)) === String(asset));
        setSelectedAsset(matched ?? { id: resolveAssetId(asset) });
        setShowDeleteModal(true);
    };

    const handleDeleteConfirm = () => {
        const assetId = resolveAssetId(selectedAsset);
        if (assetId) {
            dispatch(deleteAsset(assetId));
            setSelectedIds(prev => { const n = new Set(prev); n.delete(assetId); return n; });
            setShowDeleteModal(false);
            setSelectedAsset(null);
        }
    };

    // ── Multi delete ───────────────────────────────────────────────────────────
    const handleDeleteSelectedConfirm = async () => {
        setIsDeletingSelected(true);
        await Promise.allSettled(
            [...selectedIds].map(id => dispatch(deleteAsset(id)).unwrap())
        );
        setSelectedIds(new Set());
        setShowDeleteSelectedModal(false);
        setIsDeletingSelected(false);
        dispatch(fetchAssets());
    };

    const isNewAsset = (asset) => {
        if (!asset.created_at) return false;
        return (new Date() - new Date(asset.created_at)) / (1000 * 60 * 60) < 24;
    };

    // ── Shared tab props ───────────────────────────────────────────────────────
    const tabProps = {
        assets:          enrichedAssets,
        onEdit:          handleEdit,
        onDelete:        handleDeleteClick,
        isNewAsset,
        selectedIds,
        onToggleSelect:  toggleSelectOne,
        onToggleAll:     toggleSelectAll,
        allSelected,
    };

    return (
        <div className="asset-list-container main-asset-list">
            {/* Header */}
            <div className="asset-list-header">
                <h1 className="page-title">Asset List</h1>
                <div className="header-actions">
                    <button className="btn-header" onClick={() => fileInputRef.current?.click()} disabled={uploading}>
                        {uploading ? "⏳ Importing..." : "⬇ Import"}
                    </button>
                    <button className="btn-header" onClick={async () => {
                        const res = await api.get("/api/assets/export/excel", { responseType: "blob" });
                        const url = window.URL.createObjectURL(new Blob([res.data]));
                        const link = document.createElement("a");
                        link.href = url; link.setAttribute("download", `assets-${Date.now()}.xlsx`);
                        document.body.appendChild(link); link.click(); link.remove();
                        window.URL.revokeObjectURL(url);
                    }}>⬆ Export</button>
                    <button className="btn-header" onClick={async () => {
                        const res = await api.get("/api/assets/export/template", { responseType: "blob" });
                        const url = window.URL.createObjectURL(new Blob([res.data]));
                        const link = document.createElement("a");
                        link.href = url; link.setAttribute("download", "asset-template.xlsx");
                        document.body.appendChild(link); link.click(); link.remove();
                        window.URL.revokeObjectURL(url);
                    }}><i className="fa-solid fa-download"></i> Download Template</button>
                    <button className="btn-header btn-primary" onClick={() => setShowAddModal(true)}>
                        + Add Asset
                    </button>
                </div>
            </div>

            <input ref={fileInputRef} type="file" accept=".xlsx,.xls" style={{ display: "none" }}
                   onChange={async (e) => {
                       const file = e.target.files?.[0]; if (!file) return;
                       setUploading(true);
                       const formData = new FormData(); formData.append("file", file);
                       await api.post("/api/assets/import/excel", formData);
                       await dispatch(fetchAssets()); setUploading(false); e.target.value = "";
                   }}
            />

            {successMessage && <div className="alert alert-success">{successMessage}</div>}
            {error          && <div className="alert alert-error">{error}</div>}

            {/* Tabs */}
            <div className="asset-tabs">
                {[
                    { id: "overview",  label: "Overview" },
                    { id: "network",   label: "Network & System" },
                    { id: "location",  label: "Location & Owner" },
                    { id: "security",  label: "Security & Audit" },
                ].map((tab) => (
                    <button key={tab.id} className={`asset-tab ${activeTab === tab.id ? "active" : ""}`}
                            onClick={() => setActiveTab(tab.id)}>
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* Search + Delete Selected */}
            <div className="search-sort-container" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div className="search-box">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
                    </svg>
                    <input className="search-input" placeholder="Search Asset"
                           value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} />
                </div>

                {/* Delete Selected — فقط وقتی چیزی select شده نمایش داده میشه */}
                {someSelected && (
                    <button
                        onClick={() => setShowDeleteSelectedModal(true)}
                        style={{
                            display: "flex", alignItems: "center", gap: "6px",
                            padding: "8px 18px", background: "#dc2626", color: "white",
                            border: "none", borderRadius: "8px", fontSize: "14px",
                            fontWeight: "600", cursor: "pointer",
                        }}
                    >
                        <i className="fa-solid fa-trash"></i>
                        Delete Selected ({selectedIds.size})
                    </button>
                )}
            </div>

            {isLoading && <div className="loading-spinner">Loading assets...</div>}

            {!isLoading && activeTab === "overview"  && <OverviewTab      {...tabProps} />}
            {!isLoading && activeTab === "network"   && <NetworkSystemTab {...tabProps} />}
            {!isLoading && activeTab === "location"  && <LocationOwnerTab {...tabProps} />}
            {!isLoading && activeTab === "security"  && <SecurityAuditTab {...tabProps} />}

            {/* ── Delete single modal ──────────────────────────────────────────── */}
            {showDeleteModal && (
                <div className="modal-overlay" onClick={() => setShowDeleteModal(false)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Confirm Delete</h3>
                            <button className="modal-close" onClick={() => setShowDeleteModal(false)}>✕</button>
                        </div>
                        <div className="modal-body">
                            <p>Are you sure you want to delete "{selectedAsset?.asset_name || `ID: ${resolveAssetId(selectedAsset)}`}"?</p>
                            <p style={{ color: "#dc2626", fontSize: "13px", marginTop: "8px" }}>This action cannot be undone.</p>
                        </div>
                        <div className="modal-actions">
                            <button className="btn-cancel" onClick={() => setShowDeleteModal(false)}>Cancel</button>
                            <button className="btn-delete2" onClick={handleDeleteConfirm}>Delete</button>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Delete selected modal ────────────────────────────────────────── */}
            {showDeleteSelectedModal && (
                <div className="modal-overlay" onClick={() => !isDeletingSelected && setShowDeleteSelectedModal(false)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header" style={{ borderBottom: `3px solid ${PRIMARY}` }}>
                            <h3 style={{ color: PRIMARY }}>Delete Selected Assets</h3>
                            <button className="modal-close" onClick={() => setShowDeleteSelectedModal(false)}>✕</button>
                        </div>
                        <div className="modal-body">
                            <p>Are you sure you want to delete <strong>{selectedIds.size}</strong> selected asset{selectedIds.size !== 1 ? "s" : ""}?</p>
                            <p style={{ color: "#dc2626", fontSize: "13px", marginTop: "8px" }}>This action cannot be undone.</p>
                        </div>
                        <div className="modal-actions">
                            <button className="btn-cancel" onClick={() => setShowDeleteSelectedModal(false)}
                                    disabled={isDeletingSelected}>Cancel</button>
                            <button
                                onClick={handleDeleteSelectedConfirm}
                                disabled={isDeletingSelected}
                                style={{
                                    padding: "10px 20px", background: PRIMARY, color: "white",
                                    border: "none", borderRadius: "8px", fontSize: "14px",
                                    fontWeight: "600", cursor: isDeletingSelected ? "not-allowed" : "pointer",
                                    opacity: isDeletingSelected ? 0.7 : 1,
                                }}
                            >
                                {isDeletingSelected ? "Deleting..." : `Yes, Delete ${selectedIds.size}`}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Edit modals ──────────────────────────────────────────────────── */}
            {showEditOverviewModal && selectedAsset && (
                <EditOverviewModal asset={selectedAsset} isOpen={showEditOverviewModal}
                                   onClose={() => { setShowEditOverviewModal(false); setSelectedAsset(null); }} />
            )}
            {showEditNetworkModal && selectedAsset && (
                <EditNetworkModal asset={selectedAsset} isOpen={showEditNetworkModal}
                                  onClose={() => { setShowEditNetworkModal(false); setSelectedAsset(null); }} />
            )}
            {showEditLocationModal && selectedAsset && (
                <EditLocationModal asset={selectedAsset} isOpen={showEditLocationModal}
                                   onClose={() => { setShowEditLocationModal(false); setSelectedAsset(null); }} />
            )}
            {showEditSecurityModal && selectedAsset && (
                <EditSecurityModal asset={selectedAsset} isOpen={showEditSecurityModal}
                                   onClose={() => { setShowEditSecurityModal(false); setSelectedAsset(null); }} />
            )}

            <AddAssetModal isOpen={showAddModal} onClose={() => {
                setShowAddModal(false);
            }} />
        </div>
    );
};