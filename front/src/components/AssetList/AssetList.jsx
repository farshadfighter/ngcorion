import { useEffect, useState, useRef } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssets, deleteAsset, clearMessages } from "../../store/assetSlice";
import { usePermission } from "../../hooks/usePermission";
import api from "../../config/api";
import { OverviewTab } from "./OverviewTab";
import { NetworkSystemTab } from "./NetworkSystemTab";
import { LocationOwnerTab } from "./LocationOwnerTab";
import { SecurityAuditTab } from "./SecurityAuditTab";
import { SoftwareTab } from "./SoftwareTab";
import { Pagination } from "../Logs/Pagination.jsx";
import { EditOverviewModal } from "./EditOverviewModal";
import { EditNetworkModal } from "./EditNetworkModal";
import { EditLocationModal } from "./EditLocationModal";
import { EditSecurityModal } from "./EditSecurityModal";
import { AddAssetModal } from "./AddAssetModal";
import { ChangeHistoryModal } from "./ChangeHistoryModal";
import { useAssetFormOptions } from "./useAssetFormOptions";

import "../../assets/AssetList.css"
// Pagination's styles live with the Logs page it was first built for.
import "../../assets/LogsPage.css"
import { t as tr, n } from "../../i18n";
import { tx } from "../../i18n/tx";

const PRIMARY = "#1e3a5f";

// Asset Management has no license entitlement, so this list is not
// license-gated (no LicenseLimitModal here).
export const AssetList = () => {
    const dispatch = useDispatch();
    const { assets, isLoading, error, successMessage } = useSelector((state) => state.assets);
    const { assetTypes, locations, owners } = useAssetFormOptions();
    // The backend requires ASSET_LIST delete; without this the button is shown
    // to everyone and a user who lacks the permission just gets a 403 that used
    // to be swallowed, so deleting looked broken rather than forbidden.
    const canDelete = usePermission("asset_list", "delete");

    const [activeTab, setActiveTab]           = useState("overview");
    const [searchQuery, setSearchQuery]       = useState("");
    const [sortDir]                           = useState("asc");
    const [page, setPage]                     = useState(1);
    const [pageSize, setPageSize]             = useState(25);
    const [selectedAsset, setSelectedAsset]   = useState(null);

    // ── Single delete ──────────────────────────────────────────────────────────
    const [showDeleteModal, setShowDeleteModal] = useState(false);

    // ── Multi-select delete ────────────────────────────────────────────────────
    const [selectedIds, setSelectedIds]               = useState(new Set());
    const [showDeleteSelectedModal, setShowDeleteSelectedModal] = useState(false);
    const [isDeletingSelected, setIsDeletingSelected] = useState(false);
    const [bulkError, setBulkError]                   = useState(null);

    // ── Edit modals ────────────────────────────────────────────────────────────
    const [showEditOverviewModal,  setShowEditOverviewModal]  = useState(false);
    const [showEditNetworkModal,   setShowEditNetworkModal]   = useState(false);
    const [showEditLocationModal,  setShowEditLocationModal]  = useState(false);
    const [showEditSecurityModal,  setShowEditSecurityModal]  = useState(false);
    const [showAddModal,           setShowAddModal]           = useState(false);
    const [showHistoryModal,       setShowHistoryModal]       = useState(false);

    const [uploading, setUploading] = useState(false);
    const fileInputRef = useRef(null);

    const resolveAssetId = (asset) => {
        if (asset == null) return null;
        if (typeof asset === "number" || typeof asset === "string") return asset;
        return asset.id ?? asset.asset_id ?? asset.assetId;
    };

    useEffect(() => { dispatch(fetchAssets()); }, [dispatch]);

    useEffect(() => {
        if (successMessage || error || bulkError) {
            const timer = setTimeout(() => {
                dispatch(clearMessages());
                setBulkError(null);
            }, 3000);
            return () => clearTimeout(timer);
        }
    }, [successMessage, error, bulkError, dispatch]);

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

    // ── Pagination ─────────────────────────────────────────────────────────────
    // Client-side: /api/assets/ returns the whole inventory and the search and
    // sort above already operate on it.
    const totalPages  = Math.max(1, Math.ceil(enrichedAssets.length / pageSize));
    const safePage    = Math.min(page, totalPages);
    const pagedAssets = enrichedAssets.slice(
        (safePage - 1) * pageSize,
        safePage * pageSize
    );

    // A search that shrinks the list can leave the current page past the end.
    if (page > totalPages) setPage(1);

    // ── Selection helpers ──────────────────────────────────────────────────────
    // Scoped to the visible page: "select all" ticking rows the user cannot
    // see would make the delete count surprising.
    const allIds         = pagedAssets.map(a => a.id);
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

    // ── Change history ────────────────────────────────────────────────────────
    const handleViewHistory = (asset) => {
        setSelectedAsset(asset);
        setShowHistoryModal(true);
    };

    // ── Single delete ──────────────────────────────────────────────────────────
    const handleDeleteClick = (asset) => {
        const matched = typeof asset === "object" && asset
            ? asset
            : enrichedAssets.find((a) => String(resolveAssetId(a)) === String(asset));
        setSelectedAsset(matched ?? { id: resolveAssetId(asset) });
        setShowDeleteModal(true);
    };

    const handleDeleteConfirm = async () => {
        const assetId = resolveAssetId(selectedAsset);
        // `0` is not a real asset id here (the column is a serial starting at
        // 1), but check for absence rather than falsiness so a future id of 0
        // would not silently do nothing — which is how this failed before.
        if (assetId === null || assetId === undefined || assetId === "") {
            return;
        }
        setShowDeleteModal(false);
        const result = await dispatch(deleteAsset(assetId));
        setSelectedAsset(null);
        if (deleteAsset.fulfilled.match(result)) {
            setSelectedIds(prev => { const n = new Set(prev); n.delete(assetId); return n; });
            // Re-read the list: the delete cascades to ports, risk scores and
            // hardening rows, so the server is the only accurate view of what
            // is left. A failed delete keeps the row, and the slice's rejected
            // case surfaces why.
            dispatch(fetchAssets());
        }
    };

    // ── Multi delete ───────────────────────────────────────────────────────────
    const handleDeleteSelectedConfirm = async () => {
        setIsDeletingSelected(true);
        const outcomes = await Promise.allSettled(
            [...selectedIds].map(id => dispatch(deleteAsset(id)).unwrap())
        );
        setSelectedIds(new Set());
        setShowDeleteSelectedModal(false);
        setIsDeletingSelected(false);
        // allSettled swallows per-asset failures, and the last thunk to settle
        // decides what the slice's error says — so count them here rather than
        // reporting "deleted" for a batch that partly failed.
        const failed = outcomes.filter(o => o.status === "rejected").length;
        if (failed) {
            setBulkError(
                tr("{{failed}} of {{length}} assets could not be deleted.", { failed, length: outcomes.length })
            );
        }
        dispatch(fetchAssets());
    };

    const isNewAsset = (asset) => {
        if (!asset.created_at) return false;
        return (new Date() - new Date(asset.created_at)) / (1000 * 60 * 60) < 24;
    };

    // ── Shared tab props ───────────────────────────────────────────────────────
    const tabProps = {
        assets:          pagedAssets,
        onEdit:          handleEdit,
        onDelete:        handleDeleteClick,
        onViewHistory:   handleViewHistory,
        canDelete,
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
                <h1 className="page-title">{tr("Asset List")}</h1>
                <div className="header-actions">
                    <button className="btn-header" onClick={() => fileInputRef.current?.click()} disabled={uploading}>
                        {uploading ? tr("⏳ Importing...") : tr("⬇ Import")}
                    </button>
                    <button className="btn-header" onClick={async () => {
                        const res = await api.get("/api/assets/export/excel", { responseType: "blob" });
                        const url = window.URL.createObjectURL(new Blob([res.data]));
                        const link = document.createElement("a");
                        link.href = url; link.setAttribute("download", `assets-${Date.now()}.xlsx`);
                        document.body.appendChild(link); link.click(); link.remove();
                        window.URL.revokeObjectURL(url);
                    }}>{tr("⬆ Export")}</button>
                    <button className="btn-header" onClick={async () => {
                        const res = await api.get("/api/assets/export/template", { responseType: "blob" });
                        const url = window.URL.createObjectURL(new Blob([res.data]));
                        const link = document.createElement("a");
                        link.href = url; link.setAttribute("download", "asset-template.xlsx");
                        document.body.appendChild(link); link.click(); link.remove();
                        window.URL.revokeObjectURL(url);
                    }}><i className="fa-solid fa-download"></i> {" "}{tr("Download Template")}</button>
                    <button className="btn-header btn-primary" onClick={() => setShowAddModal(true)}>
                        {tr("+ Add Asset")}
                    </button>
                </div>
            </div>

            <input ref={fileInputRef} type="file" accept=".xlsx,.xls" style={{ display: "none" }}
                   onChange={async (e) => {
                       const file = e.target.files?.[0]; if (!file) return;
                       setUploading(true);
                       try {
                           const formData = new FormData(); formData.append("file", file);
                           await api.post("/api/assets/import/excel/upload", formData);
                           await dispatch(fetchAssets());
                       } catch (err) {
                           setBulkError(tr("Import failed: {{error}}", { error: err.response?.data?.detail || err.message }));
                       } finally {
                           setUploading(false); e.target.value = "";
                       }
                   }}
            />

            {successMessage && <div className="alert alert-success">{successMessage}</div>}
            {error          && <div className="alert alert-error">{error}</div>}
            {bulkError      && <div className="alert alert-error">{bulkError}</div>}

            {/* Tabs */}
            <div className="asset-tabs">
                {[
                    { id: "overview",  label: tr("Overview") },
                    { id: "network",   label: tr("Network & System") },
                    { id: "location",  label: tr("Location & Owner") },
                    { id: "security",  label: tr("Security & Audit") },
                    { id: "software",  label: tr("Software") },
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
                    <input className="search-input" placeholder={tr("Search Asset")}
                           value={searchQuery}
                           onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }} />
                </div>

                {/* Delete Selected — فقط وقتی چیزی select شده نمایش داده میشه */}
                {someSelected && canDelete && (
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
                        {tr("Delete Selected ({{size}})", { size: selectedIds.size })}
                    </button>
                )}
            </div>

            {isLoading && <div className="loading-spinner">{tr("Loading assets...")}</div>}

            {!isLoading && activeTab === "overview"  && <OverviewTab      {...tabProps} />}
            {!isLoading && activeTab === "network"   && <NetworkSystemTab {...tabProps} />}
            {!isLoading && activeTab === "location"  && <LocationOwnerTab {...tabProps} />}
            {!isLoading && activeTab === "security"  && <SecurityAuditTab {...tabProps} />}
            {!isLoading && activeTab === "software"  && <SoftwareTab      {...tabProps} />}

            {!isLoading && (
                <Pagination
                    page={safePage}
                    pageSize={pageSize}
                    totalItems={enrichedAssets.length}
                    onPageChange={setPage}
                    onPageSizeChange={(size) => { setPageSize(size); setPage(1); }}
                />
            )}

            {/* ── Delete single modal ──────────────────────────────────────────── */}
            {showDeleteModal && (
                <div className="modal-overlay" onClick={() => setShowDeleteModal(false)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>{tr("Confirm Delete")}</h3>
                            <button className="modal-close" onClick={() => setShowDeleteModal(false)}>✕</button>
                        </div>
                        <div className="modal-body">
                            <p>{tr("Are you sure you want to delete \"{{name}}\"?", { name: selectedAsset?.asset_name || tr("ID: {{resolveAssetId}}", { resolveAssetId: resolveAssetId(selectedAsset) }) })}</p>
                            <p style={{ color: "#dc2626", fontSize: "13px", marginTop: "8px" }}>{tr("This action cannot be undone.")}</p>
                        </div>
                        <div className="modal-actions">
                            <button className="btn-cancel" onClick={() => setShowDeleteModal(false)}>{tr("Cancel")}</button>
                            <button className="btn-delete2" onClick={handleDeleteConfirm}>{tr("Delete")}</button>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Delete selected modal ────────────────────────────────────────── */}
            {showDeleteSelectedModal && (
                <div className="modal-overlay" onClick={() => !isDeletingSelected && setShowDeleteSelectedModal(false)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header" style={{ borderBottom: `3px solid ${PRIMARY}` }}>
                            <h3 style={{ color: PRIMARY }}>{tr("Delete Selected Assets")}</h3>
                            <button className="modal-close" onClick={() => setShowDeleteSelectedModal(false)}>✕</button>
                        </div>
                        <div className="modal-body">
                            <p>{selectedIds.size === 1
                                ? tx("Are you sure you want to delete {{count}} selected asset?", { count: <strong>{n(selectedIds.size)}</strong> })
                                : tx("Are you sure you want to delete {{count}} selected assets?", { count: <strong>{n(selectedIds.size)}</strong> })}</p>
                            <p style={{ color: "#dc2626", fontSize: "13px", marginTop: "8px" }}>{tr("This action cannot be undone.")}</p>
                        </div>
                        <div className="modal-actions">
                            <button className="btn-cancel" onClick={() => setShowDeleteSelectedModal(false)}
                                    disabled={isDeletingSelected}>{tr("Cancel")}</button>
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
                                {isDeletingSelected ? tr("Deleting...") : tr("Yes, Delete {{size}}", { size: selectedIds.size })}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Edit modals ──────────────────────────────────────────────────── */}
            {showHistoryModal && selectedAsset && (
                <ChangeHistoryModal asset={selectedAsset} isOpen={showHistoryModal}
                                    onClose={() => { setShowHistoryModal(false); setSelectedAsset(null); }} />
            )}
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