/**
 * Asset List page: the inventory table with its tabs (overview, network, location, security,
 * software), search and filters, Excel import/export, and the edit, ports and change-history
 * dialogs of each asset.
 */
import { useEffect, useState, useRef } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useSearchParams } from "react-router-dom";
import { fetchAssets, deleteAsset, clearMessages } from "../../store/assetSlice";
import { getLicenseUsageThunk } from "../../store/licenseSlice";
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
import { BulkBar } from "./BulkActions";
import { filterLabel, matchesFilters, readFilters } from "./assetFilters";

import "../../assets/AssetList.css"
// Pagination's styles live with the Logs page it was first built for.
import "../../assets/LogsPage.css"
import { t as tr } from "../../i18n";
import { tv } from "../../i18n/backendText";
import { ReportShortcut } from "../Reports/ReportShortcut.jsx";


// The license covers a number of assets: the list shows when the inventory is
// over that number, and which assets are outside it (audits and hardening run
// only on the first ones). Adding past the limit is refused by the backend
// (the asset-limit dialog, components/License/AssetLimitModal.jsx).
export const AssetList = () => {
    const dispatch = useDispatch();
    const { assets, isLoading, error, successMessage } = useSelector((state) => state.assets);
    const licenseUsage = useSelector((state) => state.license.usage);
    const licensedThroughId = licenseUsage?.over_limit ? licenseUsage.licensed_through_id : null;
    const { assetTypes, locations, owners } = useAssetFormOptions();
    // The backend requires ASSET_LIST delete; without this the button is shown
    // to everyone and a user who lacks the permission just gets a 403 that used
    // to be swallowed, so deleting looked broken rather than forbidden.
    const canDelete = usePermission("asset_list", "delete");

    const [activeTab, setActiveTab]           = useState("overview");
    const [searchQuery, setSearchQuery]       = useState("");
    // ?missing=owner, ?type=3, ?vendor=… (the assets overview's cards and charts)
    const [urlParams, setUrlParams]           = useSearchParams();
    const urlFilters                          = readFilters(urlParams);
    const [sortDir]                           = useState("asc");
    const [page, setPage]                     = useState(1);
    const [pageSize, setPageSize]             = useState(25);
    const [selectedAsset, setSelectedAsset]   = useState(null);

    // ── Single delete ──────────────────────────────────────────────────────────
    const [showDeleteModal, setShowDeleteModal] = useState(false);

    // ── Multi-select delete ────────────────────────────────────────────────────
    const [selectedIds, setSelectedIds]               = useState(new Set());
    const [bulkError, setBulkError]                   = useState(null);
    const [bulkNotice, setBulkNotice]                 = useState(null);
    const [tagsByAsset, setTagsByAsset]               = useState({});

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
        if (successMessage || error || bulkError || bulkNotice) {
            const timer = setTimeout(() => {
                dispatch(clearMessages());
                setBulkError(null);
                setBulkNotice(null);
            }, bulkNotice ? 5000 : 3000);
            return () => clearTimeout(timer);
        }
    }, [successMessage, error, bulkError, bulkNotice, dispatch]);

    // ── Filtering & sorting ────────────────────────────────────────────────────
    const now = new Date();
    const filteredAssets = Array.isArray(assets)
        ? assets.filter((asset) => {
            const q = searchQuery.toLowerCase();
            return matchesFilters(asset, urlFilters, now) && (
                asset.asset_name?.toLowerCase().includes(q) ||
                asset.hostname?.toLowerCase().includes(q) ||
                asset.ip_address?.toLowerCase().includes(q) ||
                asset.serial_number?.toLowerCase().includes(q) ||
                (tagsByAsset[asset.id] || []).some((tag) => tag.includes(q))
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
            tags:            tagsByAsset[asset.id] || [],
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

    // ── Bulk edit (BulkActions.jsx) ───────────────────────────────────────────
    const loadTags = () => {
        api.get("/api/asset-groups/tags/assets").then(({ data }) => setTagsByAsset(data || {})).catch(() => setTagsByAsset({}));
    };
    useEffect(loadTags, []);

    const handleBulkDone = (message, action) => {
        setBulkNotice(message);
        if (action === "delete") setSelectedIds(new Set());
        loadTags();
        dispatch(fetchAssets());
    };

    // Refresh the license usage whenever the list changes (added, deleted, imported).
    useEffect(() => {
        dispatch(getLicenseUsageThunk());
    }, [dispatch, assets.length]);

    const isOutsideLicense = (asset) => licensedThroughId !== null && licensedThroughId !== undefined
        && asset.id > licensedThroughId;

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
        isOutsideLicense,
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
                    <ReportShortcut template="asset_coverage" className="btn-header rep-shortcut-header"
                                    title={tr("Coverage report: which assets are audited, backed up and monitored")} />
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
                           const res = await api.post("/api/assets/import/excel/upload", formData);
                           await dispatch(fetchAssets());
                           // Rows the license's asset limit (or anything else) kept out.
                           const rowErrors = res.data?.errors || [];
                           if (rowErrors.length) {
                               setBulkError(tr("Imported {{created}}, updated {{updated}}; {{failed}} rows were not imported: {{first}}", {
                                   created: res.data.created ?? 0, updated: res.data.updated ?? 0,
                                   failed: rowErrors.length, first: rowErrors[0],
                               }));
                           }
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
            {bulkNotice     && <div className="alert alert-success" role="status">{bulkNotice}</div>}
            {licenseUsage?.over_limit && (
                <div className="alert alert-error" role="status">
                    {tr("The inventory has {{used}} assets and the license covers {{limit}}. Audits and hardening run only on the first {{limit}} assets; those marked \"Outside license\" are kept but not audited.", {
                        used: licenseUsage.used, limit: licenseUsage.max_assets,
                    })}
                </div>
            )}

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

            {/* Search; bulk actions on the selected rows below */}
            <div className="search-sort-container" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div className="search-box">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
                    </svg>
                    <input className="search-input" placeholder={tr("Search name, address or tag")}
                           value={searchQuery}
                           onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }} />
                </div>
                {urlFilters.length > 0 && (
                    <div className="al-filters" role="group" aria-label={tr("Filters")}>
                        {urlFilters.map((f) => (
                            <button key={f.key} type="button" className="al-filter-chip"
                                    title={tr("Remove this filter")}
                                    onClick={() => { setUrlParams((p) => { p.delete(f.key); return p; }); setPage(1); }}>
                                {filterLabel(f, (id) => tv(assetTypes.find((x) => String(x.id) === String(id))?.type_name || id), tv)}
                                <span aria-hidden="true">×</span>
                            </button>
                        ))}
                    </div>
                )}

            </div>

            <BulkBar selectedIds={selectedIds} owners={owners} locations={locations}
                     onClear={() => setSelectedIds(new Set())} onDone={handleBulkDone} />

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