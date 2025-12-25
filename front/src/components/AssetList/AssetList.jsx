import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssets, deleteAsset, clearMessages } from "../../store/assetSlice";
import { OverviewTab } from "./OverviewTab";
import { NetworkSystemTab } from "./NetworkSystemTab";
import { LocationOwnerTab } from "./LocationOwnerTab";
import { SecurityAuditTab } from "./SecurityAuditTab";
import { EditAssetModal } from "./EditAssetModal";
import { AddAssetModal } from "./AddAssetModal";

export const AssetList = () => {
    const dispatch = useDispatch();
    const { assets, isLoading, error, successMessage } = useSelector((state) => state.assets);

    const [activeTab, setActiveTab] = useState("overview");
    const [searchQuery, setSearchQuery] = useState("");
    const [selectedAsset, setSelectedAsset] = useState(null);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [showEditModal, setShowEditModal] = useState(false);
    const [showAddModal, setShowAddModal] = useState(false);

    // بارگذاری assets هنگام mount
    useEffect(() => {
        dispatch(fetchAssets());
    }, [dispatch]);

    // پاک کردن پیغام‌ها بعد از 3 ثانیه
    useEffect(() => {
        if (successMessage || error) {
            const timer = setTimeout(() => dispatch(clearMessages()), 3000);
            return () => clearTimeout(timer);
        }
    }, [successMessage, error, dispatch]);

    // فیلتر کردن assets بر اساس جستجو
    const filteredAssets = Array.isArray(assets) ? assets.filter((asset) => {
        const query = searchQuery.toLowerCase();
        return (
            asset.asset_name?.toLowerCase().includes(query) ||
            asset.hostname?.toLowerCase().includes(query) ||
            asset.ip_address?.toLowerCase().includes(query) ||
            asset.serial_number?.toLowerCase().includes(query)
        );
    }) : [];

    // هندلر ویرایش
    const handleEdit = (asset) => {
        setSelectedAsset(asset);
        setShowEditModal(true);
    };

    // هندلر حذف
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

    // هندلر Add Asset
    const handleAddAsset = () => {
        setShowAddModal(true);
    };

    return (
        <div className="asset-list-container">
            {/* Header */}
            <div className="asset-list-header">
                <button className="btn-add-asset" onClick={handleAddAsset}>
                    + Add Asset
                </button>
            </div>

            {/* Success/Error Messages */}
            {successMessage && (
                <div className="alert alert-success">{successMessage}</div>
            )}
            {error && (
                <div className="alert alert-error">{error}</div>
            )}

            {/* Tabs */}
            <div className="tabs-container">
                <div
                    className={`tab ${activeTab === "overview" ? "active" : ""}`}
                    onClick={() => setActiveTab("overview")}
                >
                    Over view
                </div>
                <div
                    className={`tab ${activeTab === "network" ? "active" : ""}`}
                    onClick={() => setActiveTab("network")}
                >
                    network & System
                </div>
                <div
                    className={`tab ${activeTab === "location" ? "active" : ""}`}
                    onClick={() => setActiveTab("location")}
                >
                    Location & Owner
                </div>
                <div
                    className={`tab ${activeTab === "security" ? "active" : ""}`}
                    onClick={() => setActiveTab("security")}
                >
                    Security & Audit
                </div>
            </div>

            {/* Search Box */}
            <div className="search-box-container">
                <input
                    type="text"
                    className="search-input"
                    placeholder=" Search Asset"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                />
            </div>

            {/* Loading State */}
            {isLoading && <div className="loading-spinner">Loading assets...</div>}

            {/* Table based on active tab */}
            {!isLoading && (
                <>
                    {activeTab === "overview" && (
                        <OverviewTab
                            assets={filteredAssets}
                            onEdit={handleEdit}
                            onDelete={handleDeleteClick}
                        />
                    )}
                    {activeTab === "network" && (
                        <NetworkSystemTab
                            assets={filteredAssets}
                            onEdit={handleEdit}
                            onDelete={handleDeleteClick}
                        />
                    )}
                    {activeTab === "location" && (
                        <LocationOwnerTab
                            assets={filteredAssets}
                            onEdit={handleEdit}
                            onDelete={handleDeleteClick}
                        />
                    )}
                    {activeTab === "security" && (
                        <SecurityAuditTab
                            assets={filteredAssets}
                            onEdit={handleEdit}
                            onDelete={handleDeleteClick}
                        />
                    )}
                </>
            )}

            {/* No Data */}
            {!isLoading && filteredAssets.length === 0 && (
                <div className="no-data">No assets found</div>
            )}

            {/* Delete Confirmation Modal */}
            {showDeleteModal && selectedAsset && (
                <div className="modal-overlay" onClick={() => setShowDeleteModal(false)}>
                    <div className="modal-content modal-small" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Confirm Delete</h3>
                            <button className="modal-close" onClick={() => setShowDeleteModal(false)}>✕</button>
                        </div>
                        <div className="modal-body">
                            <p>Are you sure you want to delete asset <strong>{selectedAsset.asset_name}</strong>?</p>
                            <p className="warning-text">This action cannot be undone.</p>
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

            {/* Edit Asset Modal */}
            {showEditModal && selectedAsset && (
                <EditAssetModal
                    asset={selectedAsset}
                    onClose={() => {
                        setShowEditModal(false);
                        setSelectedAsset(null);
                    }}
                />
            )}

            {/* Add Asset Modal */}
            <AddAssetModal
                isOpen={showAddModal}
                onClose={() => setShowAddModal(false)}
            />
        </div>
    );
};