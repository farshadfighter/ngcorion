

import React, { useState, useEffect, useMemo } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { fetchAssets, deleteAsset } from '../../store/assetSlice.jsx';
import { selectDiscoveryCreatedAssetIds } from '../../store/discoverySlice.jsx';
import '../../assets/autoDiscoveryStyle/Assetlisttable.css';

// Tab definitions
const TABS = [
    { id: 'overview', label: 'Overview' },
    { id: 'network', label: 'Network & System' },
    { id: 'location', label: 'Location & Owner' },
    { id: 'security', label: 'Security & Audit' },
];

const AssetListTable = () => {
    const dispatch = useDispatch();

    // Redux state
    const { assets, loading } = useSelector((state) => state.assets);
    const discoveryCreatedAssetIds = useSelector(selectDiscoveryCreatedAssetIds);

    const [activeTab, setActiveTab] = useState('overview');
    const [searchTerm, setSearchTerm] = useState('');
    const [filterType, setFilterType] = useState('');

    // Edit modal state
    const [showEditModal, setShowEditModal] = useState(false);
    const [assetToEdit, setAssetToEdit] = useState(null);

    // Load assets
    useEffect(() => {
        dispatch(fetchAssets());
    }, [dispatch]);

    /**
     * فیلتر اصلی: فقط assetهای ساخته‌شده از Discovery
     */
    const discoveryAssets = useMemo(() => {
        if (!discoveryCreatedAssetIds || discoveryCreatedAssetIds.length === 0) {
            return [];
        }
        return assets.filter((asset) =>
            discoveryCreatedAssetIds.includes(asset.id)
        );
    }, [assets, discoveryCreatedAssetIds]);

    /**
     * فیلتر دوم: بر اساس search و type
     */
    const filteredAssets = useMemo(() => {
        let result = [...discoveryAssets];

        // Search
        if (searchTerm) {
            const search = searchTerm.toLowerCase();
            result = result.filter(asset =>
                asset.asset_name?.toLowerCase().includes(search) ||
                asset.ip_address?.toLowerCase().includes(search) ||
                asset.hostname?.toLowerCase().includes(search)
            );
        }

        // Filter by type
        if (filterType) {
            result = result.filter(asset =>
                asset.asset_type?.type_name === filterType
            );
        }

        return result;
    }, [discoveryAssets, searchTerm, filterType]);

    /**
     * Handle Edit
     */
    const handleEdit = (asset) => {
        setAssetToEdit(asset);
        setShowEditModal(true);
    };

    /**
     * Handle Delete
     */
    const handleDelete = async (asset) => {
        if (window.confirm(`Are you sure you want to delete "${asset.asset_name}"?`)) {
            try {
                await dispatch(deleteAsset(asset.id));
                dispatch(fetchAssets());
            } catch (error) {
                console.error('Failed to delete asset:', error);
                alert('Failed to delete asset');
            }
        }
    };

    /**
     * Render table headers based on active tab
     */
    const renderTableHeaders = () => {
        switch (activeTab) {
            case 'overview':
                return (
                    <>
                        <th>ID</th>
                        <th>Asset Name</th>
                        <th>Type</th>
                        <th>IP Address</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </>
                );
            case 'network':
                return (
                    <>
                        <th>ID</th>
                        <th>Asset Name</th>
                        <th>Hostname</th>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>OS Name</th>
                        <th>Actions</th>
                    </>
                );
            case 'location':
                return (
                    <>
                        <th>ID</th>
                        <th>Asset Name</th>
                        <th>Location</th>
                        <th>Owner</th>
                        <th>Department</th>
                        <th>Actions</th>
                    </>
                );
            case 'security':
                return (
                    <>
                        <th>ID</th>
                        <th>Asset Name</th>
                        <th>Risk Level</th>
                        <th>Confidentiality</th>
                        <th>Last Audit</th>
                        <th>Actions</th>
                    </>
                );
            default:
                return null;
        }
    };

    /**
     * Render table row based on active tab
     */
    const renderAssetRow = (asset) => {
        switch (activeTab) {
            case 'overview':
                return (
                    <>
                        <td>{asset.id}</td>
                        <td style={{ fontWeight: 500 }}>{asset.asset_name}</td>
                        <td>{asset.asset_type?.type_name || '-'}</td>
                        <td style={{ fontFamily: 'monospace' }}>{asset.ip_address || '-'}</td>
                        <td>
                            <span className={`badge badge-${asset.status || 'active'}`}>
                                {asset.status || 'active'}
                            </span>
                        </td>
                    </>
                );
            case 'network':
                return (
                    <>
                        <td>{asset.id}</td>
                        <td style={{ fontWeight: 500 }}>{asset.asset_name}</td>
                        <td>{asset.hostname || '-'}</td>
                        <td style={{ fontFamily: 'monospace' }}>{asset.ip_address || '-'}</td>
                        <td>
                            <code style={{ background: '#f3f4f6', padding: '3px 8px', borderRadius: '4px' }}>
                                {asset.mac_address || '-'}
                            </code>
                        </td>
                        <td>{asset.os_name || '-'}</td>
                    </>
                );
            case 'location':
                return (
                    <>
                        <td>{asset.id}</td>
                        <td style={{ fontWeight: 500 }}>{asset.asset_name}</td>
                        <td>{asset.location?.location_name || '-'}</td>
                        <td>{asset.owner?.owner_name || '-'}</td>
                        <td>{asset.owner?.department || '-'}</td>
                    </>
                );
            case 'security':
                return (
                    <>
                        <td>{asset.id}</td>
                        <td style={{ fontWeight: 500 }}>{asset.asset_name}</td>
                        <td>
                            <span className={`badge badge-risk-${asset.risk_level || 'low'}`}>
                                {asset.risk_level || 'Low'}
                            </span>
                        </td>
                        <td>
                            <span className={`badge badge-${asset.confidentiality_level || 'public'}`}>
                                {asset.confidentiality_level || 'Public'}
                            </span>
                        </td>
                        <td>{asset.last_audit_date || '-'}</td>
                    </>
                );
            default:
                return null;
        }
    };

    if (loading) {
        return (
            <div className="loading-spinner">
                <p>Loading assets...</p>
            </div>
        );
    }

    return (
        <div className="asset-list-container">
            {/* Info Banner */}
            <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '12px 16px',
                background: '#dbeafe',
                border: '1px solid #93c5fd',
                borderRadius: '6px',
                fontSize: '13px',
                color: '#1e40af',
                marginBottom: '20px'
            }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <path d="M12 16v-4M12 8h.01" />
                </svg>
                <span>
                    This list shows only assets created via Auto Discovery with "Create New" action. Total: {discoveryAssets.length} assets
                </span>
            </div>

            {/* Tabs */}
            <div className="tabs-container">
                {TABS.map(tab => (
                    <div
                        key={tab.id}
                        className={`tab ${activeTab === tab.id ? 'active' : ''}`}
                        onClick={() => setActiveTab(tab.id)}
                    >
                        {tab.label}
                    </div>
                ))}
            </div>

            {/* Search */}
            <div className="search-box-container">
                <input
                    type="text"
                    className="search-input"
                    placeholder="Search by name, IP, or hostname..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                />
            </div>

            {/* Table */}
            {filteredAssets.length === 0 ? (
                <div className="no-data">
                    <h3>No Assets Created from Discovery Yet</h3>
                    <p>When you approve discovered hosts with "Create New" action, they will appear here.</p>
                </div>
            ) : (
                <div className="table-container">
                    <table className="assets-table">
                        <thead>
                        <tr>
                            {renderTableHeaders()}
                        </tr>
                        </thead>
                        <tbody>
                        {filteredAssets.map(asset => (
                            <tr key={asset.id}>
                                {renderAssetRow(asset)}
                                <td>
                                    {/* Action Buttons */}
                                    <button
                                        className="btn-icon"
                                        onClick={() => handleEdit(asset)}
                                        title="Edit asset"
                                    >
                                        <img src={"/icons/edetie.svg"} alt={"edit"} />
                                    </button>
                                    <button
                                        className="btn-icon"
                                        onClick={() => handleDelete(asset)}
                                        title="Delete asset"
                                        style={{ color: '#C62828' }}
                                    >
                                        <img src={"/icons/delete.svg"} alt={"delete"} />
                                    </button>
                                </td>
                            </tr>
                        ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* Footer */}
            <div style={{
                padding: '12px 16px',
                textAlign: 'center',
                color: '#7F8C8D',
                fontSize: '13px',
                marginTop: '16px'
            }}>
                Showing {filteredAssets.length} of {discoveryAssets.length} discovery assets
            </div>

            {/* Edit Modal */}
            {showEditModal && assetToEdit && (
                <EditAssetModal
                    asset={assetToEdit}
                    onClose={() => {
                        setShowEditModal(false);
                        setAssetToEdit(null);
                        dispatch(fetchAssets());
                    }}
                />
            )}
        </div>
    );
};

export default AssetListTable;
