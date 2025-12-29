/**
 * AssetListTable - فقط assetهای ساخته‌شده از Discovery رو نشون میده
 * ✅ فیلتر می‌کنه فقط assetهایی که از طریق Discovery ساخته شدن
 */

import React, { useState, useEffect, useMemo } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { fetchAssets } from '../../store/assetSlice.jsx';
import { selectDiscoveryCreatedAssetIds } from '../../store/discoverySlice.jsx';
import ViewAssetPortsModal from './ViewAssetPortsModal';

// Tab definitions
const TABS = [
    { id: 'overview', label: 'Overview' },
    { id: 'network', label: 'Network & System' },
    { id: 'location', label: 'Location & Owner' },
    { id: 'security', label: 'Security & Audit' },
];

const AssetListTable = ({ onScanAsset, isScanning }) => {
    const dispatch = useDispatch();

    // Redux state
    const { assets, loading } = useSelector((state) => state.assets);
    const discoveryCreatedAssetIds = useSelector(selectDiscoveryCreatedAssetIds);

    const [activeTab, setActiveTab] = useState('overview');
    const [searchTerm, setSearchTerm] = useState('');
    const [filterType, setFilterType] = useState('');
    const [selectedIds, setSelectedIds] = useState([]);

    // Scan options modal
    const [showScanOptions, setShowScanOptions] = useState(false);
    const [assetToScan, setAssetToScan] = useState(null);
    const [scanType, setScanType] = useState('well_known_ports');
    const [customPorts, setCustomPorts] = useState('');
    const [protocol, setProtocol] = useState('TCP');

    // View ports modal
    const [showViewPorts, setShowViewPorts] = useState(false);
    const [assetToViewPorts, setAssetToViewPorts] = useState(null);

    // Load assets
    useEffect(() => {
        dispatch(fetchAssets());
    }, [dispatch]);

    /**
     * 🔥 فیلتر اصلی: فقط assetهای ساخته‌شده از Discovery
     */
    const discoveryAssets = useMemo(() => {
        return assets.filter((asset) =>
            discoveryCreatedAssetIds.includes(asset.id)
        );
    }, [assets, discoveryCreatedAssetIds]);

    /**
     * فیلتر دوم: بر اساس search و type
     */
    const filteredAssets = useMemo(() => {
        return discoveryAssets.filter((asset) => {
            const matchesSearch =
                !searchTerm ||
                asset.asset_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                asset.ip_address?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                asset.hostname?.toLowerCase().includes(searchTerm.toLowerCase());

            const matchesType = !filterType || asset.asset_type_id === parseInt(filterType);

            return matchesSearch && matchesType;
        });
    }, [discoveryAssets, searchTerm, filterType]);

    // Get unique asset types from discovery assets
    const assetTypeOptions = useMemo(() => {
        return [...new Set(discoveryAssets.map((a) => a.asset_type))].filter(Boolean);
    }, [discoveryAssets]);

    // Toggle selection
    const toggleSelect = (id) => {
        setSelectedIds((prev) =>
            prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
        );
    };

    const toggleSelectAll = () => {
        if (selectedIds.length === filteredAssets.length) {
            setSelectedIds([]);
        } else {
            setSelectedIds(filteredAssets.map((a) => a.id));
        }
    };

    // Open scan options
    const openScanOptions = (asset) => {
        if (!asset.ip_address) {
            alert('This asset does not have an IP address configured.');
            return;
        }
        setAssetToScan(asset);
        setScanType('well_known_ports');
        setCustomPorts('');
        setProtocol('TCP');
        setShowScanOptions(true);
    };

    // Handle scan submit
    const handleScanSubmit = () => {
        if (!assetToScan) return;

        if (scanType === 'custom_ports' && !customPorts.trim()) {
            alert('Please specify custom ports');
            return;
        }

        const scanData = {
            target: assetToScan.ip_address,
            job_name: `Scan: ${assetToScan.asset_name}`,
            scan_type: scanType,
            protocol: protocol,
        };

        if (scanType === 'custom_ports' && customPorts.trim()) {
            scanData.ports = customPorts.trim();
        }

        onScanAsset(scanData);
        setShowScanOptions(false);
        setAssetToScan(null);
    };

    // Close scan options
    const closeScanOptions = () => {
        setShowScanOptions(false);
        setAssetToScan(null);
    };

    // Scan selected assets
    const handleScanSelected = () => {
        const selectedAssets = filteredAssets.filter((a) => selectedIds.includes(a.id));
        const assetsWithIp = selectedAssets.filter((a) => a.ip_address);

        if (assetsWithIp.length === 0) {
            alert('None of the selected assets have IP addresses configured.');
            return;
        }

        if (assetsWithIp.length === 1) {
            openScanOptions(assetsWithIp[0]);
        } else {
            alert(`Selected ${assetsWithIp.length} assets with IPs. Please scan them individually or use the New Scan button with a CIDR range.`);
        }
    };

    if (loading) {
        return (
            <div className="table-loading">
                <div className="spinner-lg" />
                <p>Loading assets...</p>
            </div>
        );
    }

    // Get columns based on tab
    const getTableColumns = () => {
        switch (activeTab) {
            case 'network':
                return ['checkbox', 'Asset Name', 'IP Address', 'MAC Address', 'Hostname', 'FQDN', 'Actions'];
            case 'location':
                return ['checkbox', 'Asset Name', 'Location', 'Zone', 'Owner', 'Department', 'Actions'];
            case 'security':
                return ['checkbox', 'Asset Name', 'Criticality', 'Last Audit', 'Compliance', 'Actions'];
            default:
                return ['checkbox', 'ID', 'Asset Name', 'Hostname', 'Type', 'Role', 'Vendor', 'Model', 'Actions'];
        }
    };

    // Render row data
    const renderAssetRow = (asset) => {
        switch (activeTab) {
            case 'network':
                return (
                    <>
                        <td className="col-asset-name">{asset.asset_name || '-'}</td>
                        <td className="col-ip">
                            {asset.ip_address ? (
                                <span className="ip-address">{asset.ip_address}</span>
                            ) : (
                                <span className="text-muted">Not set</span>
                            )}
                        </td>
                        <td className="col-mac">
                            {asset.mac_address ? (
                                <code className="mac-address">{asset.mac_address}</code>
                            ) : (
                                <span className="text-muted">-</span>
                            )}
                        </td>
                        <td className="col-hostname">{asset.hostname || <span className="text-muted">-</span>}</td>
                        <td className="col-fqdn">{asset.fqdn || <span className="text-muted">-</span>}</td>
                    </>
                );

            case 'location':
                return (
                    <>
                        <td className="col-asset-name">{asset.asset_name || '-'}</td>
                        <td className="col-location">{asset.location?.site_name || <span className="text-muted">-</span>}</td>
                        <td className="col-zone">{asset.zone?.zone_name || <span className="text-muted">-</span>}</td>
                        <td className="col-owner">{asset.owner?.full_name || <span className="text-muted">-</span>}</td>
                        <td className="col-department">{asset.department || <span className="text-muted">-</span>}</td>
                    </>
                );

            case 'security':
                return (
                    <>
                        <td className="col-asset-name">{asset.asset_name || '-'}</td>
                        <td className="col-criticality">
              <span className={`criticality-badge criticality-${(asset.risk_level || 'medium').toLowerCase()}`}>
                {asset.risk_level || 'Medium'}
              </span>
                        </td>
                        <td className="col-audit">{asset.last_audit_date || <span className="text-muted">Never</span>}</td>
                        <td className="col-compliance">
              <span className={`compliance-badge compliance-${asset.compliance_status?.toLowerCase() || 'unknown'}`}>
                {asset.compliance_status || 'Unknown'}
              </span>
                        </td>
                    </>
                );

            default: // overview
                return (
                    <>
                        <td className="col-id">{asset.id}</td>
                        <td className="col-asset-name">{asset.asset_name || '-'}</td>
                        <td className="col-hostname">{asset.hostname || <span className="text-muted">-</span>}</td>
                        <td className="col-type">
                            {asset.asset_type ? (
                                <span className="type-badge">{asset.asset_type.type_name}</span>
                            ) : (
                                <span className="text-muted">-</span>
                            )}
                        </td>
                        <td className="col-role">{asset.asset_role || <span className="text-muted">-</span>}</td>
                        <td className="col-vendor">{asset.manufacturer || <span className="text-muted">-</span>}</td>
                        <td className="col-model">{asset.model || <span className="text-muted">-</span>}</td>
                    </>
                );
        }
    };

    return (
        <div className="asset-list-container">
            {/* Info Banner */}
            <div className="info-banner">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <path d="M12 16v-4M12 8h.01" />
                </svg>
                <span>
          This list shows only assets created via Auto Discovery with "Create New" action.
          Total: {discoveryAssets.length} assets
        </span>
            </div>

            {/* Tabs */}
            <div className="tabs-nav">
                {TABS.map((tab) => (
                    <button
                        key={tab.id}
                        className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
                        onClick={() => setActiveTab(tab.id)}
                    >
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* Toolbar */}
            <div className="asset-toolbar">
                <div className="search-box">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="11" cy="11" r="8" />
                        <path d="M21 21l-4.35-4.35" />
                    </svg>
                    <input
                        type="text"
                        placeholder="Search by name, IP, or hostname..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="search-input"
                    />
                </div>
                <div className="filter-controls">
                    <select
                        value={filterType}
                        onChange={(e) => setFilterType(e.target.value)}
                        className="filter-select"
                    >
                        <option value="">All Types</option>
                        {assetTypeOptions.map((type, index) => (
                            <option key={type?.id ?? `type-${index}`} value={type?.id}>
                                {type?.type_name || type}
                            </option>
                        ))}
                    </select>
                    {selectedIds.length > 0 && (
                        <button
                            className="btn btn-sm btn-primary"
                            onClick={handleScanSelected}
                            disabled={isScanning}
                        >
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <circle cx="11" cy="11" r="8" />
                                <path d="M21 21l-4.35-4.35" />
                            </svg>
                            Scan Selected ({selectedIds.length})
                        </button>
                    )}
                </div>
            </div>

            {/* Table or Empty State */}
            {filteredAssets.length === 0 ? (
                <div className="empty-state">
                    <div className="empty-icon">
                        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                            <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
                            <path d="M9 3v18M3 9h18M3 15h18M15 3v18" />
                        </svg>
                    </div>
                    {discoveryAssets.length === 0 ? (
                        <>
                            <h3>No Assets Created from Discovery Yet</h3>
                            <p>When you approve discovered hosts with "Create New" action, they will appear here.</p>
                        </>
                    ) : (
                        <>
                            <h3>No assets match your search</h3>
                            <p>Try adjusting your filters or search term</p>
                        </>
                    )}
                </div>
            ) : (
                <div className="table-wrapper">
                    <table className="asset-table">
                        <thead>
                        <tr>
                            <th className="col-checkbox">
                                <input
                                    type="checkbox"
                                    checked={selectedIds.length === filteredAssets.length && filteredAssets.length > 0}
                                    onChange={toggleSelectAll}
                                />
                            </th>
                            {getTableColumns().slice(1).map((col) => (
                                <th key={col}>{col}</th>
                            ))}
                        </tr>
                        </thead>
                        <tbody>
                        {filteredAssets.map((asset) => (
                            <tr key={asset.id} className={selectedIds.includes(asset.id) ? 'selected' : ''}>
                                <td className="col-checkbox">
                                    <input
                                        type="checkbox"
                                        checked={selectedIds.includes(asset.id)}
                                        onChange={() => toggleSelect(asset.id)}
                                    />
                                </td>
                                {renderAssetRow(asset)}
                                <td className="col-actions">
                                    <div className="action-buttons">
                                        <button
                                            className="btn btn-sm btn-icon"
                                            onClick={() => openScanOptions(asset)}
                                            disabled={!asset.ip_address || isScanning}
                                            title={asset.ip_address ? 'Run discovery scan' : 'No IP address configured'}
                                        >
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                <circle cx="11" cy="11" r="8" />
                                                <path d="M21 21l-4.35-4.35" />
                                            </svg>
                                        </button>
                                        <button
                                            className="btn btn-sm btn-icon"
                                            onClick={() => {
                                                setAssetToViewPorts(asset);
                                                setShowViewPorts(true);
                                            }}
                                            title="View ports"
                                        >
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                <rect x="2" y="7" width="20" height="14" rx="2" ry="2" />
                                                <path d="M16 21V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v16" />
                                            </svg>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* Footer */}
            <div className="asset-list-footer">
        <span className="asset-count">
          Showing {filteredAssets.length} of {discoveryAssets.length} discovery assets
        </span>
            </div>

            {/* Scan Options Modal */}
            {showScanOptions && assetToScan && (
                <div className="modal-overlay" onClick={closeScanOptions}>
                    <div className="modal modal-scan-options" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h2>Scan Options</h2>
                            <button className="modal-close" onClick={closeScanOptions}>
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M18 6L6 18M6 6l12 12" />
                                </svg>
                            </button>
                        </div>

                        <div className="modal-body">
                            <div className="scan-target-info">
                                <div className="target-label">Target Asset</div>
                                <div className="target-details">
                                    <span className="target-name">{assetToScan.asset_name}</span>
                                    <span className="target-ip">{assetToScan.ip_address}</span>
                                </div>
                            </div>

                            <div className="form-group">
                                <div className="form-label">Scan Type</div>
                                <div className="radio-group">
                                    <label className={`radio-card ${scanType === 'well_known_ports' ? 'selected' : ''}`}>
                                        <input
                                            type="radio"
                                            name="scan_type"
                                            value="well_known_ports"
                                            checked={scanType === 'well_known_ports'}
                                            onChange={(e) => setScanType(e.target.value)}
                                        />
                                        <div className="radio-content">
                                            <span className="radio-title">Well-Known Ports</span>
                                            <span className="radio-desc">Ports 1-1024 (Fast)</span>
                                        </div>
                                        <span className="radio-badge recommended">Recommended</span>
                                    </label>

                                    <label className={`radio-card ${scanType === 'all_ports' ? 'selected' : ''}`}>
                                        <input
                                            type="radio"
                                            name="scan_type"
                                            value="all_ports"
                                            checked={scanType === 'all_ports'}
                                            onChange={(e) => setScanType(e.target.value)}
                                        />
                                        <div className="radio-content">
                                            <span className="radio-title">All Ports</span>
                                            <span className="radio-desc">Ports 1-65535 (Thorough but slow)</span>
                                        </div>
                                    </label>

                                    <label className={`radio-card ${scanType === 'custom_ports' ? 'selected' : ''}`}>
                                        <input
                                            type="radio"
                                            name="scan_type"
                                            value="custom_ports"
                                            checked={scanType === 'custom_ports'}
                                            onChange={(e) => setScanType(e.target.value)}
                                        />
                                        <div className="radio-content">
                                            <span className="radio-title">Custom Ports</span>
                                            <span className="radio-desc">Specify ports below</span>
                                        </div>
                                    </label>
                                </div>
                            </div>

                            {scanType === 'custom_ports' && (
                                <div className="form-group">
                                    <label htmlFor="custom-ports">Custom Ports</label>
                                    <input
                                        type="text"
                                        id="custom-ports"
                                        value={customPorts}
                                        onChange={(e) => setCustomPorts(e.target.value)}
                                        placeholder="e.g., 80,443,8080 or 1-1000"
                                        className="form-input"
                                    />
                                    <p className="form-hint">
                                        Examples: Single (80), List (80,443,8080), Range (1-1000)
                                    </p>
                                </div>
                            )}

                            <div className="form-group">
                                <label htmlFor="protocol">Protocol</label>
                                <select
                                    id="protocol"
                                    value={protocol}
                                    onChange={(e) => setProtocol(e.target.value)}
                                    className="form-select"
                                >
                                    <option value="TCP">TCP (Recommended)</option>
                                    <option value="UDP">UDP</option>
                                    <option value="BOTH">Both TCP & UDP</option>
                                </select>
                            </div>
                        </div>

                        <div className="modal-footer">
                            <button className="btn btn-secondary" onClick={closeScanOptions}>
                                Cancel
                            </button>
                            <button
                                className="btn btn-primary"
                                onClick={handleScanSubmit}
                                disabled={isScanning || (scanType === 'custom_ports' && !customPorts.trim())}
                            >
                                {isScanning ? (
                                    <>
                                        <span className="spinner" />
                                        Starting...
                                    </>
                                ) : (
                                    <>
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                            <circle cx="11" cy="11" r="8" />
                                            <path d="M21 21l-4.35-4.35" />
                                        </svg>
                                        Start Scan
                                    </>
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* View Ports Modal */}
            {showViewPorts && assetToViewPorts && (
                <ViewAssetPortsModal
                    asset={assetToViewPorts}
                    onClose={() => {
                        setShowViewPorts(false);
                        setAssetToViewPorts(null);
                    }}
                />
            )}
        </div>
    );
};

export default AssetListTable;