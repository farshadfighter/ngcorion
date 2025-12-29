import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    applyDiscoveryWithMode,
    previewDiscoveryApplication,
    addPortsToAsset,
    overwriteAssetPorts,
    addDiscoveryCreatedAsset, // 🔥 NEW: اضافه شد
} from '../../store/discoverySlice.jsx';
import { fetchAssets, fetchAssetTypes } from '../../store/assetSlice.jsx';
import api from '../../config/api.js';
import '../../assets/autoDiscoveryStyle/ManagePortsModal.css';

const ManagePortsModal = ({ host, onClose, onSuccess }) => {
    const dispatch = useDispatch();
    const { assetTypes } = useSelector((state) => state.assets);
    const { loading, previewData } = useSelector((state) => state.discovery);

    // State
    const [selectedMode, setSelectedMode] = useState(null);
    const [matchingAsset, setMatchingAsset] = useState(null);
    const [checkingMatch, setCheckingMatch] = useState(true);
    const [isApplying, setIsApplying] = useState(false);

    // Create mode form data
    const [assetName, setAssetName] = useState('');
    const [assetTypeId, setAssetTypeId] = useState('');

    // Load asset types
    useEffect(() => {
        if (!assetTypes || assetTypes.length === 0) {
            dispatch(fetchAssetTypes());
        }
    }, [dispatch, assetTypes]);

    // Check for existing asset
    useEffect(() => {
        const checkForExistingAsset = async () => {
            try {
                setCheckingMatch(true);
                const response = await dispatch(fetchAssets()).unwrap();
                const match = response.find(asset => asset.ip_address === host.ip_address);
                setMatchingAsset(match || null);

                if (match && host.id) {
                    await dispatch(previewDiscoveryApplication({
                        hostId: host.id,
                        assetId: match.id
                    })).unwrap();
                }
            } catch (error) {
                console.error('Error checking for existing asset:', error);
            } finally {
                setCheckingMatch(false);
            }
        };

        if (host && host.ip_address) {
            checkForExistingAsset();
        }
    }, [host, dispatch]);

    // Handle mode application
    const handleApplyMode = async () => {
        if (!selectedMode || isApplying) return;

        try {
            setIsApplying(true);

            // For hosts without ID (direct from scan)
            if (!host.id) {
                await handleDirectApply();
                return;
            }

            // For hosts with ID (from pending hosts)
            const payload = {
                hostId: host.id,
                mode: selectedMode,
            };

            if (selectedMode === 'create_new') {
                if (!assetName.trim()) {
                    alert('Please enter an asset name');
                    setIsApplying(false);
                    return;
                }
                if (!assetTypeId) {
                    alert('Please select an asset type');
                    setIsApplying(false);
                    return;
                }
                payload.assetName = assetName.trim();
                payload.assetTypeId = parseInt(assetTypeId);
            } else {
                if (!matchingAsset) {
                    alert('No matching asset found');
                    setIsApplying(false);
                    return;
                }
                payload.assetId = matchingAsset.id;
            }

            const result = await dispatch(applyDiscoveryWithMode(payload)).unwrap();

            if (onSuccess) {
                onSuccess(result);
            }
            onClose();
        } catch (error) {
            alert(error || 'Failed to apply changes');
            setIsApplying(false);
        }
    };

    // Handle direct apply for hosts without database ID
    const handleDirectApply = async () => {
        try {
            const openPorts = host.ports || host.open_ports || [];

            if (selectedMode === 'create_new') {
                // Validation
                if (!assetName.trim()) {
                    alert('Please enter an asset name');
                    return;
                }
                if (!assetTypeId) {
                    alert('Please select an asset type');
                    return;
                }

                // 1. Create new asset
                const assetPayload = {
                    asset_name: assetName.trim(),
                    ip_address: host.ip_address,
                    hostname: host.hostname,
                    mac_address: host.mac_address,
                    os_name: host.os_info || host.os_name,
                    asset_type_id: parseInt(assetTypeId),
                };

                const assetResponse = await api.post('/api/assets/', assetPayload);
                const newAsset = assetResponse.data;

                // 🔥 2. Track این asset در Discovery List
                dispatch(addDiscoveryCreatedAsset(newAsset.id));

                // 3. Add ports if any
                if (openPorts.length > 0) {
                    const ports = openPorts.map(p => ({
                        port_number: p.port,
                        protocol: (p.protocol || 'tcp').toUpperCase(),
                        service_name: p.service,
                        service_product: p.product,
                        service_version: p.version,
                        state: p.state || 'open'
                    }));

                    await dispatch(addPortsToAsset({
                        assetId: newAsset.id,
                        ports,
                        scanId: host.scan_id
                    })).unwrap();
                }

                if (onSuccess) {
                    onSuccess({ asset_id: newAsset.id, mode: 'create_new' });
                }

                alert(`Asset "${assetName}" created successfully and added to Discovery List!`);
                onClose();

            } else if (selectedMode === 'overwrite' || selectedMode === 'merge') {
                // Update existing asset
                if (!matchingAsset) {
                    alert('No matching asset found');
                    return;
                }

                const ports = openPorts.map(p => ({
                    port_number: p.port,
                    protocol: (p.protocol || 'tcp').toUpperCase(),
                    service_name: p.service,
                    service_product: p.product,
                    service_version: p.version,
                    state: p.state || 'open'
                }));

                const portPayload = {
                    assetId: matchingAsset.id,
                    ports,
                    scanId: host.scan_id
                };

                if (selectedMode === 'overwrite') {
                    await dispatch(overwriteAssetPorts(portPayload)).unwrap();
                } else {
                    await dispatch(addPortsToAsset(portPayload)).unwrap();
                }

                // Update asset fields if needed (for merge mode)
                if (selectedMode === 'merge') {
                    const updatePayload = {};
                    if (host.hostname && !matchingAsset.hostname) {
                        updatePayload.hostname = host.hostname;
                    }
                    if (host.mac_address && !matchingAsset.mac_address) {
                        updatePayload.mac_address = host.mac_address;
                    }
                    if ((host.os_info || host.os_name) && !matchingAsset.os_name) {
                        updatePayload.os_name = host.os_info || host.os_name;
                    }

                    if (Object.keys(updatePayload).length > 0) {
                        await api.put(`/api/assets/${matchingAsset.id}`, updatePayload);
                    }
                }

                if (onSuccess) {
                    onSuccess({ asset_id: matchingAsset.id, mode: selectedMode });
                }

                alert(`Ports ${selectedMode === 'overwrite' ? 'overwritten' : 'updated'} successfully!`);
                onClose();
            }
        } catch (error) {
            console.error('Error applying changes:', error);
            alert(error.response?.data?.detail || 'Failed to apply changes');
        } finally {
            setIsApplying(false);
        }
    };

    if (!host) return null;

    const openPorts = host.ports || host.open_ports || [];
    const hasExistingAsset = matchingAsset !== null;

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal manage-ports-modal" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>Manage Ports</h2>
                    <button className="modal-close" onClick={onClose}>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M18 6L6 18M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                <div className="modal-body">
                    {checkingMatch ? (
                        <div className="loading-state">
                            <div className="spinner" />
                            <p>Checking for existing asset...</p>
                        </div>
                    ) : (
                        <>
                            {/* Status Alert */}
                            {hasExistingAsset ? (
                                <div className="alert alert-info">
                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <circle cx="12" cy="12" r="10" />
                                        <path d="M12 16v-4M12 8h.01" />
                                    </svg>
                                    <span>
                    This IP is available in the asset list. You can update or overwrite ports
                  </span>
                                </div>
                            ) : (
                                <div className="alert alert-warning">
                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <circle cx="12" cy="12" r="10" />
                                        <path d="M12 16v-4M12 8h.01" />
                                    </svg>
                                    <span>
                    This IP is unavailable in the asset list. You can add this asset to asset list
                  </span>
                                </div>
                            )}

                            {/* Discovered Data Display */}
                            <div className="discovered-data-card">
                                <div className="card-header">
                                    <h4>IP Address: {host.ip_address}</h4>
                                    {host.hostname && <span className="hostname">{host.hostname}</span>}
                                </div>

                                <div className="card-body">
                                    <div className="data-row">
                                        <span className="label">MAC Address:</span>
                                        <code>{host.mac_address || 'N/A'}</code>
                                    </div>
                                    <div className="data-row">
                                        <span className="label">OS Info:</span>
                                        <span>{host.os_info || host.os_name || 'Unknown'}</span>
                                    </div>
                                    <div className="data-row">
                                        <span className="label">State:</span>
                                        <span className={`status-badge status-${host.state}`}>
                      {host.state || 'unknown'}
                    </span>
                                    </div>
                                </div>

                                <div className="ports-section">
                                    <h5>Open Ports</h5>
                                    <div className="ports-list">
                                        {openPorts.length > 0 ? (
                                            openPorts.map((port, index) => (
                                                <span key={index} className="port-badge-large">
                          {port.port}/{port.protocol} ({port.service || 'unknown'})
                        </span>
                                            ))
                                        ) : (
                                            <span className="text-muted">No open ports detected</span>
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Existing Asset Info */}
                            {hasExistingAsset && previewData && (
                                <div className="existing-asset-card">
                                    <h4>Existing Asset: {matchingAsset.asset_name}</h4>
                                    <div className="data-row">
                                        <span className="label">Asset ID:</span>
                                        <span>#{matchingAsset.id}</span>
                                    </div>
                                    <div className="data-row">
                                        <span className="label">Type:</span>
                                        <span>{matchingAsset.asset_type?.type_name || 'N/A'}</span>
                                    </div>
                                    <div className="data-row">
                                        <span className="label">Current Ports:</span>
                                        <span>{previewData.existing_ports_count || 0} ports</span>
                                    </div>
                                </div>
                            )}

                            {/* Mode Selection */}
                            <div className="mode-selection">
                                <h4>Select Action</h4>

                                {hasExistingAsset ? (
                                    <>
                                        {/* Overwrite Mode */}
                                        <button
                                            className={`mode-card ${selectedMode === 'overwrite' ? 'selected' : ''}`}
                                            onClick={() => setSelectedMode('overwrite')}
                                        >
                                            <div className="mode-icon overwrite">
                                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                    <path d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                                    <path d="M9 10h6v4H9z" />
                                                </svg>
                                            </div>
                                            <div className="mode-content">
                                                <h5>Overwrite Port</h5>
                                                <p>Replace ALL existing data with discovered data</p>
                                                {previewData?.overwrite_changes && (
                                                    <div className="mode-preview">
                            <span className="preview-stat danger">
                              Remove {previewData.overwrite_changes.ports_to_remove} ports
                            </span>
                                                        <span className="preview-stat success">
                              Add {previewData.overwrite_changes.ports_to_add} ports
                            </span>
                                                    </div>
                                                )}
                                            </div>
                                        </button>

                                        {/* Merge/Update Mode */}
                                        <button
                                            className={`mode-card ${selectedMode === 'merge' ? 'selected' : ''}`}
                                            onClick={() => setSelectedMode('merge')}
                                        >
                                            <div className="mode-icon merge">
                                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                    <path d="M12 5v14M5 12h14" />
                                                </svg>
                                            </div>
                                            <div className="mode-content">
                                                <h5>Update Port</h5>
                                                <p>Keep existing data + add new discovered data</p>
                                                {previewData?.merge_changes && (
                                                    <div className="mode-preview">
                            <span className="preview-stat success">
                              Add {previewData.merge_changes.ports_to_add} new ports
                            </span>
                                                        <span className="preview-stat info">
                              Fill {previewData.merge_changes.fields_to_fill?.length || 0} empty fields
                            </span>
                                                    </div>
                                                )}
                                            </div>
                                        </button>
                                    </>
                                ) : (
                                    <>
                                        {/* Create Mode */}
                                        <div
                                            className={`mode-card ${selectedMode === 'create_new' ? 'selected' : ''}`}
                                            onClick={() => setSelectedMode('create_new')}
                                        >
                                            <div className="mode-icon create">
                                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                    <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
                                                    <path d="M12 8v8M8 12h8" />
                                                </svg>
                                            </div>
                                            <div className="mode-content">
                                                <h5>Add Asset</h5>
                                                <p>Create a new asset with all discovered data</p>
                                                <p className="mode-note">🎯 Will be added to Discovery Asset List</p>
                                            </div>
                                        </div>

                                        {/* Create Form */}
                                        {selectedMode === 'create_new' && (
                                            <div className="create-form">
                                                <div className="form-group">
                                                    <label htmlFor="asset-name">Asset Name *</label>
                                                    <input
                                                        id="asset-name"
                                                        type="text"
                                                        className="form-input"
                                                        placeholder="Enter asset name"
                                                        value={assetName}
                                                        onChange={(e) => setAssetName(e.target.value)}
                                                    />
                                                </div>
                                                <div className="form-group">
                                                    <label htmlFor="asset-type">Asset Type *</label>
                                                    <select
                                                        id="asset-type"
                                                        className="form-select"
                                                        value={assetTypeId}
                                                        onChange={(e) => setAssetTypeId(e.target.value)}
                                                    >
                                                        <option value="">Select asset type</option>
                                                        {assetTypes.map((type) => (
                                                            <option key={type.id} value={type.id}>
                                                                {type.type_name}
                                                            </option>
                                                        ))}
                                                    </select>
                                                </div>
                                            </div>
                                        )}
                                    </>
                                )}
                            </div>
                        </>
                    )}
                </div>

                <div className="modal-footer">
                    <button className="btn btn-secondary" onClick={onClose} disabled={isApplying}>
                        Cancel
                    </button>
                    {selectedMode && !checkingMatch && (
                        <button
                            className="btn btn-primary"
                            onClick={handleApplyMode}
                            disabled={isApplying || loading.applyMode}
                        >
                            {isApplying || loading.applyMode ? (
                                <>
                                    <span className="spinner" />
                                    Applying...
                                </>
                            ) : (
                                <>
                                    {selectedMode === 'create_new' && 'Add Asset'}
                                    {selectedMode === 'overwrite' && 'Overwrite Port'}
                                    {selectedMode === 'merge' && 'Update Port'}
                                </>
                            )}
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
};

export default ManagePortsModal;