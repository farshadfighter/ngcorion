import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    applyDiscoveryWithMode,
    previewDiscoveryApplication,
    addPortsToAsset,
    overwriteAssetPorts,
    addDiscoveryCreatedAsset,
} from '../../store/discoverySlice.jsx';
import { fetchAssets, fetchAssetTypes } from '../../store/assetSlice.jsx';
import api from '../../config/api.js';
import '../../assets/autoDiscoveryStyle/ManagePortsModal.css';

const ManagePortsModal = ({ host, onClose, onSuccess }) => {
    const dispatch = useDispatch();
    const { assetTypes } = useSelector((state) => state.assets);
    const { loading, previewData } = useSelector((state) => state.discovery);

    const [selectedMode, setSelectedMode] = useState(null);
    const [matchingAsset, setMatchingAsset] = useState(null);
    const [checkingMatch, setCheckingMatch] = useState(true);
    const [isApplying, setIsApplying] = useState(false);
    const [assetName, setAssetName] = useState('');
    const [assetTypeId, setAssetTypeId] = useState('');

    useEffect(() => {
        if (!assetTypes || assetTypes.length === 0) {
            dispatch(fetchAssetTypes());
        }
    }, [dispatch, assetTypes]);

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
        if (host && host.ip_address) checkForExistingAsset();
    }, [host, dispatch]);

    const handleApplyMode = async () => {
        if (!selectedMode || isApplying) return;
        try {
            setIsApplying(true);
            if (!host.id) {
                await handleDirectApply();
                return;
            }
            const payload = { hostId: host.id, mode: selectedMode };
            if (selectedMode === 'create_new') {
                if (!assetName.trim()) { alert('Please enter an asset name'); setIsApplying(false); return; }
                if (!assetTypeId) { alert('Please select an asset type'); setIsApplying(false); return; }
                payload.assetName = assetName.trim();
                payload.assetTypeId = parseInt(assetTypeId);
            } else {
                if (!matchingAsset) { alert('No matching asset found'); setIsApplying(false); return; }
                payload.assetId = matchingAsset.id;
            }
            const result = await dispatch(applyDiscoveryWithMode(payload)).unwrap();
            if (onSuccess) onSuccess(result);
            onClose();
        } catch (error) {
            alert(error || 'Failed to apply changes');
            setIsApplying(false);
        }
    };

    const handleDirectApply = async () => {
        try {
            const openPorts = host.ports || host.open_ports || [];
            if (selectedMode === 'create_new') {
                if (!assetName.trim()) { alert('Please enter an asset name'); return; }
                if (!assetTypeId) { alert('Please select an asset type'); return; }
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
                dispatch(addDiscoveryCreatedAsset(newAsset.id));
                if (openPorts.length > 0) {
                    const ports = openPorts.map(p => ({
                        port_number: p.port,
                        protocol: (p.protocol || 'tcp').toUpperCase(),
                        service_name: p.service,
                        service_product: p.product,
                        service_version: p.version,
                        state: p.state || 'open'
                    }));
                    await dispatch(addPortsToAsset({ assetId: newAsset.id, ports, scanId: host.scan_id })).unwrap();
                }
                if (onSuccess) onSuccess({ asset_id: newAsset.id, mode: 'create_new' });
                alert(`Asset "${assetName}" created successfully and added to Discovery List!`);
                onClose();
            } else if (selectedMode === 'overwrite' || selectedMode === 'merge') {
                if (!matchingAsset) { alert('No matching asset found'); return; }
                const ports = openPorts.map(p => ({
                    port_number: p.port,
                    protocol: (p.protocol || 'tcp').toUpperCase(),
                    service_name: p.service,
                    service_product: p.product,
                    service_version: p.version,
                    state: p.state || 'open'
                }));
                const portPayload = { assetId: matchingAsset.id, ports, scanId: host.scan_id };
                if (selectedMode === 'overwrite') {
                    await dispatch(overwriteAssetPorts(portPayload)).unwrap();
                } else {
                    await dispatch(addPortsToAsset(portPayload)).unwrap();
                }
                if (selectedMode === 'merge') {
                    const updatePayload = {};
                    if (host.hostname && !matchingAsset.hostname) updatePayload.hostname = host.hostname;
                    if (host.mac_address && !matchingAsset.mac_address) updatePayload.mac_address = host.mac_address;
                    if ((host.os_info || host.os_name) && !matchingAsset.os_name) updatePayload.os_name = host.os_info || host.os_name;
                    if (Object.keys(updatePayload).length > 0) await api.put(`/api/assets/${matchingAsset.id}`, updatePayload);
                }
                if (onSuccess) onSuccess({ asset_id: matchingAsset.id, mode: selectedMode });
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

    const stateClass = host.state === 'up'
        ? 'mpm-state-up'
        : host.state === 'down'
            ? 'mpm-state-down'
            : 'mpm-state-unknown';

    return (
        <div className="mpm-overlay" onClick={onClose}>
            <div className="mpm-modal" onClick={(e) => e.stopPropagation()}>

                {/* ── Header ── */}
                <div className="mpm-header">
                    <h2>Manage Asset Ports</h2>
                    <button className="mpm-close" onClick={onClose} aria-label="Close">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                            <path d="M18 6L6 18M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                {/* ── Body ── */}
                <div className="mpm-body">
                    {checkingMatch ? (
                        <div className="mpm-loading">
                            <div className="mpm-spinner" />
                            <p>Checking for existing asset...</p>
                        </div>
                    ) : (
                        <>
                            {/* Alert */}
                            {hasExistingAsset ? (
                                <div className="mpm-alert mpm-alert-info">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <circle cx="12" cy="12" r="10" />
                                        <path d="M12 16v-4M12 8h.01" />
                                    </svg>
                                    <span>This IP exists in the asset list. You can update or overwrite its ports.</span>
                                </div>
                            ) : (
                                <div className="mpm-alert mpm-alert-warning">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <circle cx="12" cy="12" r="10" />
                                        <path d="M12 16v-4M12 8h.01" />
                                    </svg>
                                    <span>This IP is not in the asset list. You can add it as a new asset.</span>
                                </div>
                            )}

                            {/* Host Info Card */}
                            <div className="mpm-host-card">
                                <div className="mpm-host-card-header">
                                    <h4>{host.ip_address}</h4>
                                    {host.hostname && (
                                        <span className="mpm-hostname-tag">{host.hostname}</span>
                                    )}
                                </div>

                                <div className="mpm-rows">
                                    <div className="mpm-row">
                                        <span className="mpm-row-label">MAC Address</span>
                                        <span className="mpm-row-value">
                                            <code>{host.mac_address || 'N/A'}</code>
                                        </span>
                                    </div>
                                    <div className="mpm-row">
                                        <span className="mpm-row-label">OS Info</span>
                                        <span className="mpm-row-value">
                                            {host.os_info || host.os_name || 'Unknown'}
                                        </span>
                                    </div>
                                    <div className="mpm-row">
                                        <span className="mpm-row-label">State</span>
                                        <span className="mpm-row-value">
                                            <span className={`mpm-state ${stateClass}`}>
                                                {host.state || 'unknown'}
                                            </span>
                                        </span>
                                    </div>
                                </div>

                                <div className="mpm-ports-section">
                                    <p className="mpm-ports-title">Open Ports</p>
                                    <div className="mpm-ports-list">
                                        {openPorts.length > 0 ? (
                                            openPorts.map((port, index) => (
                                                <span key={index} className="mpm-port-chip">
                                                    {port.port}/{port.protocol}
                                                    {port.service ? ` · ${port.service}` : ''}
                                                </span>
                                            ))
                                        ) : (
                                            <span className="mpm-no-ports">No open ports detected</span>
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Existing Asset Info */}
                            {hasExistingAsset && previewData && (
                                <div className="mpm-asset-card">
                                    <p className="mpm-asset-card-title">
                                        Existing Asset: {matchingAsset.asset_name}
                                    </p>
                                    <div className="mpm-rows">
                                        <div className="mpm-row">
                                            <span className="mpm-row-label">Asset ID</span>
                                            <span className="mpm-row-value">#{matchingAsset.id}</span>
                                        </div>
                                        <div className="mpm-row">
                                            <span className="mpm-row-label">Type</span>
                                            <span className="mpm-row-value">
                                                {matchingAsset.asset_type?.type_name || 'N/A'}
                                            </span>
                                        </div>
                                        <div className="mpm-row">
                                            <span className="mpm-row-label">Current Ports</span>
                                            <span className="mpm-row-value">
                                                {previewData.existing_ports_count || 0} ports
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Mode Selection */}
                            <div>
                                <p className="mpm-section-title">Select Action</p>
                                <div className="mpm-modes">
                                    {hasExistingAsset ? (
                                        <>
                                            {/* Overwrite */}
                                            <button
                                                className={`mpm-mode-card ${selectedMode === 'overwrite' ? 'mpm-selected' : ''}`}
                                                onClick={() => setSelectedMode('overwrite')}
                                            >
                                                <div className="mpm-mode-icon mpm-icon-overwrite">
                                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                        <path d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                                        <path d="M9 10h6v4H9z" />
                                                    </svg>
                                                </div>
                                                <div className="mpm-mode-info">
                                                    <h5>Overwrite Ports</h5>
                                                    <p>Replace ALL existing ports with newly discovered data</p>
                                                    {previewData?.overwrite_changes && (
                                                        <div className="mpm-preview-stats">
                                                            <span className="mpm-stat mpm-stat-danger">
                                                                Remove {previewData.overwrite_changes.ports_to_remove}
                                                            </span>
                                                            <span className="mpm-stat mpm-stat-success">
                                                                Add {previewData.overwrite_changes.ports_to_add}
                                                            </span>
                                                        </div>
                                                    )}
                                                </div>
                                            </button>

                                            {/* Merge */}
                                            <button
                                                className={`mpm-mode-card ${selectedMode === 'merge' ? 'mpm-selected' : ''}`}
                                                onClick={() => setSelectedMode('merge')}
                                            >
                                                <div className="mpm-mode-icon mpm-icon-merge">
                                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                        <path d="M12 5v14M5 12h14" />
                                                    </svg>
                                                </div>
                                                <div className="mpm-mode-info">
                                                    <h5>Update Ports</h5>
                                                    <p>Keep existing ports and add newly discovered ones</p>
                                                    {previewData?.merge_changes && (
                                                        <div className="mpm-preview-stats">
                                                            <span className="mpm-stat mpm-stat-success">
                                                                Add {previewData.merge_changes.ports_to_add} new
                                                            </span>
                                                            <span className="mpm-stat mpm-stat-info">
                                                                Fill {previewData.merge_changes.fields_to_fill?.length || 0} fields
                                                            </span>
                                                        </div>
                                                    )}
                                                </div>
                                            </button>
                                        </>
                                    ) : (
                                        <>
                                            {/* Create */}
                                            <button
                                                className={`mpm-mode-card ${selectedMode === 'create_new' ? 'mpm-selected' : ''}`}
                                                onClick={() => setSelectedMode('create_new')}
                                            >
                                                <div className="mpm-mode-icon mpm-icon-create">
                                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                        <rect x="3" y="3" width="18" height="18" rx="2" />
                                                        <path d="M12 8v8M8 12h8" />
                                                    </svg>
                                                </div>
                                                <div className="mpm-mode-info">
                                                    <h5>Add as New Asset</h5>
                                                    <p>Create a new asset with all discovered data</p>
                                                    <p className="mpm-mode-note">🎯 Will be added to Discovery Asset List</p>
                                                </div>
                                            </button>

                                            {/* Create Form */}
                                            {selectedMode === 'create_new' && (
                                                <div className="mpm-create-form">
                                                    <div className="mpm-field">
                                                        <label htmlFor="mpm-asset-name">Asset Name *</label>
                                                        <input
                                                            id="mpm-asset-name"
                                                            type="text"
                                                            className="mpm-input"
                                                            placeholder="Enter asset name"
                                                            value={assetName}
                                                            onChange={(e) => setAssetName(e.target.value)}
                                                        />
                                                    </div>
                                                    <div className="mpm-field">
                                                        <label htmlFor="mpm-asset-type">Asset Type *</label>
                                                        <select
                                                            id="mpm-asset-type"
                                                            className="mpm-select"
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
                            </div>
                        </>
                    )}
                </div>

                {/* ── Footer ── */}
                <div className="mpm-footer">
                    <button className="mpm-btn mpm-btn-secondary" onClick={onClose} disabled={isApplying}>
                        Cancel
                    </button>
                    {selectedMode && !checkingMatch && (
                        <button
                            className="mpm-btn mpm-btn-primary"
                            onClick={handleApplyMode}
                            disabled={isApplying || loading.applyMode}
                        >
                            {isApplying || loading.applyMode ? (
                                <>
                                    <span className="mpm-btn-spinner" />
                                    Applying...
                                </>
                            ) : (
                                <>
                                    {selectedMode === 'create_new' && 'Add Asset'}
                                    {selectedMode === 'overwrite' && 'Overwrite Ports'}
                                    {selectedMode === 'merge' && 'Update Ports'}
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