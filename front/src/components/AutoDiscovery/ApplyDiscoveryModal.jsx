
import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    previewDiscoveryApplication,
    applyDiscoveryWithMode,
    checkHostMatches,
    clearPreviewData,
    clearMatchResults,
    fetchPendingHosts,
} from '../../store/discoverySlice.jsx';

const ApplyDiscoveryModal = ({ host, assetTypes, onClose }) => {
    const dispatch = useDispatch();
    const { matchResults, previewData, loading } = useSelector((state) => state.discovery);

    // Steps: 'select_target', 'select_mode', 'confirm', 'create_new'
    const [step, setStep] = useState('loading');
    const [selectedAsset, setSelectedAsset] = useState(null);
    const [selectedMode, setSelectedMode] = useState(null);

    // For create_new mode
    const [assetName, setAssetName] = useState('');
    const [assetTypeId, setAssetTypeId] = useState('');
    const [errors, setErrors] = useState({});

    // Load matches on mount
    useEffect(() => {
        dispatch(checkHostMatches(host.id));
        setAssetName(host.hostname || `Host-${host.ip_address}`);
    }, [dispatch, host]);

    // Update step when matches are loaded
    useEffect(() => {
        if (matchResults) {
            if (matchResults.matches && matchResults.matches.length > 0) {
                setStep('select_target');
            } else {
                // No matches - go directly to create new
                setStep('create_new');
            }
        }
    }, [matchResults]);

    // Load preview when asset is selected
    useEffect(() => {
        if (selectedAsset) {
            dispatch(previewDiscoveryApplication({
                hostId: host.id,
                assetId: selectedAsset.asset_id
            }));
        }
    }, [dispatch, host.id, selectedAsset]);

    // Clean up on close
    const handleClose = () => {
        dispatch(clearMatchResults());
        dispatch(clearPreviewData());
        onClose();
    };

    // Select an existing asset
    const handleSelectAsset = (asset) => {
        setSelectedAsset(asset);
        setStep('select_mode');
    };

    // Select application mode
    const handleSelectMode = (mode) => {
        setSelectedMode(mode);
        setStep('confirm');
    };

    // Apply with selected mode
    const handleApply = async () => {
        if (selectedMode === 'create_new') {
            // Validate
            const newErrors = {};
            if (!assetName.trim()) {
                newErrors.assetName = 'Asset name is required';
            }
            if (!assetTypeId) {
                newErrors.assetTypeId = 'Asset type is required';
            }
            if (Object.keys(newErrors).length > 0) {
                setErrors(newErrors);
                return;
            }

            const result = await dispatch(applyDiscoveryWithMode({
                hostId: host.id,
                mode: 'create_new',
                assetName: assetName.trim(),
                assetTypeId: parseInt(assetTypeId),
            }));

            if (result.type.includes('fulfilled')) {
                // 🔧 FIX: Refresh pending hosts before closing
                await dispatch(fetchPendingHosts());
                handleClose();
            }
        } else {
            // Overwrite or merge mode
            const result = await dispatch(applyDiscoveryWithMode({
                hostId: host.id,
                mode: selectedMode,
                assetId: selectedAsset.asset_id,
            }));

            if (result.type.includes('fulfilled')) {
                // 🔧 FIX: Refresh pending hosts before closing
                await dispatch(fetchPendingHosts());
                handleClose();
            }
        }
    };

    // Go back one step
    const handleBack = () => {
        if (step === 'confirm') {
            setStep('select_mode');
            setSelectedMode(null);
        } else if (step === 'select_mode') {
            setStep('select_target');
            setSelectedAsset(null);
            dispatch(clearPreviewData());
        } else if (step === 'create_new' && matchResults?.matches?.length > 0) {
            setStep('select_target');
        }
    };

    // Render host info card
    const renderHostInfo = () => (
        <div className="host-info-card">
            <h4>Discovered Host</h4>
            <div className="host-details-grid">
                <div className="detail-item">
                    <span className="label">IP Address</span>
                    <span className="value ip">{host.ip_address}</span>
                </div>
                {host.hostname && (
                    <div className="detail-item">
                        <span className="label">Hostname</span>
                        <span className="value">{host.hostname}</span>
                    </div>
                )}
                {host.mac_address && (
                    <div className="detail-item">
                        <span className="label">MAC Address</span>
                        <code className="value">{host.mac_address}</code>
                    </div>
                )}
                {host.os_info && (
                    <div className="detail-item">
                        <span className="label">OS Info</span>
                        <span className="value">{host.os_info}</span>
                    </div>
                )}
                {host.open_ports && host.open_ports.length > 0 && (
                    <div className="detail-item full-width">
                        <span className="label">Open Ports ({host.open_ports.length})</span>
                        <div className="ports-display">
                            {host.open_ports.slice(0, 8).map((port, i) => (
                                <span key={i} className="port-badge">
                  {port.port}/{port.protocol}
                </span>
                            ))}
                            {host.open_ports.length > 8 && (
                                <span className="port-more">+{host.open_ports.length - 8}</span>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );

    // Render mode selection
    const renderModeSelection = () => (
        <div className="mode-selection">
            <div className="section-header">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M12 2v20M2 12h20" />
                </svg>
                <h4>How would you like to apply the discovery?</h4>
            </div>
            <p className="section-desc">
                Choose how to apply the discovered data to <strong>{selectedAsset?.asset_name}</strong>
            </p>

            <div className="mode-cards">
                {/* Overwrite Mode */}
                <div
                    className={`mode-card mode-overwrite ${selectedMode === 'overwrite' ? 'selected' : ''}`}
                    onClick={() => handleSelectMode('overwrite')}
                >
                    <div className="mode-icon">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z" />
                        </svg>
                    </div>
                    <div className="mode-content">
                        <h5>Overwrite</h5>
                        <p>Replace all existing data with discovered data</p>
                        <div className="mode-warning">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                                <line x1="12" y1="9" x2="12" y2="13" />
                                <line x1="12" y1="17" x2="12.01" y2="17" />
                            </svg>
                            <span>Existing ports will be removed</span>
                        </div>
                    </div>
                    {previewData?.overwrite_changes && (
                        <div className="mode-preview">
                            {previewData.overwrite_changes.fields_to_replace?.length > 0 && (
                                <span className="preview-badge warning">
                  {previewData.overwrite_changes.fields_to_replace.length} fields replaced
                </span>
                            )}
                            {previewData.overwrite_changes.ports_to_remove > 0 && (
                                <span className="preview-badge danger">
                  -{previewData.overwrite_changes.ports_to_remove} ports
                </span>
                            )}
                            {previewData.overwrite_changes.ports_to_add > 0 && (
                                <span className="preview-badge success">
                  +{previewData.overwrite_changes.ports_to_add} ports
                </span>
                            )}
                        </div>
                    )}
                </div>

                {/* Merge Mode */}
                <div
                    className={`mode-card mode-merge ${selectedMode === 'merge' ? 'selected' : ''}`}
                    onClick={() => handleSelectMode('merge')}
                >
                    <div className="mode-icon">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
                        </svg>
                    </div>
                    <div className="mode-content">
                        <h5>Merge / Update</h5>
                        <p>Keep existing data and add new discovered data</p>
                        <div className="mode-info">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <circle cx="12" cy="12" r="10" />
                                <path d="M12 16v-4M12 8h.01" />
                            </svg>
                            <span>Only fills empty fields, adds new ports</span>
                        </div>
                    </div>
                    {previewData?.merge_changes && (
                        <div className="mode-preview">
                            {previewData.merge_changes.fields_to_fill?.length > 0 && (
                                <span className="preview-badge success">
                  {previewData.merge_changes.fields_to_fill.length} fields added
                </span>
                            )}
                            {previewData.merge_changes.ports_to_add > 0 && (
                                <span className="preview-badge success">
                  +{previewData.merge_changes.ports_to_add} ports
                </span>
                            )}
                            {(previewData.merge_changes.fields_to_fill?.length === 0 &&
                                previewData.merge_changes.ports_to_add === 0) && (
                                <span className="preview-badge neutral">No changes</span>
                            )}
                        </div>
                    )}
                </div>
            </div>

            <div className="divider">
                <span>OR</span>
            </div>

            <button
                className="btn btn-secondary full-width"
                onClick={() => {
                    setSelectedMode('create_new');
                    setStep('create_new');
                }}
            >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M12 5v14M5 12h14" />
                </svg>
                Create as New Asset Instead
            </button>
        </div>
    );

    // Render confirmation step
    const renderConfirmation = () => {
        const isOverwrite = selectedMode === 'overwrite';

        return (
            <div className="confirm-section">
                <div className={`confirm-header ${isOverwrite ? 'warning' : 'info'}`}>
                    <div className="confirm-icon">
                        {isOverwrite ? (
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                                <line x1="12" y1="9" x2="12" y2="13" />
                                <line x1="12" y1="17" x2="12.01" y2="17" />
                            </svg>
                        ) : (
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <circle cx="12" cy="12" r="10" />
                                <path d="M12 16v-4M12 8h.01" />
                            </svg>
                        )}
                    </div>
                    <h4>
                        {isOverwrite
                            ? 'Confirm Overwrite'
                            : 'Confirm Merge'}
                    </h4>
                </div>

                <p className="confirm-text">
                    {isOverwrite
                        ? `This will replace all existing data in "${selectedAsset?.asset_name}" with the discovered data.`
                        : `This will add the discovered data to "${selectedAsset?.asset_name}" without removing existing data.`
                    }
                </p>

                {/* Show what will change */}
                {previewData && (
                    <div className="changes-preview">
                        <h5>Changes to be applied:</h5>

                        {isOverwrite && previewData.overwrite_changes?.fields_to_replace?.length > 0 && (
                            <div className="changes-group">
                                <h6>Fields to be replaced:</h6>
                                <div className="changes-list">
                                    {previewData.overwrite_changes.fields_to_replace.map((change, i) => (
                                        <div key={i} className="change-item replace">
                                            <span className="field-name">{change.field}</span>
                                            <span className="old-value">{change.current || '(empty)'}</span>
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                <path d="M5 12h14M12 5l7 7-7 7" />
                                            </svg>
                                            <span className="new-value">{change.new}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {!isOverwrite && previewData.merge_changes?.fields_to_fill?.length > 0 && (
                            <div className="changes-group">
                                <h6>Fields to be filled:</h6>
                                <div className="changes-list">
                                    {previewData.merge_changes.fields_to_fill.map((change, i) => (
                                        <div key={i} className="change-item add">
                                            <span className="field-name">{change.field}</span>
                                            <span className="new-value">{change.value}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        <div className="ports-summary">
                            {isOverwrite ? (
                                <>
                                    {previewData.existing_ports_count > 0 && (
                                        <div className="port-change remove">
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                <path d="M5 12h14" />
                                            </svg>
                                            {previewData.existing_ports_count} existing ports will be removed
                                        </div>
                                    )}
                                    {previewData.discovered_ports_count > 0 && (
                                        <div className="port-change add">
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                <path d="M12 5v14M5 12h14" />
                                            </svg>
                                            {previewData.discovered_ports_count} discovered ports will be added
                                        </div>
                                    )}
                                </>
                            ) : (
                                previewData.merge_changes?.ports_to_add > 0 && (
                                    <div className="port-change add">
                                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                            <path d="M12 5v14M5 12h14" />
                                        </svg>
                                        {previewData.merge_changes.ports_to_add} new ports will be added
                                    </div>
                                )
                            )}
                        </div>
                    </div>
                )}
            </div>
        );
    };

    // Render create new form
    const renderCreateNew = () => (
        <div className="create-section">
            <div className="section-header">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M12 5v14M5 12h14" />
                </svg>
                <h4>Create New Asset</h4>
            </div>
            <p className="section-desc">
                {matchResults?.matches?.length > 0
                    ? 'Create this host as a new asset instead of updating an existing one.'
                    : 'No matching assets found. Create a new asset from the discovered data.'}
            </p>

            <div className="form-group">
                <label htmlFor="asset-name">
                    Asset Name <span className="required">*</span>
                </label>
                <input
                    type="text"
                    id="asset-name"
                    value={assetName}
                    onChange={(e) => {
                        setAssetName(e.target.value);
                        if (errors.assetName) setErrors((p) => ({ ...p, assetName: null }));
                    }}
                    placeholder="Enter asset name"
                    className={`form-input ${errors.assetName ? 'error' : ''}`}
                />
                {errors.assetName && <p className="form-error">{errors.assetName}</p>}
            </div>

            <div className="form-group">
                <label htmlFor="asset-type">
                    Asset Type <span className="required">*</span>
                </label>
                <select
                    id="asset-type"
                    value={assetTypeId}
                    onChange={(e) => {
                        setAssetTypeId(e.target.value);
                        if (errors.assetTypeId) setErrors((p) => ({ ...p, assetTypeId: null }));
                    }}
                    className={`form-select ${errors.assetTypeId ? 'error' : ''}`}
                >
                    <option value="">Select asset type...</option>
                    {assetTypes?.map((type) => (
                        <option key={type.id} value={type.id}>
                            {type.type_name}
                        </option>
                    ))}
                </select>
                {errors.assetTypeId && <p className="form-error">{errors.assetTypeId}</p>}
            </div>

            <div className="auto-fill-info">
                <h5>Will be auto-filled from discovery:</h5>
                <ul>
                    <li>IP Address: {host.ip_address}</li>
                    {host.hostname && <li>Hostname: {host.hostname}</li>}
                    {host.mac_address && <li>MAC Address: {host.mac_address}</li>}
                    {host.os_info && <li>OS: {host.os_info}</li>}
                    {host.open_ports?.length > 0 && <li>Ports: {host.open_ports.length} open ports</li>}
                </ul>
            </div>
        </div>
    );

    // Get the modal title based on step
    const getModalTitle = () => {
        switch (step) {
            case 'loading':
                return 'Checking for Matches...';
            case 'select_target':
                return 'Select Target Asset';
            case 'select_mode':
                return 'Select Apply Mode';
            case 'confirm':
                return selectedMode === 'overwrite' ? 'Confirm Overwrite' : 'Confirm Merge';
            case 'create_new':
                return 'Create New Asset';
            default:
                return 'Apply Discovery';
        }
    };

    // Get the submit button text
    const getSubmitText = () => {
        if (loading.applyMode) {
            return 'Applying...';
        }
        switch (step) {
            case 'confirm':
                return selectedMode === 'overwrite' ? 'Overwrite Asset' : 'Merge with Asset';
            case 'create_new':
                return 'Create Asset';
            default:
                return 'Apply';
        }
    };

    return (
        <div className="modal-overlay" onClick={handleClose}>
            <div className="modal modal-apply-discovery" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>{getModalTitle()}</h2>
                    <button className="modal-close" onClick={handleClose}>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M18 6L6 18M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                <div className="modal-body">
                    {/* Always show host info */}
                    {renderHostInfo()}

                    {/* Loading State */}
                    {step === 'loading' && (
                        <div className="loading-state">
                            <div className="spinner-lg" />
                            <p>Checking for matching assets...</p>
                        </div>
                    )}

                    {/* Select Target Asset */}
                    {step === 'select_target' && matchResults?.matches && (
                        <div className="matches-section">
                            <div className="section-header">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <circle cx="11" cy="11" r="8" />
                                    <path d="M21 21l-4.35-4.35" />
                                </svg>
                                <h4>Potential Matches Found</h4>
                            </div>
                            <p className="section-desc">
                                We found {matchResults.matches.length} existing asset(s) that match this host.
                                Select one to update or create a new asset.
                            </p>

                            <div className="matches-list">
                                {matchResults.matches.map((match, index) => (
                                    <div
                                        key={index}
                                        className="match-card clickable"
                                        onClick={() => handleSelectAsset(match)}
                                    >
                                        <div className="match-header">
                                            <div className="match-name">
                                                <strong>{match.asset_name}</strong>
                                                <span className="match-id">ID: {match.asset_id}</span>
                                            </div>
                                            <span className={`confidence-badge confidence-${match.confidence}`}>
                        {match.confidence} match
                      </span>
                                        </div>
                                        <div className="match-details">
                                            <span>Match by: <strong>{match.match_type.replace('_', ' ')}</strong></span>
                                            {match.asset_type && <span>Type: {match.asset_type}</span>}
                                        </div>
                                        <div className="match-info">
                                            {match.ip_address && <span>IP: {match.ip_address}</span>}
                                            {match.mac_address && <span>MAC: {match.mac_address}</span>}
                                            {match.hostname && <span>Hostname: {match.hostname}</span>}
                                        </div>
                                        <div className="match-select-hint">
                                            Click to select this asset
                                        </div>
                                    </div>
                                ))}
                            </div>

                            <div className="divider">
                                <span>OR</span>
                            </div>

                            <button
                                className="btn btn-secondary full-width"
                                onClick={() => {
                                    setSelectedMode('create_new');
                                    setStep('create_new');
                                }}
                            >
                                Create as New Asset
                            </button>
                        </div>
                    )}

                    {/* Select Mode */}
                    {step === 'select_mode' && renderModeSelection()}

                    {/* Confirmation */}
                    {step === 'confirm' && renderConfirmation()}

                    {/* Create New */}
                    {step === 'create_new' && renderCreateNew()}
                </div>

                <div className="modal-footer">
                    {/* Back Button */}
                    {(step === 'select_mode' || step === 'confirm' ||
                        (step === 'create_new' && matchResults?.matches?.length > 0)) && (
                        <button className="btn btn-ghost" onClick={handleBack}>
                            Back
                        </button>
                    )}

                    <div className="footer-right">
                        <button className="btn btn-secondary" onClick={handleClose}>
                            Cancel
                        </button>

                        {/* Submit Button */}
                        {(step === 'confirm' || step === 'create_new') && (
                            <button
                                className={`btn ${selectedMode === 'overwrite' ? 'btn-warning' : 'btn-primary'}`}
                                onClick={handleApply}
                                disabled={loading.applyMode}
                            >
                                {loading.applyMode && <span className="spinner" />}
                                {getSubmitText()}
                            </button>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ApplyDiscoveryModal;
