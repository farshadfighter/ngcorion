/**
 * ApproveHostModal - Modal for approving/merging discovered hosts
 */

import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
  checkHostMatches,
  approveHost,
  clearMatchResults,
} from '../../../store/slices/discoverySlice';

const ApproveHostModal = ({ host, assetTypes, onClose }) => {
  const dispatch = useDispatch();
  const { matchResults, loading } = useSelector((state) => state.discovery);

  const [step, setStep] = useState('loading'); // 'loading', 'matches', 'create'
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
        setStep('matches');
      } else {
        setStep('create');
      }
    }
  }, [matchResults]);

  // Clean up on close
  const handleClose = () => {
    dispatch(clearMatchResults());
    onClose();
  };

  // Handle merge with existing asset
  const handleMerge = async (assetId) => {
    const result = await dispatch(approveHost({
      hostId: host.id,
      action: 'merge_with_existing',
      assetId: assetId,
    }));

    if (result.type.includes('fulfilled')) {
      handleClose();
    }
  };

  // Handle create new asset
  const handleCreate = async () => {
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

    const result = await dispatch(approveHost({
      hostId: host.id,
      action: 'create_new',
      assetData: {
        asset_name: assetName.trim(),
        asset_type_id: parseInt(assetTypeId),
      },
    }));

    if (result.type.includes('fulfilled')) {
      handleClose();
    }
  };

  // Handle skip (mark as reviewed)
  const handleSkip = async () => {
    const result = await dispatch(approveHost({
      hostId: host.id,
      action: 'skip',
    }));

    if (result.type.includes('fulfilled')) {
      handleClose();
    }
  };

  // Get confidence badge color
  const getConfidenceClass = (confidence) => {
    switch (confidence) {
      case 'high':
        return 'confidence-high';
      case 'medium':
        return 'confidence-medium';
      default:
        return 'confidence-low';
    }
  };

  return (
    <div className="modal-overlay" onClick={handleClose}>
      <div className="modal modal-approve" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Approve Discovered Host</h2>
          <button className="modal-close" onClick={handleClose}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="modal-body">
          {/* Host Information */}
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
                  <span className="label">Open Ports</span>
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

          {/* Loading State */}
          {step === 'loading' && (
            <div className="loading-state">
              <div className="spinner-lg" />
              <p>Checking for matching assets...</p>
            </div>
          )}

          {/* Matches Found */}
          {step === 'matches' && matchResults?.matches && (
            <div className="matches-section">
              <div className="section-header">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="11" cy="11" r="8" />
                  <path d="M21 21l-4.35-4.35" />
                </svg>
                <h4>Potential Matches Found</h4>
              </div>
              <p className="section-desc">
                We found {matchResults.matches.length} existing asset(s) that may match this host.
                You can merge with one of them or create a new asset.
              </p>

              <div className="matches-list">
                {matchResults.matches.map((match, index) => (
                  <div key={index} className="match-card">
                    <div className="match-header">
                      <div className="match-name">
                        <strong>{match.asset_name}</strong>
                        <span className="match-id">ID: {match.asset_id}</span>
                      </div>
                      <span className={`confidence-badge ${getConfidenceClass(match.confidence)}`}>
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
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={() => handleMerge(match.asset_id)}
                      disabled={loading.approve}
                    >
                      {loading.approve ? (
                        <span className="spinner" />
                      ) : (
                        <>
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
                          </svg>
                          Merge with this Asset
                        </>
                      )}
                    </button>
                  </div>
                ))}
              </div>

              <div className="divider">
                <span>OR</span>
              </div>

              <button
                className="btn btn-secondary full-width"
                onClick={() => setStep('create')}
              >
                Create as New Asset
              </button>
            </div>
          )}

          {/* Create New Asset Form */}
          {step === 'create' && (
            <div className="create-section">
              <div className="section-header">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 5v14M5 12h14" />
                </svg>
                <h4>Create New Asset</h4>
              </div>
              <p className="section-desc">
                {matchResults?.matches?.length > 0
                  ? 'Create this host as a new asset instead of merging with an existing one.'
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
                </ul>
              </div>

              {matchResults?.matches?.length > 0 && (
                <button
                  className="btn btn-link"
                  onClick={() => setStep('matches')}
                >
                  Back to matches
                </button>
              )}
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-ghost" onClick={handleSkip} disabled={loading.approve}>
            Skip
          </button>
          <div className="footer-right">
            <button className="btn btn-secondary" onClick={handleClose}>
              Cancel
            </button>
            {step === 'create' && (
              <button
                className="btn btn-primary"
                onClick={handleCreate}
                disabled={loading.approve}
              >
                {loading.approve ? (
                  <>
                    <span className="spinner" />
                    Creating...
                  </>
                ) : (
                  <>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M12 5v14M5 12h14" />
                    </svg>
                    Create Asset
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ApproveHostModal;
