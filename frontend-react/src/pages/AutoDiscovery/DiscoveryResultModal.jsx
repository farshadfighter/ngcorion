/* ==========================================
   NGCORION - Discovery Result Modal
   Modal for applying discovery to assets
   ========================================== */

import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
  applyDiscovery,
  createAssetFromDiscovery,
  clearMatchedAsset,
} from '../../store/slices/discoverySlice';
import './DiscoveryResultModal.css';

const DiscoveryResultModal = ({ host, scanId, assetTypes, onClose }) => {
  const dispatch = useDispatch();
  
  const { matchedAsset, isApplying } = useSelector((state) => state.discovery);
  
  // Local state
  const [mode, setMode] = useState('loading'); // 'loading', 'update', 'create'
  const [selectedFields, setSelectedFields] = useState([]);
  const [newAssetName, setNewAssetName] = useState('');
  const [newAssetTypeId, setNewAssetTypeId] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  
  // Available fields for discovery
  const discoveryFields = [
    { key: 'hostname', label: 'Hostname', value: host.hostname },
    { key: 'mac_address', label: 'MAC Address', value: host.mac_address },
    { key: 'os_name', label: 'OS Name', value: host.os_name },
    { key: 'os_version', label: 'OS Version', value: host.os_version },
    { key: 'vendor', label: 'Manufacturer', value: host.vendor },
  ];
  
  // Determine mode based on matched asset
  useEffect(() => {
    if (matchedAsset === null) {
      setMode('loading');
    } else if (matchedAsset.found) {
      setMode('update');
      // Pre-select empty fields
      const emptyFields = matchedAsset.empty_fields || [];
      setSelectedFields(emptyFields.filter(f => 
        discoveryFields.some(df => df.key === f && df.value)
      ));
    } else {
      setMode('create');
      setNewAssetName(host.hostname || `Discovered-${host.ip_address}`);
    }
  }, [matchedAsset, host]);
  
  // Toggle field selection
  const toggleField = (fieldKey) => {
    setSelectedFields(prev => 
      prev.includes(fieldKey)
        ? prev.filter(f => f !== fieldKey)
        : [...prev, fieldKey]
    );
  };
  
  // Handle apply to existing asset
  const handleApply = async () => {
    if (selectedFields.length === 0) {
      alert('Please select at least one field to apply');
      return;
    }
    
    try {
      await dispatch(applyDiscovery({
        scanId,
        assetId: matchedAsset.asset_id,
        ipAddress: host.ip_address,
        fieldsToApply: selectedFields,
      })).unwrap();
      
      setSuccessMessage(`Successfully updated ${selectedFields.length} fields!`);
      setTimeout(() => {
        onClose();
      }, 2000);
    } catch (error) {
      alert('Failed to apply: ' + error);
    }
  };
  
  // Handle create new asset
  const handleCreate = async () => {
    if (!newAssetName.trim()) {
      alert('Please enter an asset name');
      return;
    }
    
    if (!newAssetTypeId) {
      alert('Please select an asset type');
      return;
    }
    
    try {
      await dispatch(createAssetFromDiscovery({
        discoveredHost: host,
        assetName: newAssetName.trim(),
        assetTypeId: parseInt(newAssetTypeId),
      })).unwrap();
      
      setSuccessMessage('Asset created successfully!');
      setTimeout(() => {
        onClose();
      }, 2000);
    } catch (error) {
      alert('Failed to create asset: ' + error);
    }
  };
  
  // Cleanup on close
  const handleClose = () => {
    dispatch(clearMatchedAsset());
    onClose();
  };

  return (
    <div className="modal-overlay" onClick={handleClose}>
      <div className="modal discovery-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>
            {mode === 'update' ? '📝 Update Existing Asset' : 
             mode === 'create' ? '➕ Create New Asset' : 
             '🔍 Checking...'}
          </h3>
          <button className="close-btn" onClick={handleClose}>×</button>
        </div>
        
        <div className="modal-body">
          {/* Success Message */}
          {successMessage && (
            <div className="success-banner">
              ✅ {successMessage}
            </div>
          )}
          
          {/* Loading State */}
          {mode === 'loading' && (
            <div className="loading-state">
              <p>Checking if this IP matches an existing asset...</p>
            </div>
          )}
          
          {/* Host Info */}
          <div className="host-info-section">
            <h4>Discovered Information</h4>
            <div className="info-grid">
              <div className="info-item">
                <span className="label">IP Address:</span>
                <span className="value">{host.ip_address}</span>
              </div>
              {host.hostname && (
                <div className="info-item">
                  <span className="label">Hostname:</span>
                  <span className="value">{host.hostname}</span>
                </div>
              )}
              {host.mac_address && (
                <div className="info-item">
                  <span className="label">MAC Address:</span>
                  <span className="value">{host.mac_address}</span>
                </div>
              )}
              {host.os_name && (
                <div className="info-item">
                  <span className="label">OS:</span>
                  <span className="value">
                    {host.os_name} {host.os_version || ''}
                  </span>
                </div>
              )}
              {host.vendor && (
                <div className="info-item">
                  <span className="label">Vendor:</span>
                  <span className="value">{host.vendor}</span>
                </div>
              )}
              <div className="info-item">
                <span className="label">Open Ports:</span>
                <span className="value">{host.ports?.length || 0} ports</span>
              </div>
            </div>
          </div>
          
          {/* Update Existing Asset */}
          {mode === 'update' && matchedAsset && (
            <div className="update-section">
              <div className="matched-asset-info">
                <h4>🎯 Matched Asset</h4>
                <p>
                  <strong>ID:</strong> {matchedAsset.asset_id} | 
                  <strong> Name:</strong> {matchedAsset.asset_name}
                </p>
              </div>
              
              <h4>Select Fields to Update</h4>
              <p className="hint">
                Only empty fields can be updated. Fields with existing data are skipped.
              </p>
              
              <div className="fields-list">
                {discoveryFields.map((field) => {
                  const isEmpty = matchedAsset.empty_fields?.includes(field.key);
                  const hasValue = !!field.value;
                  const canApply = isEmpty && hasValue;
                  const currentValue = matchedAsset.current_values?.[field.key];
                  
                  return (
                    <div 
                      key={field.key} 
                      className={`field-item ${canApply ? 'can-apply' : 'disabled'}`}
                    >
                      <label>
                        <input
                          type="checkbox"
                          checked={selectedFields.includes(field.key)}
                          onChange={() => toggleField(field.key)}
                          disabled={!canApply}
                        />
                        <span className="field-label">{field.label}</span>
                      </label>
                      <div className="field-values">
                        <span className="current">
                          Current: {currentValue || <em>(empty)</em>}
                        </span>
                        <span className="arrow">→</span>
                        <span className={`discovered ${hasValue ? 'has-value' : ''}`}>
                          {field.value || <em>(not discovered)</em>}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
              
              <div className="discovery-note">
                <p>⚠️ Fields updated via Auto Discovery will be highlighted in orange in the Asset List.</p>
              </div>
            </div>
          )}
          
          {/* Create New Asset */}
          {mode === 'create' && (
            <div className="create-section">
              <div className="no-match-info">
                <p>⚠️ No existing asset found with IP: <strong>{host.ip_address}</strong></p>
                <p>You can create a new asset with the discovered information.</p>
              </div>
              
              <div className="form-group">
                <label>Asset Name *</label>
                <input
                  type="text"
                  value={newAssetName}
                  onChange={(e) => setNewAssetName(e.target.value)}
                  placeholder="Enter asset name"
                />
              </div>
              
              <div className="form-group">
                <label>Asset Type *</label>
                <select 
                  value={newAssetTypeId} 
                  onChange={(e) => setNewAssetTypeId(e.target.value)}
                >
                  <option value="">Select Type...</option>
                  {assetTypes?.map((type) => (
                    <option key={type.id} value={type.id}>
                      {type.type_name}
                    </option>
                  ))}
                </select>
                {host.suggested_asset_type && (
                  <small>Suggested type: {host.suggested_asset_type}</small>
                )}
              </div>
              
              <div className="auto-fill-info">
                <h5>Will be auto-filled:</h5>
                <ul>
                  <li>IP Address: {host.ip_address}</li>
                  {host.hostname && <li>Hostname: {host.hostname}</li>}
                  {host.mac_address && <li>MAC Address: {host.mac_address}</li>}
                  {host.os_name && <li>OS: {host.os_name} {host.os_version || ''}</li>}
                  {host.vendor && <li>Manufacturer: {host.vendor}</li>}
                </ul>
              </div>
            </div>
          )}
        </div>
        
        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={handleClose}>
            Cancel
          </button>
          
          {mode === 'update' && (
            <button 
              className="btn btn-primary"
              onClick={handleApply}
              disabled={isApplying || selectedFields.length === 0}
            >
              {isApplying ? 'Applying...' : `Apply ${selectedFields.length} Fields`}
            </button>
          )}
          
          {mode === 'create' && (
            <button 
              className="btn btn-primary"
              onClick={handleCreate}
              disabled={isApplying}
            >
              {isApplying ? 'Creating...' : 'Create Asset'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default DiscoveryResultModal;
