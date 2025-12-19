/**
 * Auto Discovery Asset List Modal - Full screen popup
 * Shows assets from Asset List that can be used for discovery scans
 */

import React from 'react';
import AssetListTable from './AssetListTable';
import './AutoDiscoveryAssetListModal.css';

const AutoDiscoveryAssetListModal = ({ onClose, onScanAsset, isScanning }) => {
  return (
    <div className="asset-list-modal-overlay" onClick={onClose}>
      <div className="asset-list-modal" onClick={(e) => e.stopPropagation()}>
        <div className="asset-list-modal-header">
          <div className="modal-header-left">
            <button className="modal-back-btn" onClick={onClose}>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M19 12H5M12 19l-7-7 7-7" />
              </svg>
            </button>
            <h2>Auto Discovery Asset list</h2>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="asset-list-modal-body">
          <AssetListTable
            onScanAsset={onScanAsset}
            isScanning={isScanning}
          />
        </div>
      </div>
    </div>
  );
};

export default AutoDiscoveryAssetListModal;
