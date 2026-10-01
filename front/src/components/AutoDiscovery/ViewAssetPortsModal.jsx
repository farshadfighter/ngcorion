/**
 * ViewAssetPortsModal - View and manage ports for an asset
 *
 * Features:
 * - Fetch all ports for a specific asset
 * - Display port details (port number, protocol, service, state)
 * - Delete individual ports
 */

import React, { useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { fetchAssetPorts, deletePort } from '../../store/discoverySlice.jsx';
import '../../assets/autoDiscoveryStyle/ViewAssetPortsModal.css';
import { t } from "../../i18n";

const ViewAssetPortsModal = ({ asset, onClose }) => {
  const dispatch = useDispatch();
  const { assetPorts, loading, error } = useSelector((state) => state.discovery);

  useEffect(() => {
    if (asset && asset.id) {
      dispatch(fetchAssetPorts(asset.id));
    }
  }, [asset, dispatch]);

  const handleDeletePort = async (portId) => {
    if (!window.confirm(t("Are you sure you want to delete this port?"))) {
      return;
    }

    try {
      await dispatch(deletePort(portId)).unwrap();
    } catch (err) {
      alert(err || t("Failed to delete port"));
    }
  };

  if (!asset) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal view-ports-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <h2>{t("Asset Ports")}</h2>
            <p className="asset-info">
              {asset.asset_name} ({asset.ip_address})
            </p>
          </div>
          <button className="modal-close" onClick={onClose}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="modal-body">
          {loading.ports ? (
            <div className="loading-state">
              <div className="spinner" />
              <p>{t("Loading ports...")}</p>
            </div>
          ) : error ? (
            <div className="error-state">
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 8v4M12 16h.01" />
              </svg>
              <p>{error}</p>
            </div>
          ) : assetPorts.length === 0 ? (
            <div className="empty-state">
              <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 8v8M8 12h8" />
              </svg>
              <h3>{t("No Ports Found")}</h3>
              <p>{t("This asset doesn't have any discovered ports yet.")}</p>
            </div>
          ) : (
            <div className="ports-table-container">
              <table className="ports-table">
                <thead>
                  <tr>
                    <th>{t("Port")}</th>
                    <th>{t("Protocol")}</th>
                    <th>{t("Service")}</th>
                    <th>{t("Product")}</th>
                    <th>{t("Version")}</th>
                    <th>{t("State")}</th>
                    <th>{t("Actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  {assetPorts.map((port) => (
                    <tr key={port.id}>
                      <td>
                        <strong>{port.port_number}</strong>
                      </td>
                      <td>
                        <span className={`protocol-badge ${port.protocol?.toLowerCase()}`}>
                          {port.protocol}
                        </span>
                      </td>
                      <td>{port.service_name || '-'}</td>
                      <td>{port.service_product || '-'}</td>
                      <td>{port.service_version || '-'}</td>
                      <td>
                        <span className={`state-badge ${port.state?.toLowerCase()}`}>
                          {port.state || 'unknown'}
                        </span>
                      </td>
                      <td>
                        <button
                          className="btn-icon btn-delete"
                          onClick={() => handleDeletePort(port.id)}
                          title={t("Delete port")}
                        >
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2M10 11v6M14 11v6" />
                          </svg>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <div className="footer-info">
            <span className="port-count">
              {t("{{count}} ports found", { count: assetPorts.length })}
            </span>
          </div>
          <button className="btn btn-secondary" onClick={onClose}>
           {t("Close")}
          </button>
        </div>
      </div>
    </div>

  );
};

export default ViewAssetPortsModal;
