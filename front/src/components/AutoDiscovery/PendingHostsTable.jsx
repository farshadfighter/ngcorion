/**
 * PendingHostsTable - Table of discovered hosts awaiting approval
 */

import React, { useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { rejectHost, bulkApproveHosts, fetchPendingHosts } from '../../store/discoverySlice.jsx';
import { t, n } from "../../i18n";
import { tx } from "../../i18n/tx";

const PendingHostsTable = ({ hosts, loading, onApprove, assetTypes }) => {
    const dispatch = useDispatch();
    const { loading: storeLoading } = useSelector((state) => state.discovery);

    const [selectedIds, setSelectedIds] = useState([]);
    const [showBulkModal, setShowBulkModal] = useState(false);
    const [bulkAssetTypeId, setBulkAssetTypeId] = useState('');

    // Toggle single selection
    const toggleSelect = (id) => {
        setSelectedIds((prev) =>
            prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
        );
    };

    // Toggle all selection
    const toggleSelectAll = () => {
        if (selectedIds.length === hosts.length) {
            setSelectedIds([]);
        } else {
            setSelectedIds(hosts.map((h) => h.id));
        }
    };

    // Handle reject
    const handleReject = async (host) => {
        if (window.confirm(t("Reject host {{ip_address}}? This will remove it from the pending list.", { ip_address: host.ip_address }))) {
            await dispatch(rejectHost(host.id));
        }
    };

    // Handle bulk approve
    const handleBulkApprove = async () => {
        if (!bulkAssetTypeId) {
            alert(t("Please select an asset type"));
            return;
        }

        const result = await dispatch(bulkApproveHosts({
            hostIds: selectedIds,
            defaultAssetTypeId: parseInt(bulkAssetTypeId),
        }));

        if (result.type.includes('fulfilled')) {
            // 🔧 FIX: Wait for pending hosts to refresh before clearing state
            await dispatch(fetchPendingHosts());
            setSelectedIds([]);
            setShowBulkModal(false);
            setBulkAssetTypeId('');
        }
    };

    // Format ports for display with state color coding
    const formatPorts = (ports) => {
        if (!ports || ports.length === 0) return '-';
        const openPorts = ports.filter(p => p.state === 'open' || !p.state);
        const closedPorts = ports.filter(p => p.state === 'closed');
        const filteredPorts = ports.filter(p => p.state === 'filtered');
        const shown = [
            ...openPorts.slice(0, 3),
            ...closedPorts.slice(0, 2),
            ...filteredPorts.slice(0, 1),
        ];
        const remaining = ports.length - shown.length;
        return (
            <div className="ports-display">
                {openPorts.slice(0, 3).map((port, i) => (
                    <span key={i} className="port-badge port-state-open" title="open">
                        {port.port}/{port.protocol}
                    </span>
                ))}
                {closedPorts.slice(0, 2).map((port, i) => (
                    <span key={`c${i}`} className="port-badge port-state-closed" title="closed">
                        {port.port}/{port.protocol}
                    </span>
                ))}
                {filteredPorts.slice(0, 1).map((port, i) => (
                    <span key={`f${i}`} className="port-badge port-state-filtered" title="filtered">
                        {port.port}/{port.protocol}
                    </span>
                ))}
                {remaining > 0 && <span className="port-more">+{remaining}</span>}
                {closedPorts.length > 0 && (
                    <span className="port-state-label closed">{t("{{length}} closed", { length: closedPorts.length })}</span>
                )}
            </div>
        );
    };

    if (loading) {
        return (
            <div className="table-loading">
                <div className="spinner-lg" />
                <p>{t("Loading pending hosts...")}</p>
            </div>
        );
    }

    if (hosts.length === 0) {
        return (
            <div className="empty-state">
                <div className="empty-icon">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
                        <path d="M22 4L12 14.01l-3-3" />
                    </svg>
                </div>
                <h3>{t("No Pending Hosts")}</h3>
                <p>{t("All discovered hosts have been processed. Start a new scan to discover more assets.")}</p>
            </div>
        );
    }

    return (
        <div className="table-container">
            {/* Bulk Actions */}
            {selectedIds.length > 0 && (
                <div className="bulk-actions-bar">
                    <span className="bulk-count">{t("{{length}} host(s) selected", { length: selectedIds.length })}</span>
                    <div className="bulk-buttons">
                        <button
                            className="btn btn-sm btn-primary"
                            onClick={() => setShowBulkModal(true)}
                        >
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
                                <path d="M22 4L12 14.01l-3-3" />
                            </svg>
                           {t("Bulk Approve")}
                        </button>
                        <button
                            className="btn btn-sm btn-ghost"
                            onClick={() => setSelectedIds([])}
                        >
                           {t("Clear Selection")}
                        </button>
                    </div>
                </div>
            )}

            {/* Table */}
            <table className="data-table">
                <thead>
                <tr>
                    <th className="col-checkbox">
                        <input
                            type="checkbox"
                            checked={selectedIds.length === hosts.length && hosts.length > 0}
                            onChange={toggleSelectAll}
                        />
                    </th>
                    <th>{t("IP Address")}</th>
                    <th>{t("Hostname")}</th>
                    <th>{t("MAC Address")}</th>
                    <th>{t("OS Info")}</th>
                    <th>{t("Ports")}</th>
                    <th>{t("Status")}</th>
                    <th className="col-actions">{t("Actions")}</th>
                </tr>
                </thead>
                <tbody>
                {hosts.map((host) => (
                    <tr key={host.id} className={host.highlight ? 'row-highlight' : ''}>
                        <td className="col-checkbox">
                            <input
                                type="checkbox"
                                checked={selectedIds.includes(host.id)}
                                onChange={() => toggleSelect(host.id)}
                            />
                        </td>
                        <td>
                            <span className="ip-address">{host.ip_address}</span>
                        </td>
                        <td>{host.hostname || <span className="text-muted">-</span>}</td>
                        <td>
                            {host.mac_address ? (
                                <code className="mac-address">{host.mac_address}</code>
                            ) : (
                                <span className="text-muted">-</span>
                            )}
                        </td>
                        <td>
                            {host.os_info ? (
                                <div className="os-info">
                                    <span>{host.os_info}</span>
                                    {host.os_accuracy && (
                                        <span className="os-accuracy">{host.os_accuracy}%</span>
                                    )}
                                </div>
                            ) : (
                                <span className="text-muted">{t("Unknown")}</span>
                            )}
                        </td>
                        <td>{formatPorts(host.open_ports)}</td>
                        <td>
                <span className={`status-badge status-${host.status}`}>
                  {host.status}
                </span>
                        </td>
                        <td className="col-actions">
                            <div className="action-buttons">
                                <button
                                    className="btn btn-sm btn-success"
                                    onClick={() => onApprove(host)}
                                    title={t("Approve host")}
                                >
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <path d="M20 6L9 17l-5-5" />
                                    </svg>
                                   {t("Approve")}
                                </button>
                                <button
                                    className="btn btn-sm btn-ghost btn-danger"
                                    onClick={() => handleReject(host)}
                                    title={t("Reject host")}
                                    disabled={storeLoading.approve}
                                >
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <path d="M18 6L6 18M6 6l12 12" />
                                    </svg>
                                </button>
                            </div>
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>

            {/* Bulk Approve Modal */}
            {showBulkModal && (
                <div className="modal-overlay" onClick={() => setShowBulkModal(false)}>
                    <div className="modal modal-sm" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>{t("Bulk Approve Hosts")}</h3>
                            <button className="modal-close" onClick={() => setShowBulkModal(false)}>
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M18 6L6 18M6 6l12 12" />
                                </svg>
                            </button>
                        </div>
                        <div className="modal-body">
                            <p className="modal-text">
                               {tx("You are about to create assets for {{count}} discovered hosts. Please select a default asset type for all new assets.", { count: <strong>{n(selectedIds.length)}</strong> })}
                            </p>
                            <div className="form-group">
                                <label htmlFor="bulk-asset-type">{t("Asset Type")}</label>
                                <select
                                    id="bulk-asset-type"
                                    value={bulkAssetTypeId}
                                    onChange={(e) => setBulkAssetTypeId(e.target.value)}
                                    className="form-select"
                                >
                                    <option value="">{t("Select asset type...")}</option>
                                    {assetTypes?.map((type) => (
                                        <option key={type.id} value={type.id}>
                                            {type.type_name}
                                        </option>
                                    ))}
                                </select>
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button
                                className="btn btn-secondary"
                                onClick={() => setShowBulkModal(false)}
                            >
                               {t("Cancel")}
                            </button>
                            <button
                                className="btn btn-primary"
                                onClick={handleBulkApprove}
                                disabled={!bulkAssetTypeId || storeLoading.approve}
                            >
                                {storeLoading.approve ? (
                                    <>
                                        <span className="spinner" />
                                       {t("Processing...")}
                                    </>
                                ) : (
                                    t("Approve {{length}} Hosts", { length: selectedIds.length })
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default PendingHostsTable;
