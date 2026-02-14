/**
 * HardeningHistory - Component to display hardening action history
 * Supports multiple device types (Cisco, FortiGate, etc.)
 */

import { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    fetchHardeningHistory,
    selectHardeningHistory,
    selectLoading,
} from '../../store/hardeningSlice';

// Device type display labels
const deviceTypeLabels = {
    cisco: 'Cisco IOS',
    fortinet: 'FortiGate',
    linux: 'Linux',
    windows: 'Windows',
    apache: 'Apache',
};

export const HardeningHistory = () => {
    const dispatch = useDispatch();

    const hardeningHistory = useSelector(selectHardeningHistory);
    const loading = useSelector(selectLoading);

    // Filter state
    const [deviceTypeFilter, setDeviceTypeFilter] = useState('all');

    // Fetch history on mount and when filter changes
    useEffect(() => {
        // For now, fetch Cisco and FortiGate history
        // In a future enhancement, this could aggregate multiple device type histories
        const deviceType = deviceTypeFilter === 'all' ? 'cisco' : deviceTypeFilter;
        dispatch(fetchHardeningHistory({ limit: 50, deviceType }));
    }, [dispatch, deviceTypeFilter]);

    // Format date
    const formatDate = (dateStr) => {
        if (!dateStr) return 'N/A';
        return new Date(dateStr).toLocaleString();
    };

    // Get status badge class
    const getStatusClass = (status) => {
        switch (status?.toLowerCase()) {
            case 'success':
                return 'status-success';
            case 'failed':
                return 'status-failed';
            case 'pending':
                return 'status-pending';
            case 'executing':
                return 'status-executing';
            case 'blocked':
                return 'status-blocked';
            default:
                return 'status-unknown';
        }
    };

    if (loading.history) {
        return <div className="loading-message">Loading hardening history...</div>;
    }

    if (hardeningHistory.length === 0) {
        return (
            <div className="no-history-message">
                <p>No hardening actions have been performed yet.</p>
            </div>
        );
    }

    return (
        <div className="hardening-history">
            <div className="history-header">
                <h4>Hardening Action History</h4>
                <div className="history-controls">
                    <select
                        className="device-type-filter"
                        value={deviceTypeFilter}
                        onChange={(e) => setDeviceTypeFilter(e.target.value)}
                    >
                        <option value="all">All Device Types</option>
                        <option value="cisco">Cisco IOS</option>
                        <option value="fortinet">FortiGate</option>
                        <option value="linux">Linux</option>
                    </select>
                    <button
                        className="btn btn-small"
                        onClick={() => {
                            const deviceType = deviceTypeFilter === 'all' ? 'cisco' : deviceTypeFilter;
                            dispatch(fetchHardeningHistory({ limit: 50, deviceType }));
                        }}
                    >
                        Refresh
                    </button>
                </div>
            </div>

            <table className="history-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Device</th>
                        <th>Check</th>
                        <th>Title</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Verified</th>
                        <th>Created</th>
                    </tr>
                </thead>
                <tbody>
                    {hardeningHistory.map(action => {
                        const actionDeviceType = action.device_type || deviceTypeFilter || 'cisco';
                        return (
                            <tr key={action.id}>
                                <td>{action.id}</td>
                                <td>
                                    <span className={`badge device-badge device-${actionDeviceType}`}>
                                        {deviceTypeLabels[actionDeviceType] || actionDeviceType}
                                    </span>
                                </td>
                                <td>
                                    <code>{action.check_number}</code>
                                </td>
                                <td className="col-title">
                                    {action.check_title}
                                </td>
                                <td>
                                    <span className={`badge type-${action.action_type}`}>
                                        {action.action_type}
                                    </span>
                                </td>
                                <td>
                                    <span className={`badge ${getStatusClass(action.status)}`}>
                                        {action.status}
                                    </span>
                                </td>
                                <td>
                                    {action.verification_passed === null ? (
                                        <span className="verification-na">-</span>
                                    ) : action.verification_passed ? (
                                        <span className="verification-passed">Yes</span>
                                    ) : (
                                        <span className="verification-failed">No</span>
                                    )}
                                </td>
                                <td className="col-date">
                                    {formatDate(action.created_at)}
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
};

export default HardeningHistory;
