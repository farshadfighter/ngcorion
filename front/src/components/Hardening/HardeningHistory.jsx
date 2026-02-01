/**
 * HardeningHistory - Component to display hardening action history
 */

import { useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    fetchHardeningHistory,
    selectHardeningHistory,
    selectLoading,
} from '../../store/hardeningSlice';

export const HardeningHistory = () => {
    const dispatch = useDispatch();

    const hardeningHistory = useSelector(selectHardeningHistory);
    const loading = useSelector(selectLoading);

    // Fetch history on mount
    useEffect(() => {
        dispatch(fetchHardeningHistory({ limit: 50 }));
    }, [dispatch]);

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
                <button
                    className="btn btn-small"
                    onClick={() => dispatch(fetchHardeningHistory({ limit: 50 }))}
                >
                    Refresh
                </button>
            </div>

            <table className="history-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Check</th>
                        <th>Title</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Verified</th>
                        <th>Created</th>
                    </tr>
                </thead>
                <tbody>
                    {hardeningHistory.map(action => (
                        <tr key={action.id}>
                            <td>{action.id}</td>
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
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default HardeningHistory;
