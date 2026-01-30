/**
 * AuditResultsTable - Displays audit results with selection and fix actions
 */

import { useDispatch, useSelector } from 'react-redux';
import {
    toggleCheckSelection,
    selectAllFailedChecks,
    deselectAllChecks,
    selectAuditResults,
    selectFailedChecks,
    selectSelectedCheckIds,
    selectLoading,
    selectAllFailedSelected,
} from '../../store/hardeningSlice';

export const AuditResultsTable = ({ onFixSingle }) => {
    const dispatch = useDispatch();

    const auditResults = useSelector(selectAuditResults);
    const failedChecks = useSelector(selectFailedChecks);
    const selectedCheckIds = useSelector(selectSelectedCheckIds);
    const loading = useSelector(selectLoading);
    const allSelected = useSelector(selectAllFailedSelected);

    // Handle select all toggle
    const handleSelectAll = () => {
        if (allSelected) {
            dispatch(deselectAllChecks());
        } else {
            dispatch(selectAllFailedChecks());
        }
    };

    // Handle individual check selection
    const handleCheckToggle = (checkId) => {
        dispatch(toggleCheckSelection(checkId));
    };

    // Get severity badge class
    const getSeverityClass = (severity) => {
        switch (severity?.toLowerCase()) {
            case 'high':
            case 'critical':
                return 'severity-high';
            case 'medium':
                return 'severity-medium';
            case 'low':
                return 'severity-low';
            default:
                return 'severity-info';
        }
    };

    // Get status badge class
    const getStatusClass = (status) => {
        switch (status?.toUpperCase()) {
            case 'PASS':
                return 'status-pass';
            case 'FAIL':
                return 'status-fail';
            case 'ERROR':
                return 'status-error';
            default:
                return 'status-info';
        }
    };

    if (loading.results) {
        return <div className="loading-message">Loading audit results...</div>;
    }

    if (auditResults.length === 0) {
        return <div className="no-results-message">No audit results available.</div>;
    }

    return (
        <div className="audit-results-table-container">
            {/* Selection Summary */}
            {failedChecks.length > 0 && (
                <div className="selection-summary">
                    <span>
                        {selectedCheckIds.length} of {failedChecks.length} failed checks selected
                    </span>
                </div>
            )}

            {/* Table */}
            <table className="audit-results-table">
                <thead>
                    <tr>
                        <th className="col-checkbox">
                            <input
                                type="checkbox"
                                checked={allSelected}
                                onChange={handleSelectAll}
                                disabled={failedChecks.length === 0}
                                title="Select all failed checks"
                            />
                        </th>
                        <th className="col-check-number">Check #</th>
                        <th className="col-title">Title</th>
                        <th className="col-severity">Severity</th>
                        <th className="col-status">Status</th>
                        <th className="col-actions">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {auditResults.map(result => {
                        const isFailed = result.status === 'FAIL';
                        const isSelected = selectedCheckIds.includes(result.id);

                        return (
                            <tr
                                key={result.id}
                                className={`${isFailed ? 'row-failed' : 'row-passed'} ${isSelected ? 'row-selected' : ''}`}
                            >
                                <td className="col-checkbox">
                                    <input
                                        type="checkbox"
                                        checked={isSelected}
                                        onChange={() => handleCheckToggle(result.id)}
                                        disabled={!isFailed}
                                    />
                                </td>
                                <td className="col-check-number">
                                    <code>{result.check_number}</code>
                                </td>
                                <td className="col-title">
                                    {result.check_title}
                                </td>
                                <td className="col-severity">
                                    <span className={`badge ${getSeverityClass(result.severity)}`}>
                                        {result.severity || 'N/A'}
                                    </span>
                                </td>
                                <td className="col-status">
                                    <span className={`badge ${getStatusClass(result.status)}`}>
                                        {result.status}
                                    </span>
                                </td>
                                <td className="col-actions">
                                    {isFailed && (
                                        <button
                                            className="btn btn-small btn-fix"
                                            onClick={() => onFixSingle(result)}
                                        >
                                            Fix
                                        </button>
                                    )}
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>

            {/* Legend */}
            <div className="table-legend">
                <span className="legend-item">
                    <span className="badge status-pass">PASS</span> - Check passed
                </span>
                <span className="legend-item">
                    <span className="badge status-fail">FAIL</span> - Check failed (fixable)
                </span>
            </div>
        </div>
    );
};

export default AuditResultsTable;
