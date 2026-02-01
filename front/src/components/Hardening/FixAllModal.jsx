/**
 * FixAllModal - Modal for batch fixing selected checks
 *
 * Steps:
 * 1. Show selected checks summary
 * 2. Collect parameters for all selected checks
 * 3. Collect SSH credentials
 * 4. Execute batch and show progress
 * 5. Show results summary
 */

import { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    fetchSessionParameters,
    executeBatchHarden,
    clearBatchResult,
    updateUserParameter,
    clearUserParameters,
    selectSelectedSession,
    selectSelectedCheckIds,
    selectSessionParameters,
    selectUserParameters,
    selectBatchResult,
    selectLoading,
    selectFailedChecks,
} from '../../store/hardeningSlice';
import { SSHCredentialsForm } from './SSHCredentialsForm';
import { ConfigurationForm } from './ConfigurationForm';

export const FixAllModal = ({ onClose }) => {
    const dispatch = useDispatch();

    const selectedSession = useSelector(selectSelectedSession);
    const selectedCheckIds = useSelector(selectSelectedCheckIds);
    const failedChecks = useSelector(selectFailedChecks);
    const sessionParameters = useSelector(selectSessionParameters);
    const userParameters = useSelector(selectUserParameters);
    const batchResult = useSelector(selectBatchResult);
    const loading = useSelector(selectLoading);

    // Steps: 'summary' | 'params' | 'credentials' | 'executing' | 'result'
    const [step, setStep] = useState('summary');
    const [sshCredentials, setSshCredentials] = useState(null);

    // Get selected check details
    const selectedChecks = failedChecks.filter(c => selectedCheckIds.includes(c.id));

    // Fetch parameters for selected checks on mount
    useEffect(() => {
        dispatch(fetchSessionParameters({
            sessionId: selectedSession.id,
            checkIds: selectedCheckIds,
        }));
        return () => {
            dispatch(clearBatchResult());
            dispatch(clearUserParameters());
        };
    }, [selectedSession.id, selectedCheckIds, dispatch]);

    // Handle close
    const handleClose = () => {
        dispatch(clearBatchResult());
        dispatch(clearUserParameters());
        onClose();
    };

    // Move from summary to params or credentials
    const handleSummaryConfirm = () => {
        if (sessionParameters?.required_parameters &&
            Object.keys(sessionParameters.required_parameters).length > 0) {
            // Check if any parameter actually requires input
            const needsInput = Object.values(sessionParameters.required_parameters)
                .some(p => p.required);
            if (needsInput) {
                setStep('params');
                return;
            }
        }
        setStep('credentials');
    };

    // Handle params submission
    const handleParamsSubmit = () => {
        setStep('credentials');
    };

    // Handle SSH credentials submission
    const handleCredentialsSubmit = (credentials) => {
        setSshCredentials(credentials);
        setStep('executing');

        // Execute batch fix
        dispatch(executeBatchHarden({
            sessionId: selectedSession.id,
            checkIds: selectedCheckIds,
            parameters: userParameters,
            sshCredentials: credentials,
            skipBackup: false,
        }));
    };

    // Update step when execution completes
    useEffect(() => {
        if (batchResult && step === 'executing') {
            setStep('result');
        }
    }, [batchResult, step]);

    // Handle parameter change
    const handleParamChange = (name, value) => {
        dispatch(updateUserParameter({ paramName: name, value }));
    };

    return (
        <div className="modal-overlay" onClick={handleClose}>
            <div className="modal fix-all-modal" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h3>Fix Selected Checks</h3>
                    <button className="close-btn" onClick={handleClose}>×</button>
                </div>

                <div className="modal-body">
                    {/* Step: Summary */}
                    {step === 'summary' && (
                        <div className="step-summary">
                            <h4>Selected Checks</h4>
                            <p>{selectedCheckIds.length} check(s) selected for hardening.</p>

                            <div className="selected-checks-list">
                                {selectedChecks.map(check => (
                                    <div key={check.id} className="selected-check-item">
                                        <code>{check.check_number}</code>
                                        <span>{check.check_title}</span>
                                    </div>
                                ))}
                            </div>

                            {loading.parameters && (
                                <div className="loading-message">
                                    Loading required parameters...
                                </div>
                            )}

                            {!loading.parameters && sessionParameters && (
                                <div className="parameters-summary">
                                    <div className="summary-stats">
                                        <span>Fixable: {sessionParameters.fixable_count}</span>
                                        <span>Unfixable: {sessionParameters.unfixable_count}</span>
                                    </div>

                                    {sessionParameters.no_template_checks?.length > 0 && (
                                        <div className="warning-message">
                                            <strong>Warning:</strong> {sessionParameters.no_template_checks.length} check(s)
                                            have no remediation template and will be skipped.
                                        </div>
                                    )}
                                </div>
                            )}

                            <div className="step-actions">
                                <button
                                    className="btn btn-secondary"
                                    onClick={handleClose}
                                >
                                    Cancel
                                </button>
                                <button
                                    className="btn btn-primary"
                                    onClick={handleSummaryConfirm}
                                    disabled={loading.parameters}
                                >
                                    Continue
                                </button>
                            </div>
                        </div>
                    )}

                    {/* Step: Parameters */}
                    {step === 'params' && sessionParameters && (
                        <div className="step-params">
                            <ConfigurationForm
                                parameters={sessionParameters.required_parameters}
                                values={userParameters}
                                onChange={handleParamChange}
                                onSubmit={handleParamsSubmit}
                                onCancel={() => setStep('summary')}
                                loading={false}
                            />
                        </div>
                    )}

                    {/* Step: SSH Credentials */}
                    {step === 'credentials' && (
                        <div className="step-credentials">
                            <SSHCredentialsForm
                                onSubmit={handleCredentialsSubmit}
                                onCancel={() => {
                                    if (sessionParameters?.required_parameters &&
                                        Object.values(sessionParameters.required_parameters).some(p => p.required)) {
                                        setStep('params');
                                    } else {
                                        setStep('summary');
                                    }
                                }}
                                loading={false}
                            />
                        </div>
                    )}

                    {/* Step: Executing */}
                    {step === 'executing' && (
                        <div className="step-executing">
                            <div className="executing-animation">
                                <div className="spinner"></div>
                                <p>Executing batch hardening...</p>
                                <p className="small">Fixing {selectedCheckIds.length} checks. This may take several minutes.</p>
                            </div>
                        </div>
                    )}

                    {/* Step: Result */}
                    {step === 'result' && batchResult && (
                        <div className="step-result">
                            <div className="result-summary">
                                <h4>Batch Hardening Complete</h4>

                                <div className="result-stats">
                                    <div className="stat-item success">
                                        <span className="stat-number">{batchResult.fixed_count}</span>
                                        <span className="stat-label">Fixed</span>
                                    </div>
                                    <div className="stat-item failed">
                                        <span className="stat-number">{batchResult.failed_count}</span>
                                        <span className="stat-label">Failed</span>
                                    </div>
                                    <div className="stat-item skipped">
                                        <span className="stat-number">{batchResult.skipped_count}</span>
                                        <span className="stat-label">Skipped</span>
                                    </div>
                                </div>
                            </div>

                            {batchResult.results && batchResult.results.length > 0 && (
                                <div className="results-list">
                                    <h5>Details</h5>
                                    <table className="results-table">
                                        <thead>
                                            <tr>
                                                <th>Check</th>
                                                <th>Status</th>
                                                <th>Details</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {batchResult.results.map((result, idx) => (
                                                <tr key={idx} className={`result-row ${result.status}`}>
                                                    <td>
                                                        <code>{result.check_number}</code>
                                                    </td>
                                                    <td>
                                                        <span className={`badge status-${result.status}`}>
                                                            {result.status}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        {result.error || result.reason || (
                                                            result.verification_passed ? 'Verified' : 'Not verified'
                                                        )}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}

                            <div className="step-actions">
                                <button
                                    className="btn btn-primary"
                                    onClick={handleClose}
                                >
                                    Close
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default FixAllModal;
