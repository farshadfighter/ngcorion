/**
 * AutoHardenModal - Modal for automatic hardening with CIS defaults
 *
 * Steps:
 * 1. Show preview with default values that will be applied
 * 2. Show which checks will be skipped (require user input)
 * 3. Collect SSH credentials
 * 4. Require confirmation checkbox
 * 5. Execute and show results
 */

import { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    fetchAutoHardenPreview,
    executeAutoHarden,
    clearAutoHardenPreview,
    clearBatchResult,
    selectSelectedSession,
    selectAutoHardenPreview,
    selectBatchResult,
    selectLoading,
} from '../../store/hardeningSlice';
import { SSHCredentialsForm } from './SSHCredentialsForm';

export const AutoHardenModal = ({ deviceType = 'cisco', onClose }) => {
    const dispatch = useDispatch();

    const selectedSession = useSelector(selectSelectedSession);
    const autoHardenPreview = useSelector(selectAutoHardenPreview);
    const batchResult = useSelector(selectBatchResult);
    const loading = useSelector(selectLoading);

    // Steps: 'preview' | 'credentials' | 'executing' | 'result'
    const [step, setStep] = useState('preview');
    const [confirmed, setConfirmed] = useState(false);
    const [sshCredentials, setSshCredentials] = useState(null);
    const [vdom, setVdom] = useState(''); // FortiGate VDOM support

    // Fetch preview on mount
    useEffect(() => {
        dispatch(fetchAutoHardenPreview({ sessionId: selectedSession.id, deviceType }));
        return () => {
            dispatch(clearAutoHardenPreview());
            dispatch(clearBatchResult());
        };
    }, [selectedSession.id, deviceType, dispatch]);

    // Handle close
    const handleClose = () => {
        dispatch(clearAutoHardenPreview());
        dispatch(clearBatchResult());
        onClose();
    };

    // Move to credentials step
    const handlePreviewConfirm = () => {
        if (!confirmed) {
            alert('Please confirm that you have reviewed the default values.');
            return;
        }
        setStep('credentials');
    };

    // Handle SSH credentials submission
    const handleCredentialsSubmit = (credentials) => {
        setSshCredentials(credentials);
        setStep('executing');

        // Execute auto-harden
        dispatch(executeAutoHarden({
            sessionId: selectedSession.id,
            assetId: selectedSession.asset_id,  // Required for Linux
            sshCredentials: credentials,
            skipBackup: false,
            deviceType,
            vdom: deviceType === 'fortinet' ? vdom : null,
        }));
    };

    // Update step when execution completes
    useEffect(() => {
        if (batchResult && step === 'executing') {
            setStep('result');
        }
    }, [batchResult, step]);

    return (
        <div className="modal-overlay" onClick={handleClose}>
            <div className="modal auto-harden-modal" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h3>Automatic Hardening</h3>
                    <button className="close-btn" onClick={handleClose}>×</button>
                </div>

                <div className="modal-body">
                    {/* Step: Preview */}
                    {step === 'preview' && (
                        <div className="step-preview">
                            {loading.autoPreview && (
                                <div className="loading-message">Loading preview...</div>
                            )}

                            {!loading.autoPreview && autoHardenPreview && (
                                <>
                                    <div className="preview-summary">
                                        <h4>Automatic Hardening Summary</h4>
                                        <p>
                                            This will apply CIS-recommended default values to eligible checks.
                                        </p>

                                        <div className="summary-stats">
                                            <div className="stat-item success">
                                                <span className="stat-number">
                                                    {autoHardenPreview.auto_fixable_count}
                                                </span>
                                                <span className="stat-label">Checks to Fix</span>
                                            </div>
                                            <div className="stat-item skipped">
                                                <span className="stat-number">
                                                    {autoHardenPreview.skipped_count}
                                                </span>
                                                <span className="stat-label">Will Be Skipped</span>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Checks with defaults */}
                                    {autoHardenPreview.checks_with_defaults?.length > 0 && (
                                        <div className="defaults-section">
                                            <h5>Default Values to Apply</h5>
                                            <table className="defaults-table">
                                                <thead>
                                                    <tr>
                                                        <th>Check</th>
                                                        <th>Parameter</th>
                                                        <th>Default Value</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    {autoHardenPreview.checks_with_defaults.map(check => (
                                                        Object.keys(check.defaults || {}).length > 0 ? (
                                                            Object.entries(check.defaults).map(([param, value], idx) => (
                                                                <tr key={`${check.check_number}-${param}`}>
                                                                    {idx === 0 && (
                                                                        <td rowSpan={Object.keys(check.defaults).length}>
                                                                            <code>{check.check_number}</code>
                                                                            <div className="check-title-small">
                                                                                {check.check_title}
                                                                            </div>
                                                                        </td>
                                                                    )}
                                                                    <td>{param}</td>
                                                                    <td><code>{value}</code></td>
                                                                </tr>
                                                            ))
                                                        ) : (
                                                            <tr key={check.check_number}>
                                                                <td>
                                                                    <code>{check.check_number}</code>
                                                                    <div className="check-title-small">
                                                                        {check.check_title}
                                                                    </div>
                                                                </td>
                                                                <td colSpan="2">
                                                                    <em>No parameters required</em>
                                                                </td>
                                                            </tr>
                                                        )
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    )}

                                    {/* Skipped checks */}
                                    {autoHardenPreview.skipped_checks?.length > 0 && (
                                        <div className="skipped-section">
                                            <h5>Checks That Will Be Skipped</h5>
                                            <p className="section-description">
                                                These checks require user input and cannot be auto-fixed.
                                            </p>
                                            <ul className="skipped-list">
                                                {autoHardenPreview.skipped_checks.map(check => (
                                                    <li key={check.check_number}>
                                                        <code>{check.check_number}</code>
                                                        <span>{check.check_title}</span>
                                                        <span className="reason">{check.reason}</span>
                                                    </li>
                                                ))}
                                            </ul>
                                        </div>
                                    )}

                                    {/* Confirmation */}
                                    <div className="confirmation-section">
                                        <label className="checkbox-label">
                                            <input
                                                type="checkbox"
                                                checked={confirmed}
                                                onChange={(e) => setConfirmed(e.target.checked)}
                                            />
                                            <span>
                                                I have reviewed the default values and confirm they are acceptable
                                                for my environment.
                                            </span>
                                        </label>
                                    </div>

                                    <div className="step-actions">
                                        <button
                                            className="btn btn-secondary"
                                            onClick={handleClose}
                                        >
                                            Cancel
                                        </button>
                                        <button
                                            className="btn btn-primary"
                                            onClick={handlePreviewConfirm}
                                            disabled={!confirmed || autoHardenPreview.auto_fixable_count === 0}
                                        >
                                            Continue
                                        </button>
                                    </div>
                                </>
                            )}

                            {!loading.autoPreview && autoHardenPreview?.auto_fixable_count === 0 && (
                                <div className="no-fixable-message">
                                    <p>No checks can be automatically fixed. All failed checks require user input.</p>
                                    <p>Please use "Fix Selected" mode to provide the required parameters.</p>
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
                    )}

                    {/* Step: SSH Credentials */}
                    {step === 'credentials' && (
                        <div className="step-credentials">
                            <SSHCredentialsForm
                                onSubmit={handleCredentialsSubmit}
                                onCancel={() => setStep('preview')}
                                loading={false}
                                deviceType={deviceType}
                                vdom={vdom}
                                onVdomChange={setVdom}
                            />
                        </div>
                    )}

                    {/* Step: Executing */}
                    {step === 'executing' && (
                        <div className="step-executing">
                            <div className="executing-animation">
                                <div className="spinner"></div>
                                <p>Executing automatic hardening...</p>
                                <p className="small">
                                    Applying {autoHardenPreview?.auto_fixable_count} fixes with CIS defaults.
                                </p>
                            </div>
                        </div>
                    )}

                    {/* Step: Result */}
                    {step === 'result' && batchResult && (
                        <div className="step-result">
                            <div className="result-summary">
                                <h4>Automatic Hardening Complete</h4>

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

                            {batchResult.fixed_checks && batchResult.fixed_checks.length > 0 && (
                                <div className="fixed-list">
                                    <h5>Successfully Fixed</h5>
                                    <ul>
                                        {batchResult.fixed_checks.map(check => (
                                            <li key={check.check_number}>
                                                <code>{check.check_number}</code>
                                                <span>{check.check_title}</span>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            )}

                            {batchResult.skipped_checks && batchResult.skipped_checks.length > 0 && (
                                <div className="skipped-list-result">
                                    <h5>Skipped (Require User Input)</h5>
                                    <ul>
                                        {batchResult.skipped_checks.map(check => (
                                            <li key={check.check_number}>
                                                <code>{check.check_number}</code>
                                                <span>{check.reason}</span>
                                            </li>
                                        ))}
                                    </ul>
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

export default AutoHardenModal;
