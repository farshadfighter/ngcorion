import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    fetchRequiredParameters,
    autoHardenWithDefaults,
    discoverFortinetVdoms,
    clearRequiredParameters,
    clearMessages
} from '../../store/hardeningSlice';
import CredentialsForm from './CredentialsForm';
import BackupOption from './BackupOption';
import {
    isWindows,
    isMssql,
    isCisco,
    isFortinet,
    defaultCredentialsState,
    validateCredentials,
    buildCredentials,
} from './hardeningCredentials';
import '../../assets/hardening/Hardenallmodal.css';

const HardenAllModal = ({ sessionId, assetId, deviceType, onClose, onSuccess }) => {
    const dispatch = useDispatch();
    const {
        requiredParameters,
        isFetchingParams,
        isExecuting,
        error,
        vdomDiscovery
    } = useSelector((state) => state.hardening);

    const [vdomEnabled, setVdomEnabled] = useState(false);
    const [createBackup, setCreateBackup] = useState(false);

    const [step, setStep] = useState(1); // 1: Parameters, 2: Credentials, 3: Executing, 4: Results
    const [paramValues, setParamValues] = useState({});
    const [sshCredentials, setSshCredentials] = useState(defaultCredentialsState);
    const [credErrors, setCredErrors] = useState({});
    const [executionResult, setExecutionResult] = useState(null);

    useEffect(() => {
        if (sessionId && deviceType) {
            dispatch(fetchRequiredParameters({ sessionId, deviceType }));
        }
        return () => {
            dispatch(clearRequiredParameters());
            dispatch(clearMessages());
        };
    }, [dispatch, sessionId, deviceType]);

    useEffect(() => {
        if (requiredParameters?.required_parameters) {
            const initialValues = {};
            Object.entries(requiredParameters.required_parameters).forEach(([key, param]) => {
                initialValues[key] = param.default || '';
            });
            // eslint-disable-next-line react-hooks/set-state-in-effect
            setParamValues(prev => {
                const hasChanged = JSON.stringify(prev) !== JSON.stringify(initialValues);
                return hasChanged ? initialValues : prev;
            });
        }
    }, [requiredParameters?.required_parameters]);

    const handleParamChange = (key, value) => setParamValues(prev => ({ ...prev, [key]: value }));

    const handleSSHChange = (e) => {
        const { name, value } = e.target;
        setSshCredentials(prev => ({ ...prev, [name]: value }));
        setCredErrors(prev => (prev[name] ? { ...prev, [name]: undefined } : prev));
    };

    const handleDetectVdoms = () => {
        if (!assetId || !sshCredentials.ssh_username || !sshCredentials.ssh_password) return;
        dispatch(discoverFortinetVdoms({
            mode:         'hardening',
            asset_id:     parseInt(assetId),
            ssh_username: sshCredentials.ssh_username,
            ssh_password: sshCredentials.ssh_password,
            ssh_port:     parseInt(sshCredentials.ssh_port) || 22,
        }));
    };

    const validateParameters = () => {
        if (!requiredParameters?.required_parameters) return true;
        const errors = [];
        Object.entries(requiredParameters.required_parameters).forEach(([key, param]) => {
            if (!param.optional && !paramValues[key]?.trim()) errors.push(param.description || key);
        });
        if (errors.length > 0) {
            alert(`Please fill in required fields:\n${errors.join('\n')}`);
            return false;
        }
        return true;
    };

    const validateForm = () => {
        const errs = validateCredentials(deviceType, sshCredentials);
        setCredErrors(errs);
        return Object.keys(errs).length === 0;
    };

    const handleNextFromParams = () => {
        if (validateParameters()) setStep(2);
    };

    const handleExecute = async () => {
        if (!validateForm()) return;
        setStep(3);

        try {
            const credentials = buildCredentials(deviceType, sshCredentials, { vdomEnabled });

            const result = await dispatch(autoHardenWithDefaults({
                sessionId,
                assetId,
                deviceType,
                credentials,
                skipBackup: !createBackup,
            })).unwrap();

            setExecutionResult(result);
            setStep(4);
        } catch (error) {
            console.error('Error executing hardening fixes:', error);
            setStep(2);
        }
    };

    const handleFinish = () => {
        if (onSuccess) onSuccess();
        onClose();
    };

    // ─── Input style helper ────────────────────────────────────────────────────
    const inputStyle = {
        width: '450px',
        padding: '8px 12px',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        fontSize: '13px',
        color: '#111827',
        transition: 'all 0.2s',
        background: 'white'
    };

    // ─── Renders ──────────────────────────────────────────────────────────────

    const renderParametersForm = () => {
        if (isFetchingParams) {
            return (
                <div className="hardening-modal-loading">
                    <div className="hardening-spinner"></div>
                    <p>Loading parameters...</p>
                </div>
            );
        }
        if (!requiredParameters?.required_parameters || Object.keys(requiredParameters.required_parameters).length === 0) {
            return (
                <div className="hardening-no-params">
                    <p>No additional parameters required.</p>
                    <p className="hardening-sub-text">Click Next to proceed with credentials.</p>
                </div>
            );
        }
        return (
            <div className="hardening-params-form">
                {Object.entries(requiredParameters.required_parameters).map(([key, param]) => (
                    <div key={key} className="hardening-form-group">
                        <label>
                            {param.description || key}
                            {!param.optional && <span className="hardening-required">*</span>}
                        </label>
                        <div className="hardening-input-with-meta">
                            <input type="text" value={paramValues[key] || ''} onChange={(e) => handleParamChange(key, e.target.value)} placeholder={param.default || `Enter ${key}`} style={inputStyle} />
                            {param.usage && <span className="hardening-param-usage">{param.usage}</span>}
                        </div>
                    </div>
                ))}
            </div>
        );
    };

    const renderCredentialsForm = () => (
        <CredentialsForm
            deviceType={deviceType}
            value={sshCredentials}
            onChange={handleSSHChange}
            errors={credErrors}
            vdomEnabled={vdomEnabled}
            onVdomEnabledChange={setVdomEnabled}
            vdomDiscovery={vdomDiscovery}
            onDetectVdoms={handleDetectVdoms}
            canDetectVdoms={!!assetId && !!sshCredentials.ssh_username && !!sshCredentials.ssh_password}
        />
    );

    const renderBackupOption = () => (
        (isCisco(deviceType) || isFortinet(deviceType)) && (
            <BackupOption checked={createBackup} onChange={setCreateBackup} />
        )
    );

    const renderExecuting = () => (
        <div className="hardening-modal-executing">
            <div className="hardening-spinner-large"></div>
            <h3>Executing Hardening...</h3>
            <p>Please wait while we apply the security hardening configurations.</p>
            <p>This may take a few minutes.</p>
        </div>
    );

    const renderResults = () => {
        if (!executionResult) return <div className="hardening-modal-error"><p>No results available.</p></div>;

        const successCount = executionResult.successful || 0;
        const failedCount  = executionResult.failed     || 0;
        const skippedList  = Array.isArray(executionResult.skipped) ? executionResult.skipped : [];
        const skippedCount = skippedList.length;
        const results      = executionResult.results || [];

        return (
            <div>
                <div className="hardening-results-summary">
                    <div className="hardening-result-item success">
                        <span className="hardening-result-icon">✓</span>
                        <div><strong>{successCount}</strong><span>Successful</span></div>
                    </div>
                    <div className="hardening-result-item failed">
                        <span className="hardening-result-icon">✗</span>
                        <div><strong>{failedCount}</strong><span>Failed</span></div>
                    </div>
                    <div className="hardening-result-item skipped">
                        <span className="hardening-result-icon">⊘</span>
                        <div><strong>{skippedCount}</strong><span>Skipped</span></div>
                    </div>
                </div>

                {/* Per-check results table */}
                {(results.length > 0 || skippedList.length > 0) && (
                    <div className="result-table-wrapper" style={{ marginTop: '24px', maxHeight: '340px', overflowY: 'auto' }}>
                        <table className="result-table">
                            <thead>
                                <tr>
                                    <th>Section</th>
                                    <th>Description</th>
                                    <th>Result</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {results.map((r) => (
                                    <tr key={r.check_id}>
                                        <td style={{ color: r.success ? '#1e3a5f' : '#ef4444', fontWeight: '600' }}>{r.check_id}</td>
                                        <td><div className="recommendation-text">{r.check_title || r.check_id}</div></td>
                                        <td>
                                            {r.success
                                                ? <span className="result-badge result-success">Fixed</span>
                                                : <span className="result-badge result-fail">Failed</span>}
                                        </td>
                                        <td style={{ fontSize: '12px', color: '#6b7280', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                            {r.error_message || r.verification_result || '—'}
                                        </td>
                                    </tr>
                                ))}
                                {skippedList.map((checkId) => (
                                    <tr key={checkId}>
                                        <td style={{ color: '#9ca3af', fontWeight: '600' }}>{checkId}</td>
                                        <td>—</td>
                                        <td><span className="result-badge result-unknown">Skipped</span></td>
                                        <td style={{ fontSize: '12px', color: '#9ca3af' }}>Not auto-fixable</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        );
    };

    // ─── Credential form label by device type ─────────────────────────────────
    const credentialStepLabel = isWindows(deviceType)
        ? 'Enter Windows credentials to execute hardening fixes.'
        : isMssql(deviceType)
            ? 'Enter SQL Server credentials to execute hardening fixes.'
            : 'Enter SSH credentials to execute hardening fixes.';

    return (
        <div className="hardening-modal-overlay" onClick={onClose}>
            <div className="hardening-modal-content hardening-modal-large" onClick={(e) => e.stopPropagation()}>
                <div className="hardening-modal-header">
                    <div className="hardening-modal-title">
                        <span className="hardening-modal-icon"><img src="/icons/audit.svg" alt="" className="btn-icon" /></span>
                        <h2>Harden All Failed Checks</h2>
                    </div>
                    <button className="hardening-modal-close" onClick={onClose}>×</button>
                </div>

                {step <= 2 && (
                    <div className="hardening-modal-info">
                        <span className="hardening-info-icon">ℹ️</span>
                        <p>
                            {step === 1
                                ? 'Review and configure parameters for hardening all failed checks.'
                                : credentialStepLabel}
                        </p>
                    </div>
                )}

                <div className="hardening-modal-body">
                    {step === 1 && renderParametersForm()}
                    {step === 2 && <>{renderCredentialsForm()}{renderBackupOption()}</>}
                    {step === 3 && renderExecuting()}
                    {step === 4 && renderResults()}
                </div>

                <div className="hardening-modal-footer">
                    {step === 1 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={onClose}>Cancel</button>
                            <button className="hardening-btn-primary" onClick={handleNextFromParams} disabled={isFetchingParams}>Next</button>
                        </>
                    )}
                    {step === 2 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={() => setStep(1)}>Back</button>
                            <button className="hardening-btn-primary" onClick={handleExecute} disabled={isExecuting}>Execute Hardening</button>
                        </>
                    )}
                    {step === 4 && (
                        <button className="hardening-btn-primary" onClick={handleFinish}>Finish</button>
                    )}
                </div>

                {error && step !== 4 && (
                    <div className="hardening-error-message" style={{ margin: '16px 24px' }}>
                        <span>⚠</span>
                        <p>{typeof error === 'string' ? error : (error?.message || 'Operation failed')}</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default HardenAllModal;
