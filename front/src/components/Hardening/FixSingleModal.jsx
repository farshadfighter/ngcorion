import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    previewHardenCheck,
    executeHardenCheck,
    discoverFortinetVdoms,
    clearPreviewData,
    clearMessages
} from '../../store/hardeningSlice';
import CredentialsForm from './CredentialsForm';
import BackupOption from './BackupOption';
import {
    isCisco,
    isFortinet,
    defaultCredentialsState,
    validateCredentials,
    buildCredentials,
} from './hardeningCredentials';
import '../../assets/hardening/Hardenallmodal.css';

// Cisco and Fortinet return action_id in preview and require it on execute.
const isCiscoOrFortinet = (dt) => isCisco(dt) || isFortinet(dt);

const FixSingleModal = ({ check, assetId, sessionId, deviceType, onClose, onSuccess }) => {
    const dispatch = useDispatch();
    const {
        previewData,
        isLoading,
        isExecuting,
        error,
        vdomDiscovery
    } = useSelector((state) => state.hardening);

    const [step, setStep] = useState(1); // 1: Preview, 2: Parameters, 3: Credentials, 4: Executing, 5: Results
    const [paramValues, setParamValues] = useState({});
    const [sshCredentials, setSshCredentials] = useState(defaultCredentialsState);
    const [credErrors, setCredErrors] = useState({});
    const [vdomEnabled, setVdomEnabled] = useState(false);
    const [createBackup, setCreateBackup] = useState(false);
    const [formError, setFormError] = useState(null);
    const [executionResult, setExecutionResult] = useState(null);

    // Cisco/Fortinet can only execute when the preview produced an action_id.
    const missingAction = isCiscoOrFortinet(deviceType) && !previewData?.action_id;

    // Fetch preview on mount for all device types
    useEffect(() => {
        if (check?.id && deviceType) {
            dispatch(previewHardenCheck({
                auditResultId: check.id,            // AuditResult row ID (Cisco/Fortinet)
                checkId:       check.check_number,  // CIS check string (Linux/Apache/etc.)
                deviceType:    deviceType,
                parameters:    {}
            }));
        }
        return () => {
            dispatch(clearPreviewData());
            dispatch(clearMessages());
        };
    }, [dispatch, check, deviceType]);

    // Initialize param values when preview loads — required (empty) + optional (pre-filled with defaults)
    useEffect(() => {
        if (!previewData) return;
        const initialValues = {};
        previewData.required_parameters?.forEach(p => { initialValues[p] = ''; });
        previewData.optional_parameters?.forEach(p => {
            initialValues[p] = previewData.parameter_defaults?.[p] ?? '';
        });
        // eslint-disable-next-line react-hooks/set-state-in-effect
        setParamValues(initialValues);
    }, [previewData]);

    const handleParamChange = (key, value) => {
        setParamValues(prev => ({ ...prev, [key]: value }));
    };

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

    const handleNextFromPreview = () => {
        const hasParams = (previewData?.required_parameters?.length ?? 0) > 0
                       || (previewData?.optional_parameters?.length ?? 0) > 0;
        if (hasParams) {
            setStep(2);
        } else {
            setStep(3);
        }
    };

    const validateParameters = () => {
        if (!previewData?.required_parameters) return true;
        const errors = [];
        previewData.required_parameters.forEach(param => {
            if (!paramValues[param]?.trim()) errors.push(param);
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
        if (validateParameters()) setStep(3);
    };

    const handleExecute = async () => {
        if (!validateForm()) return;

        // Guard: Cisco/Fortinet need an action_id from the preview step.
        if (missingAction) {
            setFormError('Could not load the hardening action for this check. Go back and retry the preview before executing.');
            return;
        }

        setFormError(null);
        setStep(4);

        try {
            const credentials = buildCredentials(deviceType, sshCredentials, { vdomEnabled });

            const result = await dispatch(executeHardenCheck({
                actionId:   isCiscoOrFortinet(deviceType) ? previewData?.action_id : null,
                checkId:    check.check_number,
                assetId:    assetId,
                sessionId:  sessionId,
                deviceType: deviceType,
                credentials,
                parameters: paramValues,
                skipBackup: !createBackup,
            })).unwrap();

            setExecutionResult(result);
            setStep(5);
        } catch (error) {
            console.error('Error executing hardening:', error);
            setStep(3);
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

    const renderPreview = () => {
        if (isLoading) {
            return (
                <div className="hardening-modal-loading">
                    <div className="hardening-spinner"></div>
                    <p>Loading preview...</p>
                </div>
            );
        }
        if (!previewData) {
            return <div className="hardening-modal-error"><p>Failed to load hardening preview.</p></div>;
        }
        return (
            <div className="hardening-preview-section">
                <h3 style={{ fontSize: '18px', color: '#1e3a5f', margin: '0 0 20px 0', fontWeight: '700', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    📋 Hardening Preview
                </h3>
                {previewData.commands && previewData.commands.length > 0 && (
                    <div className="hardening-commands-preview">
                        <h4 style={{ fontSize: '15px', color: '#1e3a5f', margin: '0 0 12px 0', fontWeight: '700' }}>Commands to Execute:</h4>
                        <div style={{ background: 'linear-gradient(135deg, #f8f9fb 0%, #ffffff 100%)', borderRadius: '10px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '10px', border: '1px solid #e8edf5' }}>
                            {previewData.commands.map((cmd, index) => (
                                <div key={index} style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', padding: '14px', background: 'white', borderRadius: '8px', borderLeft: '4px solid #1e3a5f', boxShadow: '0 2px 6px rgba(30,58,95,0.06)' }}>
                                    <div style={{ background: 'linear-gradient(135deg, #1e3a5f 0%, #2d4a7c 100%)', color: 'white', minWidth: '26px', height: '26px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: '700', flexShrink: '0' }}>{index + 1}</div>
                                    <code style={{ fontFamily: "'Consolas','Monaco','Courier New',monospace", fontSize: '13px', color: '#1f2937', lineHeight: '1.6', wordBreak: 'break-word', background: '#f8f9fb', padding: '2px 6px', borderRadius: '4px' }}>{cmd}</code>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
                {previewData.warnings && previewData.warnings.length > 0 && (
                    <div className="hardening-warnings-box">
                        <h4>⚠️ Warnings:</h4>
                        <ul>{previewData.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
                    </div>
                )}
                {((previewData.required_parameters?.length ?? 0) > 0 || (previewData.optional_parameters?.length ?? 0) > 0) && (
                    <div className="hardening-info-box">
                        <p><strong>ℹ️ Parameters will be configured in the next step</strong></p>
                        {previewData.required_parameters?.length > 0 && (
                            <><strong>Required:</strong> <ul>{previewData.required_parameters.map((p, i) => <li key={i}>{p}</li>)}</ul></>
                        )}
                        {previewData.optional_parameters?.length > 0 && (
                            <><strong>Optional (with defaults):</strong> <ul>{previewData.optional_parameters.map((p, i) => <li key={i}>{p} = {previewData.parameter_defaults?.[p]}</li>)}</ul></>
                        )}
                    </div>
                )}
            </div>
        );
    };

    const renderParametersForm = () => {
        const hasRequired = previewData?.required_parameters?.length > 0;
        const hasOptional = previewData?.optional_parameters?.length > 0;
        if (!hasRequired && !hasOptional) return null;
        return (
            <div className="hardening-params-form">
                {previewData.required_parameters?.map((param) => (
                    <div key={param} className="hardening-form-group">
                        <label>{param}<span className="hardening-required">*</span></label>
                        <input type="text" value={paramValues[param] ?? ''} onChange={(e) => handleParamChange(param, e.target.value)} placeholder={`Enter ${param}`} style={inputStyle} />
                    </div>
                ))}
                {previewData.optional_parameters?.map((param) => (
                    <div key={param} className="hardening-form-group">
                        <label>
                            {param}
                            <span style={{ color: "#6b7280", fontWeight: 400, marginLeft: "6px" }}>(optional)</span>
                        </label>
                        <input
                            type="text"
                            value={paramValues[param] ?? ''}
                            onChange={(e) => handleParamChange(param, e.target.value)}
                            placeholder={`default: ${previewData.parameter_defaults?.[param] ?? ''}`}
                            style={inputStyle}
                        />
                    </div>
                ))}
            </div>
        );
    };

    const renderCredentialsForm = () => (
        <>
            {missingAction && (
                <div className="hardening-error-message" style={{ marginBottom: '16px' }}>
                    <span>⚠</span>
                    <p>Could not load the hardening action for this check. Go back and retry the preview before executing.</p>
                </div>
            )}
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
            {isCiscoOrFortinet(deviceType) && (
                <BackupOption checked={createBackup} onChange={setCreateBackup} />
            )}
        </>
    );

    const renderExecuting = () => (
        <div className="hardening-modal-executing">
            <div className="hardening-spinner-large"></div>
            <h3>Executing Hardening...</h3>
            <p>Please wait while we apply this security fix.</p>
        </div>
    );

    const renderResults = () => {
        if (!executionResult) return <div className="hardening-modal-error"><p>No results available.</p></div>;

        // Cisco/Fortinet return { status: "success", verification_passed, verification_evidence, message }
        // Linux/MongoDB/MSSQL/Apache return { success: true, verification_result, check_title, error_message }
        const isSuccess = executionResult.success === true || executionResult.status === 'success';
        const isWarning = executionResult.status === 'warning';
        const displayMessage = executionResult.message || executionResult.check_title || 'Hardening operation completed.';
        const verificationText = executionResult.verification_evidence || executionResult.verification_result;

        return (
            <div className="hardening-single-result" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                <div style={{ padding: '24px', borderRadius: '12px', borderLeft: isSuccess ? '5px solid #1e3a5f' : isWarning ? '5px solid #f59e0b' : '5px solid #ef4444', boxShadow: '0 4px 12px rgba(0,0,0,0.08)', background: isSuccess ? 'linear-gradient(135deg,#e8edf5 0%,#f0f4f9 100%)' : isWarning ? 'linear-gradient(135deg,#fef3c7 0%,#fef9e7 100%)' : 'linear-gradient(135deg,#fee2e2 0%,#fef2f2 100%)' }}>
                    <h3 style={{ fontSize: '20px', margin: '0 0 12px 0', fontWeight: '700', display: 'flex', alignItems: 'center', gap: '10px', color: isSuccess ? '#1e3a5f' : isWarning ? '#92400e' : '#c0392b' }}>
                        {isSuccess && <span style={{ background: '#1e3a5f', color: 'white', width: '32px', height: '32px', borderRadius: '50%', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: '18px', fontWeight: 'bold' }}>✓</span>}
                        {isSuccess ? 'Hardening Successful' : isWarning ? '⚠ Completed with Warnings' : '✗ Hardening Failed'}
                    </h3>
                    <p style={{ margin: 0, color: '#6b7280', fontSize: '14px', lineHeight: '1.6' }}>{displayMessage}</p>
                </div>

                {(executionResult.verification_passed !== undefined || verificationText) && (
                    <div style={{ background: 'linear-gradient(135deg,#fafbfc 0%,#ffffff 100%)', padding: '18px', borderRadius: '10px', border: '2px solid #e8edf5' }}>
                        <h4 style={{ fontSize: '15px', color: '#1e3a5f', margin: '0 0 12px 0', fontWeight: '700' }}>🔍 Verification</h4>
                        {executionResult.verification_passed !== undefined && (
                            <p style={{ margin: '0 0 10px 0', fontSize: '14px', fontWeight: '600', color: executionResult.verification_passed ? '#1e3a5f' : '#ef4444' }}>
                                {executionResult.verification_passed ? '✓ Verified' : '✗ Not Verified'}
                            </p>
                        )}
                        {verificationText && (
                            <pre style={{ background: '#f8f9fb', padding: '12px', borderRadius: '6px', border: '1px solid #e8edf5', fontSize: '12px', overflowX: 'auto', margin: '10px 0 0 0', color: '#1f2937', fontFamily: "'Consolas','Monaco','Courier New',monospace" }}>{verificationText}</pre>
                        )}
                    </div>
                )}

                {executionResult.commands_executed && executionResult.commands_executed.length > 0 && (
                    <div style={{ background: 'linear-gradient(135deg,#fafbfc 0%,#ffffff 100%)', padding: '18px', borderRadius: '10px', border: '2px solid #e8edf5' }}>
                        <h4 style={{ fontSize: '15px', color: '#1e3a5f', margin: '0 0 12px 0', fontWeight: '700' }}>⚙️ Commands Executed</h4>
                        <div style={{ background: 'linear-gradient(135deg,#f8f9fb 0%,#ffffff 100%)', borderRadius: '10px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '10px', border: '1px solid #e8edf5' }}>
                            {executionResult.commands_executed.map((cmd, index) => (
                                <div key={index} style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', padding: '14px', background: 'white', borderRadius: '8px', borderLeft: '4px solid #1e3a5f', boxShadow: '0 2px 6px rgba(30,58,95,0.06)' }}>
                                    <div style={{ background: 'linear-gradient(135deg,#1e3a5f 0%,#2d4a7c 100%)', color: 'white', minWidth: '26px', height: '26px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: '700', flexShrink: '0' }}>{index + 1}</div>
                                    <code style={{ fontFamily: "'Consolas','Monaco','Courier New',monospace", fontSize: '13px', color: '#1f2937', lineHeight: '1.6', wordBreak: 'break-word', background: '#f8f9fb', padding: '2px 6px', borderRadius: '4px' }}>{cmd}</code>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {executionResult.backup_created && (
                    <div style={{ background: 'linear-gradient(135deg,#e8edf5 0%,#f0f4f9 100%)', borderLeft: '5px solid #1e3a5f', padding: '16px 20px', borderRadius: '10px' }}>
                        <p style={{ margin: 0, color: '#2d4a7c', fontSize: '14px', fontWeight: '600' }}>💾 Configuration backup created successfully</p>
                    </div>
                )}

                {executionResult.error_message && (
                    <div className="hardening-error-message">
                        <span>⚠</span>
                        <p>{executionResult.error_message}</p>
                    </div>
                )}
            </div>
        );
    };

    return (
        <div className="hardening-modal-overlay" onClick={onClose}>
            <div className="hardening-modal-content hardening-modal-large" onClick={(e) => e.stopPropagation()}>
                <div className="hardening-modal-header">
                    <div className="hardening-modal-title">
                        <span className="hardening-modal-icon"><img src="/icons/audit.svg" alt="" className="btn-icon" /></span>
                        <h2>Harden Single Check</h2>
                    </div>
                    <button className="hardening-modal-close" onClick={onClose}>×</button>
                </div>

                {step <= 3 && (
                    <div className="hardening-modal-info">
                        <span className="hardening-info-icon">ℹ️</span>
                        <p>
                            {step === 1 && 'Review the commands that will be executed for this hardening fix.'}
                            {step === 2 && 'Configure required parameters for this hardening operation.'}
                            {step === 3 && 'Enter credentials to execute the hardening fix.'}
                        </p>
                    </div>
                )}

                <div className="hardening-modal-body">
                    {step === 1 && renderPreview()}
                    {step === 2 && renderParametersForm()}
                    {step === 3 && renderCredentialsForm()}
                    {step === 4 && renderExecuting()}
                    {step === 5 && renderResults()}
                </div>

                <div className="hardening-modal-footer">
                    {step === 1 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={onClose}>Cancel</button>
                            <button className="hardening-btn-primary" onClick={handleNextFromPreview} disabled={isLoading}>Next</button>
                        </>
                    )}
                    {step === 2 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={() => setStep(1)}>Back</button>
                            <button className="hardening-btn-primary" onClick={handleNextFromParams}>Next</button>
                        </>
                    )}
                    {step === 3 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={() => setStep(((previewData?.required_parameters?.length ?? 0) > 0 || (previewData?.optional_parameters?.length ?? 0) > 0) ? 2 : 1)}>Back</button>
                            <button className="hardening-btn-primary" onClick={handleExecute} disabled={isExecuting || missingAction}>Execute Hardening</button>
                        </>
                    )}
                    {step === 5 && (
                        <button className="hardening-btn-primary" onClick={handleFinish}>Finish</button>
                    )}
                </div>

                {(error || formError) && step !== 5 && (
                    <div className="hardening-error-message" style={{ margin: '16px 24px' }}>
                        <span>⚠</span>
                        <p>{formError || (typeof error === 'string' ? error : (error?.message || 'Operation failed'))}</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default FixSingleModal;
