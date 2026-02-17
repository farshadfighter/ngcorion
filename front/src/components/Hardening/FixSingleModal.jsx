import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    previewHardenCheck,
    executeHardenCheck,
    clearPreviewData,
    clearMessages
} from '../../store/hardeningSlice';
import '../../assets/hardening/Hardenallmodal.css';

const FixSingleModal = ({ check, deviceType, onClose, onSuccess }) => {
    const dispatch = useDispatch();
    const {
        previewData,
        isLoading,
        isExecuting,
        error
    } = useSelector((state) => state.hardening);

    const [step, setStep] = useState(1); // 1: Preview, 2: Parameters, 3: SSH, 4: Executing, 5: Results
    const [paramValues, setParamValues] = useState({});
    const [sshCredentials, setSshCredentials] = useState({
        ssh_username: '',
        ssh_password: '',
        ssh_secret: '',      // Cisco only
        vdom: '',            // Fortinet only
        sudo_password: ''    // Linux/Apache only
    });
    const [executionResult, setExecutionResult] = useState(null);

    // Fetch preview on mount
    useEffect(() => {
        if (check?.id && deviceType) {
            dispatch(previewHardenCheck({
                auditResultId: check.id,
                deviceType: deviceType,
                parameters: {}
            }));
        }

        return () => {
            dispatch(clearPreviewData());
            dispatch(clearMessages());
        };
    }, [dispatch, check, deviceType]);

    // Initialize param values when preview loads (only once)
    useEffect(() => {
        if (previewData?.required_parameters && Object.keys(paramValues).length === 0) {
            const initialValues = {};
            previewData.required_parameters.forEach(param => {
                initialValues[param] = '';
            });
            setParamValues(initialValues);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [previewData?.required_parameters]);

    const handleParamChange = (key, value) => {
        setParamValues(prev => ({
            ...prev,
            [key]: value
        }));
    };

    const handleSSHChange = (e) => {
        const { name, value } = e.target;
        setSshCredentials(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleNextFromPreview = () => {
        if (previewData?.required_parameters && previewData.required_parameters.length > 0) {
            setStep(2); // Go to parameters
        } else {
            setStep(3); // Skip to SSH
        }
    };

    const validateParameters = () => {
        if (!previewData?.required_parameters) return true;

        const errors = [];
        previewData.required_parameters.forEach(param => {
            if (!paramValues[param]?.trim()) {
                errors.push(param);
            }
        });

        if (errors.length > 0) {
            alert(`Please fill in required fields:\n${errors.join('\n')}`);
            return false;
        }
        return true;
    };

    const validateSSH = () => {
        if (!sshCredentials.ssh_username.trim()) {
            alert('SSH Username is required');
            return false;
        }
        if (!sshCredentials.ssh_password.trim()) {
            alert('SSH Password is required');
            return false;
        }
        return true;
    };

    const handleNextFromParams = () => {
        if (validateParameters()) {
            setStep(3);
        }
    };

    const handleExecute = async () => {
        if (!validateSSH()) return;

        setStep(4); // Show executing spinner

        try {
            // Prepare credentials based on device type
            const credentials = {
                ssh_username: sshCredentials.ssh_username,
                ssh_password: sshCredentials.ssh_password,
            };

            // Add device-specific credentials
            if (deviceType === 'cisco' && sshCredentials.ssh_secret) {
                credentials.ssh_secret = sshCredentials.ssh_secret;
            }
            if (deviceType === 'fortinet' && sshCredentials.vdom) {
                credentials.vdom = sshCredentials.vdom;
            }
            if ((deviceType?.startsWith('linux-') || deviceType === 'apache') && sshCredentials.sudo_password) {
                credentials.sudo_password = sshCredentials.sudo_password;
            }

            const result = await dispatch(executeHardenCheck({
                actionId: previewData.action_id,
                deviceType: deviceType,
                credentials: credentials,
                parameters: paramValues
            })).unwrap();

            setExecutionResult(result);
            setStep(5);
        } catch (error) {
            console.error("Error executing hardening:", error);
            setStep(3); // Go back to SSH form on error
        }
    };

    const handleFinish = () => {
        if (onSuccess) {
            onSuccess();
        }
        onClose();
    };

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
            return (
                <div className="hardening-modal-error">
                    <p>Failed to load hardening preview.</p>
                </div>
            );
        }

        return (
            <div className="hardening-preview-section">
                <h3 style={{
                    fontSize: '18px',
                    color: '#1e3a5f',
                    margin: '0 0 20px 0',
                    fontWeight: '700',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px'
                }}>
                    📋 Hardening Preview
                </h3>

                {/* Commands to be executed */}
                {previewData.commands && previewData.commands.length > 0 && (
                    <div className="hardening-commands-preview">
                        <h4 style={{
                            fontSize: '15px',
                            color: '#1e3a5f',
                            margin: '0 0 12px 0',
                            fontWeight: '700'
                        }}>
                            Commands to Execute:
                        </h4>
                        <div style={{
                            background: 'linear-gradient(135deg, #f8f9fb 0%, #ffffff 100%)',
                            borderRadius: '10px',
                            padding: '16px',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '10px',
                            border: '1px solid #e8edf5'
                        }}>
                            {previewData.commands.map((cmd, index) => (
                                <div key={index} style={{
                                    display: 'flex',
                                    alignItems: 'flex-start',
                                    gap: '12px',
                                    padding: '14px',
                                    background: 'white',
                                    borderRadius: '8px',
                                    borderLeft: '4px solid #1e3a5f',
                                    boxShadow: '0 2px 6px rgba(30, 58, 95, 0.06)',
                                    transition: 'all 0.2s'
                                }}>
                                    <div style={{
                                        background: 'linear-gradient(135deg, #1e3a5f 0%, #2d4a7c 100%)',
                                        color: 'white',
                                        minWidth: '26px',
                                        height: '26px',
                                        borderRadius: '50%',
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        fontSize: '12px',
                                        fontWeight: '700',
                                        flexShrink: '0',
                                        boxShadow: '0 2px 4px rgba(30, 58, 95, 0.3)'
                                    }}>
                                        {index + 1}
                                    </div>
                                    <code style={{
                                        fontFamily: "'Consolas', 'Monaco', 'Courier New', monospace",
                                        fontSize: '13px',
                                        color: '#1f2937',
                                        lineHeight: '1.6',
                                        wordBreak: 'break-word',
                                        background: '#f8f9fb',
                                        padding: '2px 6px',
                                        borderRadius: '4px'
                                    }}>
                                        {cmd}
                                    </code>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Warnings */}
                {previewData.warnings && previewData.warnings.length > 0 && (
                    <div className="hardening-warnings-box">
                        <h4>⚠️ Warnings:</h4>
                        <ul>
                            {previewData.warnings.map((warning, index) => (
                                <li key={index}>{warning}</li>
                            ))}
                        </ul>
                    </div>
                )}

                {/* Info about parameters */}
                {previewData.required_parameters && previewData.required_parameters.length > 0 && (
                    <div className="hardening-info-box">
                        <p><strong>ℹ️ Additional Configuration Required</strong></p>
                        <ul>
                            {previewData.required_parameters.map((param, index) => (
                                <li key={index}>{param}</li>
                            ))}
                        </ul>
                    </div>
                )}
            </div>
        );
    };

    const renderParametersForm = () => {
        if (!previewData?.required_parameters || previewData.required_parameters.length === 0) {
            return null;
        }

        return (
            <div className="hardening-params-form">
                {previewData.required_parameters.map((param) => (
                    <div key={param} className="hardening-form-group">
                        <label>
                            {param}
                            <span className="hardening-required">*</span>
                        </label>
                        <input
                            type="text"
                            value={paramValues[param] || ''}
                            onChange={(e) => handleParamChange(param, e.target.value)}
                            placeholder={`Enter ${param}`}
                            style={{
                                width: '450px',
                                padding: '8px 12px',
                                border: '1px solid #d1d5db',
                                borderRadius: '6px',
                                fontSize: '13px',
                                color: '#111827',
                                transition: 'all 0.2s',
                                background: 'white'
                            }}
                        />
                    </div>
                ))}
            </div>
        );
    };

    const renderSSHForm = () => {
        return (
            <div className="hardening-ssh-form">
                {/* Common Fields */}
                <div className="hardening-form-group">
                    <label>
                        SSH Username
                        <span className="hardening-required">*</span>
                    </label>
                    <input
                        type="text"
                        name="ssh_username"
                        value={sshCredentials.ssh_username}
                        onChange={handleSSHChange}
                        placeholder="Enter SSH username"
                        autoComplete="username"
                        style={{
                            width: '450px',
                            padding: '8px 12px',
                            border: '1px solid #d1d5db',
                            borderRadius: '6px',
                            fontSize: '13px',
                            color: '#111827',
                            transition: 'all 0.2s',
                            background: 'white'
                        }}
                    />
                </div>

                <div className="hardening-form-group">
                    <label>
                        SSH Password
                        <span className="hardening-required">*</span>
                    </label>
                    <input
                        type="password"
                        name="ssh_password"
                        value={sshCredentials.ssh_password}
                        onChange={handleSSHChange}
                        placeholder="Enter SSH password"
                        autoComplete="current-password"
                        style={{
                            width: '450px',
                            padding: '8px 12px',
                            border: '1px solid #d1d5db',
                            borderRadius: '6px',
                            fontSize: '13px',
                            color: '#111827',
                            transition: 'all 0.2s',
                            background: 'white'
                        }}
                    />
                </div>

                {/* Device-Specific Fields */}

                {/* CISCO: Enable Password */}
                {deviceType === 'cisco' && (
                    <div className="hardening-form-group">
                        <label>Enable Password</label>
                        <input
                            type="password"
                            name="ssh_secret"
                            value={sshCredentials.ssh_secret}
                            onChange={handleSSHChange}
                            placeholder="Enter enable secret (optional)"
                            autoComplete="off"
                            style={{
                                width: '450px',
                                padding: '8px 12px',
                                border: '1px solid #d1d5db',
                                borderRadius: '6px',
                                fontSize: '13px',
                                color: '#111827',
                                transition: 'all 0.2s',
                                background: 'white'
                            }}
                        />
                        <span style={{fontSize: '12px', color: '#7f8c8d', display: 'block', marginTop: '4px'}}>
                            Required for privileged commands
                        </span>
                    </div>
                )}

                {/* FORTINET: VDOM */}
                {deviceType === 'fortinet' && (
                    <div className="hardening-form-group">
                        <label>VDOM</label>
                        <input
                            type="text"
                            name="vdom"
                            value={sshCredentials.vdom}
                            onChange={handleSSHChange}
                            placeholder="Virtual Domain (optional, default: root)"
                            autoComplete="off"
                            style={{
                                width: '450px',
                                padding: '8px 12px',
                                border: '1px solid #d1d5db',
                                borderRadius: '6px',
                                fontSize: '13px',
                                color: '#111827',
                                transition: 'all 0.2s',
                                background: 'white'
                            }}
                        />
                        <span style={{fontSize: '12px', color: '#7f8c8d', display: 'block', marginTop: '4px'}}>
                            Leave empty for default VDOM
                        </span>
                    </div>
                )}

                {/* LINUX (ALL VARIANTS): Sudo Password */}
                {deviceType?.startsWith('linux-') && (
                    <div className="hardening-form-group">
                        <label>Sudo Password</label>
                        <input
                            type="password"
                            name="sudo_password"
                            value={sshCredentials.sudo_password}
                            onChange={handleSSHChange}
                            placeholder="Sudo password (optional)"
                            autoComplete="off"
                            style={{
                                width: '450px',
                                padding: '8px 12px',
                                border: '1px solid #d1d5db',
                                borderRadius: '6px',
                                fontSize: '13px',
                                color: '#111827',
                                transition: 'all 0.2s',
                                background: 'white'
                            }}
                        />
                        <span style={{fontSize: '12px', color: '#7f8c8d', display: 'block', marginTop: '4px'}}>
                            Required for root access (defaults to SSH password)
                        </span>
                    </div>
                )}

                {/* APACHE: Sudo Password */}
                {deviceType === 'apache' && (
                    <div className="hardening-form-group">
                        <label>Sudo Password</label>
                        <input
                            type="password"
                            name="sudo_password"
                            value={sshCredentials.sudo_password}
                            onChange={handleSSHChange}
                            placeholder="Sudo password (optional)"
                            autoComplete="off"
                            style={{
                                width: '450px',
                                padding: '8px 12px',
                                border: '1px solid #d1d5db',
                                borderRadius: '6px',
                                fontSize: '13px',
                                color: '#111827',
                                transition: 'all 0.2s',
                                background: 'white'
                            }}
                        />
                        <span style={{fontSize: '12px', color: '#7f8c8d', display: 'block', marginTop: '4px'}}>
                            Required for root access (defaults to SSH password)
                        </span>
                    </div>
                )}
            </div>
        );
    };

    const renderExecuting = () => {
        return (
            <div className="hardening-modal-executing">
                <div className="hardening-spinner-large"></div>
                <h3>Executing Hardening...</h3>
                <p>Please wait while we apply this security fix.</p>
            </div>
        );
    };

    const renderResults = () => {
        if (!executionResult) {
            return (
                <div className="hardening-modal-error">
                    <p>No results available.</p>
                </div>
            );
        }

        const isSuccess = executionResult.status === 'success' || executionResult.verification_passed;
        const statusClass = isSuccess ? 'success' :
            executionResult.status === 'warning' ? 'warning' : 'error';

        return (
            <div className="hardening-single-result" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                <div style={{
                    padding: '24px',
                    borderRadius: '12px',
                    borderLeft: isSuccess ? '5px solid #1e3a5f' : statusClass === 'warning' ? '5px solid #f59e0b' : '5px solid #ef4444',
                    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.08)',
                    background: isSuccess ? 'linear-gradient(135deg, #e8edf5 0%, #f0f4f9 100%)' :
                        statusClass === 'warning' ? 'linear-gradient(135deg, #fef3c7 0%, #fef9e7 100%)' :
                            'linear-gradient(135deg, #fee2e2 0%, #fef2f2 100%)'
                }}>
                    <h3 style={{
                        fontSize: '20px',
                        margin: '0 0 12px 0',
                        fontWeight: '700',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px',
                        color: isSuccess ? '#1e3a5f' : statusClass === 'warning' ? '#92400e' : '#c0392b'
                    }}>
                        {isSuccess && <span style={{
                            background: '#1e3a5f',
                            color: 'white',
                            width: '32px',
                            height: '32px',
                            borderRadius: '50%',
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontSize: '18px',
                            fontWeight: 'bold'
                        }}>✓</span>}
                        {isSuccess ? 'Hardening Successful' :
                            executionResult.status === 'warning' ? '⚠ Completed with Warnings' :
                                '✗ Hardening Failed'}
                    </h3>
                    <p style={{
                        margin: 0,
                        color: '#6b7280',
                        fontSize: '14px',
                        lineHeight: '1.6'
                    }}>
                        {executionResult.message || 'Hardening operation completed.'}
                    </p>
                </div>

                {/* Verification */}
                {executionResult.verification_passed !== undefined && (
                    <div style={{
                        background: 'linear-gradient(135deg, #fafbfc 0%, #ffffff 100%)',
                        padding: '18px',
                        borderRadius: '10px',
                        border: '2px solid #e8edf5'
                    }}>
                        <h4 style={{
                            fontSize: '15px',
                            color: '#1e3a5f',
                            margin: '0 0 12px 0',
                            fontWeight: '700',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px'
                        }}>
                            🔍 Verification
                        </h4>
                        <p style={{
                            margin: '0 0 10px 0',
                            fontSize: '14px',
                            fontWeight: '600',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px',
                            color: executionResult.verification_passed ? '#1e3a5f' : '#ef4444'
                        }}>
                            {executionResult.verification_passed && <span style={{
                                background: '#1e3a5f',
                                color: 'white',
                                width: '20px',
                                height: '20px',
                                borderRadius: '50%',
                                display: 'inline-flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                fontSize: '12px'
                            }}>✓</span>}
                            {executionResult.verification_passed ? 'Verified' : '✗ Not Verified'}
                        </p>
                        {executionResult.verification_evidence && (
                            <pre style={{
                                background: '#f8f9fb',
                                padding: '12px',
                                borderRadius: '6px',
                                border: '1px solid #e8edf5',
                                fontSize: '12px',
                                overflowX: 'auto',
                                margin: '10px 0 0 0',
                                color: '#1f2937',
                                fontFamily: "'Consolas', 'Monaco', 'Courier New', monospace"
                            }}>
                                {executionResult.verification_evidence}
                            </pre>
                        )}
                    </div>
                )}

                {/* Commands Executed */}
                {executionResult.commands_executed && executionResult.commands_executed.length > 0 && (
                    <div style={{
                        background: 'linear-gradient(135deg, #fafbfc 0%, #ffffff 100%)',
                        padding: '18px',
                        borderRadius: '10px',
                        border: '2px solid #e8edf5'
                    }}>
                        <h4 style={{
                            fontSize: '15px',
                            color: '#1e3a5f',
                            margin: '0 0 12px 0',
                            fontWeight: '700',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px'
                        }}>
                            ⚙️ Commands Executed
                        </h4>
                        <div style={{
                            background: 'linear-gradient(135deg, #f8f9fb 0%, #ffffff 100%)',
                            borderRadius: '10px',
                            padding: '16px',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '10px',
                            border: '1px solid #e8edf5'
                        }}>
                            {executionResult.commands_executed.map((cmd, index) => (
                                <div key={index} style={{
                                    display: 'flex',
                                    alignItems: 'flex-start',
                                    gap: '12px',
                                    padding: '14px',
                                    background: 'white',
                                    borderRadius: '8px',
                                    borderLeft: '4px solid #1e3a5f',
                                    boxShadow: '0 2px 6px rgba(30, 58, 95, 0.06)'
                                }}>
                                    <div style={{
                                        background: 'linear-gradient(135deg, #1e3a5f 0%, #2d4a7c 100%)',
                                        color: 'white',
                                        minWidth: '26px',
                                        height: '26px',
                                        borderRadius: '50%',
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        fontSize: '12px',
                                        fontWeight: '700',
                                        flexShrink: '0',
                                        boxShadow: '0 2px 4px rgba(30, 58, 95, 0.3)'
                                    }}>
                                        {index + 1}
                                    </div>
                                    <code style={{
                                        fontFamily: "'Consolas', 'Monaco', 'Courier New', monospace",
                                        fontSize: '13px',
                                        color: '#1f2937',
                                        lineHeight: '1.6',
                                        wordBreak: 'break-word',
                                        background: '#f8f9fb',
                                        padding: '2px 6px',
                                        borderRadius: '4px'
                                    }}>
                                        {cmd}
                                    </code>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Backup Info */}
                {executionResult.backup_created && (
                    <div style={{
                        background: 'linear-gradient(135deg, #e8edf5 0%, #f0f4f9 100%)',
                        borderLeft: '5px solid #1e3a5f',
                        padding: '16px 20px',
                        borderRadius: '10px',
                        boxShadow: '0 2px 8px rgba(30, 58, 95, 0.1)'
                    }}>
                        <p style={{
                            margin: 0,
                            color: '#2d4a7c',
                            fontSize: '14px',
                            fontWeight: '600',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px'
                        }}>
                            💾 Configuration backup created successfully
                        </p>
                    </div>
                )}

                {/* Error Details */}
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
                {/* Header */}
                <div className="hardening-modal-header">
                    <div className="hardening-modal-title">
                        <span className="hardening-modal-icon">🛡️</span>
                        <h2>Harden Single Check</h2>
                    </div>
                    <button className="hardening-modal-close" onClick={onClose}>×</button>
                </div>

                {/* Info */}
                {step <= 3 && (
                    <div className="hardening-modal-info">
                        <span className="hardening-info-icon">ℹ️</span>
                        <p>
                            {step === 1 && "Review the commands that will be executed for this hardening fix."}
                            {step === 2 && "Configure required parameters for this hardening operation."}
                            {step === 3 && "Enter SSH credentials to execute the hardening fix."}
                        </p>
                    </div>
                )}

                {/* Body */}
                <div className="hardening-modal-body">
                    {step === 1 && renderPreview()}
                    {step === 2 && renderParametersForm()}
                    {step === 3 && renderSSHForm()}
                    {step === 4 && renderExecuting()}
                    {step === 5 && renderResults()}
                </div>

                {/* Footer */}
                <div className="hardening-modal-footer">
                    {step === 1 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={onClose}>
                                Cancel
                            </button>
                            <button
                                className="hardening-btn-primary"
                                onClick={handleNextFromPreview}
                                disabled={isLoading}
                            >
                                Next
                            </button>
                        </>
                    )}

                    {step === 2 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={() => setStep(1)}>
                                Back
                            </button>
                            <button
                                className="hardening-btn-primary"
                                onClick={handleNextFromParams}
                            >
                                Next
                            </button>
                        </>
                    )}

                    {step === 3 && (
                        <>
                            <button
                                className="hardening-btn-secondary"
                                onClick={() => setStep(previewData?.required_parameters?.length > 0 ? 2 : 1)}
                            >
                                Back
                            </button>
                            <button
                                className="hardening-btn-primary"
                                onClick={handleExecute}
                                disabled={isExecuting}
                            >
                                Execute Hardening
                            </button>
                        </>
                    )}

                    {step === 5 && (
                        <button className="hardening-btn-primary" onClick={handleFinish}>
                            Finish
                        </button>
                    )}
                </div>

                {/* Error Display */}
                {error && step !== 5 && (
                    <div className="hardening-error-message" style={{margin: '16px 24px'}}>
                        <span>⚠</span>
                        <p>{error}</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default FixSingleModal;