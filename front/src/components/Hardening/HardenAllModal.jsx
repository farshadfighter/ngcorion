import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    fetchRequiredParameters,
    autoHardenWithDefaults,
    clearRequiredParameters,
    clearMessages
} from '../../store/hardeningSlice';
import '../../assets/hardening/Hardenallmodal.css';

const HardenAllModal = ({ sessionId, deviceType, onClose, onSuccess }) => {
    const dispatch = useDispatch();
    const {
        requiredParameters,
        isFetchingParams,
        isExecuting,
        error,
        cisChecks
    } = useSelector((state) => state.hardening);

    const [step, setStep] = useState(1); // 1: Parameters, 2: SSH Credentials, 3: Executing, 4: Results
    const [paramValues, setParamValues] = useState({});
    const [sshCredentials, setSshCredentials] = useState({
        ssh_username: '',
        ssh_password: '',
        ssh_secret: '',      // Cisco only
        vdom: '',            // Fortinet only
        sudo_password: ''    // Linux/Apache only
    });
    const [executionResult, setExecutionResult] = useState(null);

    // Fetch parameters on mount
    useEffect(() => {
        if (sessionId && deviceType) {
            dispatch(fetchRequiredParameters({
                sessionId,
                deviceType
            }));
        }

        return () => {
            dispatch(clearRequiredParameters());
            dispatch(clearMessages());
        };
    }, [dispatch, sessionId, deviceType]);

    // Initialize param values when data loads
    useEffect(() => {
        if (requiredParameters?.required_parameters) {
            const initialValues = {};
            Object.entries(requiredParameters.required_parameters).forEach(([key, param]) => {
                initialValues[key] = param.default || '';
            });
            setParamValues(prevValues => {
                const hasChanged = JSON.stringify(prevValues) !== JSON.stringify(initialValues);
                return hasChanged ? initialValues : prevValues;
            });
        }
    }, [requiredParameters]);

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

    const validateParameters = () => {
        if (!requiredParameters?.required_parameters) return true;

        const errors = [];
        Object.entries(requiredParameters.required_parameters).forEach(([key, param]) => {
            if (!param.optional && !paramValues[key]?.trim()) {
                errors.push(param.description || key);
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
            setStep(2);
        }
    };

    const handleExecute = async () => {
        if (!validateSSH()) return;

        setStep(3); // Show executing spinner

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

            const result = await dispatch(autoHardenWithDefaults({
                sessionId: sessionId,
                deviceType: deviceType,
                credentials: credentials
            })).unwrap();

            setExecutionResult(result);
            setStep(4);
        } catch (error) {
            console.error("Error executing hardening fixes:", error);
            setStep(2); // Go back to SSH form on error
        }
    };

    const handleFinish = () => {
        if (onSuccess) {
            onSuccess();
        }
        onClose();
    };

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
                    <p className="hardening-sub-text">Click Next to proceed with SSH credentials.</p>
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
                            <input
                                type="text"
                                value={paramValues[key] || ''}
                                onChange={(e) => handleParamChange(key, e.target.value)}
                                placeholder={param.default || `Enter ${key}`}
                            />
                            {param.usage && (
                                <span className="hardening-param-usage">{param.usage}</span>
                            )}
                        </div>
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
                <p>Please wait while we apply the security hardening configurations.</p>
                <p>This may take a few minutes.</p>
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

        const successCount = executionResult.successful || 0;
        const failedCount = executionResult.failed || 0;
        const skippedCount = executionResult.skipped || 0;

        return (
            <div>
                <div className="hardening-results-summary">
                    <div className="hardening-result-item success">
                        <span className="hardening-result-icon">✓</span>
                        <div>
                            <strong>{successCount}</strong>
                            <span>Successful</span>
                        </div>
                    </div>
                    <div className="hardening-result-item failed">
                        <span className="hardening-result-icon">✗</span>
                        <div>
                            <strong>{failedCount}</strong>
                            <span>Failed</span>
                        </div>
                    </div>
                    <div className="hardening-result-item skipped">
                        <span className="hardening-result-icon">⊘</span>
                        <div>
                            <strong>{skippedCount}</strong>
                            <span>Skipped</span>
                        </div>
                    </div>
                </div>

                {successCount > 0 && (
                    <div className="hardening-success-message">
                        <p>✓ Hardening completed successfully! {successCount} checks were hardened.</p>
                    </div>
                )}

                {failedCount > 0 && (
                    <div className="hardening-error-message">
                        <span>⚠</span>
                        <p>{failedCount} checks failed to harden. Please review the logs for details.</p>
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
                        <h2>Harden All Failed Checks</h2>
                    </div>
                    <button className="hardening-modal-close" onClick={onClose}>×</button>
                </div>

                {/* Info */}
                {step <= 2 && (
                    <div className="hardening-modal-info">
                        <span className="hardening-info-icon">ℹ️</span>
                        <p>
                            {step === 1
                                ? "Review and configure parameters for hardening all failed checks."
                                : "Enter SSH credentials to execute hardening fixes."}
                        </p>
                    </div>
                )}

                {/* Body */}
                <div className="hardening-modal-body">
                    {step === 1 && renderParametersForm()}
                    {step === 2 && renderSSHForm()}
                    {step === 3 && renderExecuting()}
                    {step === 4 && renderResults()}
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
                                onClick={handleNextFromParams}
                                disabled={isFetchingParams}
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
                                onClick={handleExecute}
                                disabled={isExecuting}
                            >
                                Execute Hardening
                            </button>
                        </>
                    )}

                    {step === 4 && (
                        <button className="hardening-btn-primary" onClick={handleFinish}>
                            Finish
                        </button>
                    )}
                </div>

                {/* Error Display */}
                {error && step !== 4 && (
                    <div className="hardening-error-message" style={{margin: '16px 24px'}}>
                        <span>⚠</span>
                        <p>{error}</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default HardenAllModal;