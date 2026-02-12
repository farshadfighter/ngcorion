/**
 * FixSingleModal - Modal for fixing a single check
 *
 * Steps:
 * 1. Show check details
 * 2. Preview hardening commands
 * 3. Collect parameters (if any)
 * 4. Collect SSH credentials
 * 5. Execute and show result
 */

import { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    previewSingleCheck,
    executeSingleCheck,
    clearPreview,
    clearExecutionResult,
    selectSinglePreview,
    selectExecutionResult,
    selectLoading,
    selectSelectedSession,
} from '../../store/hardeningSlice';
import { SSHCredentialsForm } from './SSHCredentialsForm';
import { ConfigurationForm } from './ConfigurationForm';

export const FixSingleModal = ({ check, deviceType = 'cisco', onClose }) => {
    const dispatch = useDispatch();

    const preview = useSelector(selectSinglePreview);
    const executionResult = useSelector(selectExecutionResult);
    const loading = useSelector(selectLoading);
    const selectedSession = useSelector(selectSelectedSession);

    // Steps: 'preview' | 'params' | 'credentials' | 'executing' | 'result'
    const [step, setStep] = useState('preview');
    const [userParams, setUserParams] = useState({});
    const [sshCredentials, setSshCredentials] = useState(null);
    const [vdom, setVdom] = useState(''); // FortiGate VDOM support

    // Request preview on mount
    useEffect(() => {
        if (deviceType === 'linux') {
            // Linux uses template endpoint with check_number
            dispatch(previewSingleCheck({
                checkId: check.check_number,
                deviceType
            }));
        } else {
            dispatch(previewSingleCheck({ auditResultId: check.id, deviceType }));
        }
        return () => {
            dispatch(clearPreview());
            dispatch(clearExecutionResult());
        };
    }, [check.id, check.check_number, deviceType, dispatch]);

    // Handle close
    const handleClose = () => {
        dispatch(clearPreview());
        dispatch(clearExecutionResult());
        onClose();
    };

    // Move to params step or credentials if no params needed
    const handlePreviewConfirm = () => {
        // Check for required parameters
        const hasRequiredParams = deviceType === 'linux'
            ? preview?.parameters_metadata?.some(p => p.required && !p.default)
            : preview?.required_parameters?.length > 0;

        if (hasRequiredParams) {
            setStep('params');
        } else {
            setStep('credentials');
        }
    };

    // Handle params submission
    const handleParamsSubmit = (params) => {
        setUserParams(params);
        setStep('credentials');
    };

    // Handle SSH credentials submission
    const handleCredentialsSubmit = (credentials) => {
        setSshCredentials(credentials);
        setStep('executing');

        // Execute the fix
        dispatch(executeSingleCheck({
            actionId: preview?.action_id,
            assetId: selectedSession?.asset_id,  // Required for Linux
            checkId: check.check_number,  // Required for Linux
            sshCredentials: credentials,
            parameters: userParams,
            deviceType,
            vdom: deviceType === 'fortinet' ? vdom : null,
        }));
    };

    // Update step when execution completes
    useEffect(() => {
        if (executionResult && step === 'executing') {
            setStep('result');
        }
    }, [executionResult, step]);

    // Build required params metadata
    const getParamsMetadata = () => {
        const metadata = {};

        // Linux returns full parameter metadata from template endpoint
        if (deviceType === 'linux' && preview?.parameters_metadata) {
            preview.parameters_metadata.forEach(param => {
                metadata[param.name] = {
                    type: param.type || 'text',
                    label: param.label || param.name.replace(/_/g, ' '),
                    description: param.description,
                    required: param.required,
                    default: param.default,
                    options: param.options,
                    min_value: param.min_value,
                    max_value: param.max_value,
                };
            });
            return metadata;
        }

        // Cisco/FortiGate - infer types from parameter names
        if (preview?.required_parameters) {
            preview.required_parameters.forEach(param => {
                metadata[param] = {
                    type: param.includes('SECRET') || param.includes('PASSWORD') ? 'password' :
                          param.includes('TEXT') ? 'textarea' :
                          param.includes('SERVER') || param.includes('IP') ? 'ip' : 'text',
                    label: param.replace(/_/g, ' '),
                    required: true,
                };
            });
        }
        if (preview?.optional_parameters) {
            preview.optional_parameters.forEach(param => {
                metadata[param] = {
                    type: 'text',
                    label: param.replace(/_/g, ' '),
                    required: false,
                };
            });
        }
        return metadata;
    };

    return (
        <div className="modal-overlay" onClick={handleClose}>
            <div className="modal fix-single-modal" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h3>Fix Single Check</h3>
                    <button className="close-btn" onClick={handleClose}>×</button>
                </div>

                <div className="modal-body">
                    {/* Check Info */}
                    <div className="check-info">
                        <div className="check-number">{check.check_number}</div>
                        <div className="check-title">{check.check_title}</div>
                    </div>

                    {/* Step: Preview */}
                    {step === 'preview' && (
                        <div className="step-preview">
                            {loading.preview && (
                                <div className="loading-message">Loading preview...</div>
                            )}

                            {!loading.preview && preview && (
                                <>
                                    <h4>Commands to Execute</h4>
                                    <div className="commands-preview">
                                        {preview.commands.map((cmd, idx) => (
                                            <div key={idx} className="command-line">
                                                <code>{cmd}</code>
                                            </div>
                                        ))}
                                    </div>

                                    {preview.warnings?.length > 0 && (
                                        <div className="warnings">
                                            <h5>Warnings</h5>
                                            <ul>
                                                {preview.warnings.map((warning, idx) => (
                                                    <li key={idx}>{warning}</li>
                                                ))}
                                            </ul>
                                        </div>
                                    )}

                                    {preview.required_parameters?.length > 0 && (
                                        <div className="required-params-notice">
                                            <strong>Required Parameters:</strong>{' '}
                                            {preview.required_parameters.join(', ')}
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
                                            onClick={handlePreviewConfirm}
                                        >
                                            Continue
                                        </button>
                                    </div>
                                </>
                            )}
                        </div>
                    )}

                    {/* Step: Parameters */}
                    {step === 'params' && (
                        <div className="step-params">
                            <ConfigurationForm
                                parameters={getParamsMetadata()}
                                values={userParams}
                                onChange={(name, value) => setUserParams(prev => ({ ...prev, [name]: value }))}
                                onSubmit={handleParamsSubmit}
                                onCancel={() => setStep('preview')}
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
                                    if (preview?.required_parameters?.length > 0) {
                                        setStep('params');
                                    } else {
                                        setStep('preview');
                                    }
                                }}
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
                                <p>Executing hardening commands...</p>
                                <p className="small">This may take a moment.</p>
                            </div>
                        </div>
                    )}

                    {/* Step: Result */}
                    {step === 'result' && executionResult && (
                        <div className="step-result">
                            <div className={`result-status ${executionResult.status}`}>
                                {executionResult.status === 'success' ? (
                                    <>
                                        <div className="status-icon success">✓</div>
                                        <h4>Fix Applied Successfully</h4>
                                    </>
                                ) : (
                                    <>
                                        <div className="status-icon failed">✗</div>
                                        <h4>Fix Failed</h4>
                                    </>
                                )}
                            </div>

                            <div className="result-details">
                                <div className="detail-item">
                                    <span className="label">Verification:</span>
                                    <span className={`value ${executionResult.verification_passed ? 'passed' : 'failed'}`}>
                                        {executionResult.verification_passed ? 'Passed' : 'Failed'}
                                    </span>
                                </div>

                                {executionResult.backup_created && (
                                    <div className="detail-item">
                                        <span className="label">Backup Created:</span>
                                        <span className="value">Yes</span>
                                    </div>
                                )}

                                {executionResult.error_message && (
                                    <div className="detail-item error">
                                        <span className="label">Error:</span>
                                        <span className="value">{executionResult.error_message}</span>
                                    </div>
                                )}

                                {executionResult.verification_evidence && (
                                    <div className="detail-item">
                                        <span className="label">Evidence:</span>
                                        <pre className="evidence">{executionResult.verification_evidence}</pre>
                                    </div>
                                )}
                            </div>

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

export default FixSingleModal;
