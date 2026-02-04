/**
 * HardeningWizard - Multi-step wizard for schema-driven hardening
 *
 * Steps:
 * 1. Mode Selection - Post-audit or Full hardening
 * 2. Control Selection - List controls with SKIP/AUDIT/APPLY
 * 3. Parameters - Fill in inputs for APPLY controls
 * 4. Credentials - SSH credentials
 * 5. Review - Summary before execution
 * 6. Execution - Progress and results
 */

import { useState, useEffect, useMemo, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    fetchHardeningForm,
    validateHardeningInputs,
    executeHardeningControls,
    setControlState,
    setControlInput,
    setSharedFieldValue,
    clearWizardState,
    selectFormSchema,
    selectSharedFields,
    selectControlStates,
    selectSharedFieldValues,
    selectValidationErrors,
    selectHardeningMode,
    selectWizardLoading,
    selectWizardError,
} from '../../store/hardeningSlice';
import ModeSelector from './ModeSelector';
import ControlCard from './ControlCard';
import SSHCredentialsForm from './SSHCredentialsForm';

const STEPS = {
    MODE: 'mode',
    CONTROLS: 'controls',
    CREDENTIALS: 'credentials',
    REVIEW: 'review',
    EXECUTING: 'executing',
    RESULTS: 'results',
};

const SUPPORTED_DEVICES = [
    { type: 'cisco', name: 'Cisco IOS', status: 'available' },
    { type: 'fortinet', name: 'FortiGate', status: 'coming_soon' },
    { type: 'linux', name: 'Linux', status: 'coming_soon' },
    { type: 'windows', name: 'Windows', status: 'coming_soon' },
    { type: 'apache', name: 'Apache', status: 'coming_soon' },
];

const HardeningWizard = ({
    onClose,
    initialMode = null,
    sessionId = null,
    checkNumbers = null,
}) => {
    const dispatch = useDispatch();

    // Redux state
    const formSchema = useSelector(selectFormSchema);
    const sharedFields = useSelector(selectSharedFields);
    const controlStates = useSelector(selectControlStates);
    const sharedFieldValues = useSelector(selectSharedFieldValues);
    const validationErrors = useSelector(selectValidationErrors);
    const hardeningMode = useSelector(selectHardeningMode);
    const loading = useSelector(selectWizardLoading);
    const error = useSelector(selectWizardError);

    // Local state
    const [currentStep, setCurrentStep] = useState(initialMode ? STEPS.CONTROLS : STEPS.MODE);
    const [deviceType, setDeviceType] = useState('cisco');
    const [deviceIp, setDeviceIp] = useState('');
    const [sshCredentials, setSshCredentials] = useState({
        username: '',
        password: '',
        secret: '',
    });
    const [executionResults, setExecutionResults] = useState(null);
    const [expandedControls, setExpandedControls] = useState(new Set());

    // Load form when mode is selected
    useEffect(() => {
        if (initialMode && sessionId) {
            dispatch(fetchHardeningForm({
                deviceType: 'cisco',
                mode: initialMode,
                sessionId,
                checkNumbers,
            }));
        }
    }, [dispatch, initialMode, sessionId, checkNumbers]);

    // Handle mode selection
    const handleModeSelect = async (mode, selectedDeviceType = 'cisco') => {
        setDeviceType(selectedDeviceType);

        if (mode === 'post_audit') {
            // Need to select session - handled by parent
            if (onClose) onClose('select_session');
            return;
        }

        // Full hardening mode
        await dispatch(fetchHardeningForm({
            deviceType: selectedDeviceType,
            mode: 'full',
        }));
        setCurrentStep(STEPS.CONTROLS);
    };

    // Handle control state change
    const handleControlStateChange = useCallback((controlId, state) => {
        dispatch(setControlState({ controlId, state }));
    }, [dispatch]);

    // Handle control input change
    const handleControlInputChange = useCallback((controlId, inputName, value) => {
        dispatch(setControlInput({ controlId, inputName, value }));
    }, [dispatch]);

    // Handle shared field change
    const handleSharedFieldChange = useCallback((fieldName, value) => {
        dispatch(setSharedFieldValue({ fieldName, value }));
    }, [dispatch]);

    // Toggle control expansion
    const handleToggleExpand = useCallback((controlId, expanded) => {
        setExpandedControls(prev => {
            const newSet = new Set(prev);
            if (expanded) {
                newSet.add(controlId);
            } else {
                newSet.delete(controlId);
            }
            return newSet;
        });
    }, []);

    // Calculate control counts
    const controlCounts = useMemo(() => {
        const counts = { apply: 0, audit: 0, skip: 0, total: 0 };
        if (!formSchema?.controls) return counts;

        formSchema.controls.forEach(control => {
            counts.total++;
            const state = controlStates[control.control_id]?.state || 'AUDIT';
            if (state === 'APPLY') counts.apply++;
            else if (state === 'AUDIT') counts.audit++;
            else counts.skip++;
        });
        return counts;
    }, [formSchema, controlStates]);

    // Validate and proceed to credentials
    const handleProceedToCredentials = async () => {
        // Build control states for validation
        const controlStatesList = Object.entries(controlStates).map(([controlId, state]) => ({
            control_id: controlId,
            state: state.state,
            inputs: state.inputs,
        }));

        const result = await dispatch(validateHardeningInputs({
            deviceType,
            controlStates: controlStatesList,
            sharedFields: sharedFieldValues,
        }));

        if (result.payload?.valid) {
            setCurrentStep(STEPS.CREDENTIALS);
        }
    };

    // Proceed to review
    const handleProceedToReview = () => {
        if (!sshCredentials.username || !sshCredentials.password) {
            alert('Please enter SSH credentials');
            return;
        }
        setCurrentStep(STEPS.REVIEW);
    };

    // Execute hardening
    const handleExecute = async () => {
        setCurrentStep(STEPS.EXECUTING);

        const controlStatesList = Object.entries(controlStates).map(([controlId, state]) => ({
            control_id: controlId,
            state: state.state,
            inputs: state.inputs,
        }));

        const result = await dispatch(executeHardeningControls({
            deviceType,
            deviceIp: deviceIp || undefined,
            sessionId: sessionId || undefined,
            controlStates: controlStatesList,
            sharedFields: sharedFieldValues,
            sshCredentials,
        }));

        if (result.payload) {
            setExecutionResults(result.payload);
            setCurrentStep(STEPS.RESULTS);
        } else {
            setCurrentStep(STEPS.REVIEW);
        }
    };

    // Bulk actions
    const handleSetAllState = (state) => {
        formSchema?.controls.forEach(control => {
            if (control.state_options.includes(state)) {
                dispatch(setControlState({ controlId: control.control_id, state }));
            }
        });
    };

    // Expand/collapse all
    const handleExpandAll = () => {
        const allIds = new Set(formSchema?.controls.map(c => c.control_id) || []);
        setExpandedControls(allIds);
    };

    const handleCollapseAll = () => {
        setExpandedControls(new Set());
    };

    // Clean up on close
    const handleClose = () => {
        dispatch(clearWizardState());
        if (onClose) onClose();
    };

    // Render step content
    const renderStepContent = () => {
        switch (currentStep) {
            case STEPS.MODE:
                return (
                    <ModeSelector
                        onSelect={handleModeSelect}
                        loading={loading.form}
                        supportedDevices={SUPPORTED_DEVICES}
                    />
                );

            case STEPS.CONTROLS:
                return (
                    <div className="controls-step">
                        {/* Shared Fields Section */}
                        {sharedFields.length > 0 && (
                            <div className="shared-fields-section">
                                <h4>Device Configuration</h4>
                                <p className="section-description">
                                    These settings apply across multiple controls.
                                </p>
                                <div className="shared-fields-grid">
                                    {sharedFields.map(field => (
                                        <div key={field.name} className="shared-field">
                                            <label>
                                                {field.label}
                                                {field.required && <span className="required-marker"> *</span>}
                                            </label>
                                            {field.type === 'enum' ? (
                                                <select
                                                    value={sharedFieldValues[field.name] || field.default || ''}
                                                    onChange={(e) => handleSharedFieldChange(field.name, e.target.value)}
                                                >
                                                    <option value="">-- Select --</option>
                                                    {field.options?.map(opt => (
                                                        <option key={opt} value={opt}>{opt}</option>
                                                    ))}
                                                </select>
                                            ) : (
                                                <input
                                                    type="text"
                                                    value={sharedFieldValues[field.name] || field.default || ''}
                                                    onChange={(e) => handleSharedFieldChange(field.name, e.target.value)}
                                                    placeholder={field.hint || ''}
                                                />
                                            )}
                                            {field.hint && <small className="form-hint">{field.hint}</small>}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Device IP for full mode */}
                        {hardeningMode === 'full' && (
                            <div className="device-ip-section">
                                <h4>Target Device</h4>
                                <div className="form-group">
                                    <label>
                                        Device IP Address
                                        <span className="required-marker"> *</span>
                                    </label>
                                    <input
                                        type="text"
                                        value={deviceIp}
                                        onChange={(e) => setDeviceIp(e.target.value)}
                                        placeholder="e.g., 192.168.1.1"
                                    />
                                </div>
                            </div>
                        )}

                        {/* Controls Summary */}
                        <div className="controls-summary">
                            <div className="summary-stats">
                                <span className="stat apply">{controlCounts.apply} APPLY</span>
                                <span className="stat audit">{controlCounts.audit} AUDIT</span>
                                <span className="stat skip">{controlCounts.skip} SKIP</span>
                                <span className="stat total">{controlCounts.total} Total</span>
                            </div>
                            <div className="bulk-actions">
                                <button onClick={() => handleSetAllState('APPLY')} className="link-btn">
                                    Set All APPLY
                                </button>
                                <button onClick={() => handleSetAllState('AUDIT')} className="link-btn">
                                    Set All AUDIT
                                </button>
                                <button onClick={() => handleSetAllState('SKIP')} className="link-btn">
                                    Set All SKIP
                                </button>
                                <span className="separator">|</span>
                                <button onClick={handleExpandAll} className="link-btn">
                                    Expand All
                                </button>
                                <button onClick={handleCollapseAll} className="link-btn">
                                    Collapse All
                                </button>
                            </div>
                        </div>

                        {/* Control Cards */}
                        <div className="control-cards">
                            {formSchema?.controls.map(control => (
                                <ControlCard
                                    key={control.control_id}
                                    control={control}
                                    controlState={controlStates[control.control_id] || { state: 'AUDIT', inputs: {} }}
                                    onStateChange={handleControlStateChange}
                                    onInputChange={handleControlInputChange}
                                    sharedFields={sharedFields}
                                    sharedFieldValues={sharedFieldValues}
                                    onSharedFieldChange={handleSharedFieldChange}
                                    errors={validationErrors[control.control_id] || {}}
                                    expanded={expandedControls.has(control.control_id)}
                                    onToggleExpand={handleToggleExpand}
                                />
                            ))}
                        </div>

                        {/* Validation Errors Summary */}
                        {Object.keys(validationErrors).length > 0 && (
                            <div className="validation-errors-summary">
                                <h4>Validation Errors</h4>
                                <p>Please fix the following errors before proceeding:</p>
                                <ul>
                                    {Object.entries(validationErrors).map(([controlId, errors]) => (
                                        <li key={controlId}>
                                            <strong>{controlId}:</strong>{' '}
                                            {Object.values(errors).join(', ')}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        )}
                    </div>
                );

            case STEPS.CREDENTIALS:
                return (
                    <div className="credentials-step">
                        <h3>SSH Credentials</h3>
                        <p className="step-description">
                            Enter the credentials to connect to the target device.
                        </p>
                        <SSHCredentialsForm
                            credentials={sshCredentials}
                            onChange={setSshCredentials}
                        />
                    </div>
                );

            case STEPS.REVIEW:
                return (
                    <div className="review-step">
                        <h3>Review and Execute</h3>
                        <p className="step-description">
                            Please review the hardening configuration before execution.
                        </p>

                        <div className="review-summary">
                            <div className="review-section">
                                <h4>Target Device</h4>
                                <p>{deviceIp || 'From audit session'}</p>
                            </div>

                            <div className="review-section">
                                <h4>Control Actions</h4>
                                <div className="review-stats">
                                    <div className="stat-item apply">
                                        <span className="number">{controlCounts.apply}</span>
                                        <span className="label">Controls to APPLY</span>
                                    </div>
                                    <div className="stat-item audit">
                                        <span className="number">{controlCounts.audit}</span>
                                        <span className="label">Controls to AUDIT</span>
                                    </div>
                                    <div className="stat-item skip">
                                        <span className="number">{controlCounts.skip}</span>
                                        <span className="label">Controls to SKIP</span>
                                    </div>
                                </div>
                            </div>

                            {controlCounts.apply > 0 && (
                                <div className="review-section">
                                    <h4>Controls to be Applied</h4>
                                    <ul className="apply-list">
                                        {formSchema?.controls
                                            .filter(c => controlStates[c.control_id]?.state === 'APPLY')
                                            .map(control => (
                                                <li key={control.control_id}>
                                                    <code>{control.control_id}</code> - {control.title}
                                                    {control.risk_level === 'HIGH' && (
                                                        <span className="risk-badge high">HIGH RISK</span>
                                                    )}
                                                </li>
                                            ))}
                                    </ul>
                                </div>
                            )}

                            <div className="warning-box">
                                <strong>Warning:</strong> Executing hardening commands will modify device configuration.
                                Ensure you have a backup and maintenance window scheduled.
                            </div>
                        </div>
                    </div>
                );

            case STEPS.EXECUTING:
                return (
                    <div className="executing-step">
                        <div className="executing-animation">
                            <div className="spinner"></div>
                            <p>Executing hardening controls...</p>
                            <p className="small">This may take several minutes.</p>
                        </div>
                    </div>
                );

            case STEPS.RESULTS:
                return (
                    <div className="results-step">
                        <h3>Execution Results</h3>

                        {executionResults && (
                            <>
                                <div className="result-stats">
                                    <div className="stat-item success">
                                        <span className="number">{executionResults.applied_count}</span>
                                        <span className="label">Applied</span>
                                    </div>
                                    <div className="stat-item audit">
                                        <span className="number">{executionResults.audited_count}</span>
                                        <span className="label">Audited</span>
                                    </div>
                                    <div className="stat-item skip">
                                        <span className="number">{executionResults.skipped_count}</span>
                                        <span className="label">Skipped</span>
                                    </div>
                                    <div className="stat-item failed">
                                        <span className="number">{executionResults.failed_count}</span>
                                        <span className="label">Failed</span>
                                    </div>
                                </div>

                                <div className="results-list">
                                    <h4>Detailed Results</h4>
                                    <table className="results-table">
                                        <thead>
                                            <tr>
                                                <th>Control</th>
                                                <th>Status</th>
                                                <th>Message</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {executionResults.results.map(result => (
                                                <tr key={result.control_id} className={`result-row ${result.status}`}>
                                                    <td><code>{result.control_id}</code></td>
                                                    <td>
                                                        <span className={`badge status-${result.status}`}>
                                                            {result.status.toUpperCase()}
                                                        </span>
                                                    </td>
                                                    <td>{result.message || result.error || '-'}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </>
                        )}
                    </div>
                );

            default:
                return null;
        }
    };

    // Render step navigation
    const renderNavigation = () => {
        const showBack = currentStep !== STEPS.MODE && currentStep !== STEPS.EXECUTING;
        const showNext = currentStep === STEPS.CONTROLS || currentStep === STEPS.CREDENTIALS;
        const showExecute = currentStep === STEPS.REVIEW;
        const showClose = currentStep === STEPS.RESULTS;

        return (
            <div className="wizard-navigation">
                {showBack && (
                    <button
                        className="btn btn-secondary"
                        onClick={() => {
                            if (currentStep === STEPS.CONTROLS) setCurrentStep(STEPS.MODE);
                            else if (currentStep === STEPS.CREDENTIALS) setCurrentStep(STEPS.CONTROLS);
                            else if (currentStep === STEPS.REVIEW) setCurrentStep(STEPS.CREDENTIALS);
                        }}
                        disabled={loading.form || loading.validate || loading.execute}
                    >
                        Back
                    </button>
                )}

                <div className="nav-spacer"></div>

                {showNext && (
                    <button
                        className="btn btn-primary"
                        onClick={() => {
                            if (currentStep === STEPS.CONTROLS) handleProceedToCredentials();
                            else if (currentStep === STEPS.CREDENTIALS) handleProceedToReview();
                        }}
                        disabled={loading.form || loading.validate || loading.execute}
                    >
                        {loading.validate ? 'Validating...' : 'Next'}
                    </button>
                )}

                {showExecute && (
                    <button
                        className="btn btn-primary btn-execute"
                        onClick={handleExecute}
                        disabled={loading.execute}
                    >
                        Execute Hardening
                    </button>
                )}

                {showClose && (
                    <button
                        className="btn btn-primary"
                        onClick={handleClose}
                    >
                        Close
                    </button>
                )}
            </div>
        );
    };

    return (
        <div className="hardening-wizard">
            <div className="wizard-header">
                <h2>Device Hardening Wizard</h2>
                <button className="close-btn" onClick={handleClose}>×</button>
            </div>

            {/* Step Indicator */}
            <div className="wizard-steps">
                <div className={`step ${currentStep === STEPS.MODE ? 'active' : ''}`}>
                    1. Mode
                </div>
                <div className={`step ${currentStep === STEPS.CONTROLS ? 'active' : ''}`}>
                    2. Controls
                </div>
                <div className={`step ${currentStep === STEPS.CREDENTIALS ? 'active' : ''}`}>
                    3. Credentials
                </div>
                <div className={`step ${currentStep === STEPS.REVIEW ? 'active' : ''}`}>
                    4. Review
                </div>
                <div className={`step ${currentStep === STEPS.EXECUTING || currentStep === STEPS.RESULTS ? 'active' : ''}`}>
                    5. Execute
                </div>
            </div>

            {/* Error Display */}
            {error && (
                <div className="alert alert-error">
                    <span>{error}</span>
                </div>
            )}

            {/* Loading State */}
            {loading.form && currentStep === STEPS.CONTROLS && (
                <div className="loading-message">
                    <div className="spinner"></div>
                    Loading control schema...
                </div>
            )}

            {/* Step Content */}
            <div className="wizard-content">
                {renderStepContent()}
            </div>

            {/* Navigation */}
            {renderNavigation()}
        </div>
    );
};

export default HardeningWizard;
