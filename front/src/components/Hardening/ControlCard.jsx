/**
 * ControlCard - Single control with state selector and collapsible inputs
 */

import { useState, useCallback } from 'react';
import DynamicForm from './DynamicForm';

const ControlCard = ({
    control,
    controlState = { state: 'AUDIT', inputs: {} },
    onStateChange,
    onInputChange,
    sharedFields = [],
    sharedFieldValues = {},
    onSharedFieldChange,
    errors = {},
    disabled = false,
    expanded = false,
    onToggleExpand,
}) => {
    const [isExpanded, setIsExpanded] = useState(expanded);

    const handleStateChange = (e) => {
        const newState = e.target.value;
        onStateChange(control.control_id, newState);
    };

    const handleInputChange = useCallback((inputName, value) => {
        onInputChange(control.control_id, inputName, value);
    }, [control.control_id, onInputChange]);

    const toggleExpand = () => {
        const newExpanded = !isExpanded;
        setIsExpanded(newExpanded);
        if (onToggleExpand) {
            onToggleExpand(control.control_id, newExpanded);
        }
    };

    // Determine if control has inputs that need to be shown
    const hasInputs = control.inputs && control.inputs.length > 0;
    const showInputs = controlState.state === 'APPLY' && hasInputs;
    const hasErrors = Object.keys(errors).length > 0;

    // Get state badge class
    const getStateBadgeClass = () => {
        switch (controlState.state) {
            case 'APPLY': return 'state-apply';
            case 'AUDIT': return 'state-audit';
            case 'SKIP': return 'state-skip';
            default: return '';
        }
    };

    return (
        <div className={`control-card ${hasErrors ? 'has-errors' : ''} ${controlState.state.toLowerCase()}`}>
            <div className="control-card-header" onClick={hasInputs ? toggleExpand : undefined}>
                <div className="control-info">
                    <span className="control-id">{control.control_id}</span>
                    <span className="control-title">{control.title}</span>
                    {control.risk_level === 'HIGH' && (
                        <span className="risk-badge high">HIGH RISK</span>
                    )}
                </div>

                <div className="control-actions">
                    <select
                        className={`state-selector ${getStateBadgeClass()}`}
                        value={controlState.state}
                        onChange={handleStateChange}
                        onClick={(e) => e.stopPropagation()}
                        disabled={disabled}
                    >
                        {control.state_options.map(option => (
                            <option key={option} value={option}>
                                {option}
                            </option>
                        ))}
                    </select>

                    {hasInputs && (
                        <button
                            type="button"
                            className={`expand-btn ${isExpanded ? 'expanded' : ''}`}
                            onClick={(e) => {
                                e.stopPropagation();
                                toggleExpand();
                            }}
                            disabled={disabled}
                        >
                            {isExpanded ? '▼' : '▶'}
                        </button>
                    )}
                </div>
            </div>

            {hasErrors && !isExpanded && (
                <div className="control-error-summary">
                    <span className="error-icon">⚠</span>
                    {Object.keys(errors).length} validation error(s)
                </div>
            )}

            {showInputs && isExpanded && (
                <div className="control-card-body">
                    <DynamicForm
                        inputs={control.inputs}
                        values={controlState.inputs}
                        onChange={handleInputChange}
                        sharedFields={sharedFields}
                        sharedFieldValues={sharedFieldValues}
                        onSharedFieldChange={onSharedFieldChange}
                        errors={errors}
                        disabled={disabled}
                        controlId={control.control_id}
                    />
                </div>
            )}

            {controlState.state === 'SKIP' && (
                <div className="control-skip-notice">
                    This control will be skipped during hardening.
                </div>
            )}

            {controlState.state === 'AUDIT' && (
                <div className="control-audit-notice">
                    This control will be audited only (no changes applied).
                </div>
            )}
        </div>
    );
};

export default ControlCard;
