/**
 * ConfigurationForm - Dynamic form for hardening parameters
 *
 * Renders input fields based on parameter metadata from the backend.
 */

import { useState } from 'react';

export const ConfigurationForm = ({
    parameters,
    values,
    onChange,
    onSubmit,
    onCancel,
    loading = false
}) => {
    const [showPasswords, setShowPasswords] = useState({});

    // Toggle password visibility for a specific field
    const togglePasswordVisibility = (paramName) => {
        setShowPasswords(prev => ({
            ...prev,
            [paramName]: !prev[paramName]
        }));
    };

    // Render appropriate input based on parameter type
    const renderInput = (paramName, paramMeta) => {
        const value = values[paramName] || '';
        const isRequired = paramMeta.required;
        const inputId = `param-${paramName}`;

        switch (paramMeta.type) {
            case 'password':
                return (
                    <div className="password-input-wrapper">
                        <input
                            type={showPasswords[paramName] ? 'text' : 'password'}
                            id={inputId}
                            value={value}
                            onChange={(e) => onChange(paramName, e.target.value)}
                            placeholder={paramMeta.placeholder || ''}
                            required={isRequired}
                            disabled={loading}
                        />
                        <button
                            type="button"
                            className="toggle-password-btn"
                            onClick={() => togglePasswordVisibility(paramName)}
                        >
                            {showPasswords[paramName] ? 'Hide' : 'Show'}
                        </button>
                    </div>
                );

            case 'textarea':
                return (
                    <textarea
                        id={inputId}
                        value={value}
                        onChange={(e) => onChange(paramName, e.target.value)}
                        placeholder={paramMeta.placeholder || ''}
                        required={isRequired}
                        disabled={loading}
                        rows={4}
                    />
                );

            case 'number':
                return (
                    <input
                        type="number"
                        id={inputId}
                        value={value}
                        onChange={(e) => onChange(paramName, e.target.value)}
                        placeholder={paramMeta.default || paramMeta.placeholder || ''}
                        required={isRequired}
                        disabled={loading}
                        min={paramMeta.min_value}
                        max={paramMeta.max_value}
                    />
                );

            case 'ip':
                return (
                    <input
                        type="text"
                        id={inputId}
                        value={value}
                        onChange={(e) => onChange(paramName, e.target.value)}
                        placeholder={paramMeta.placeholder || '192.168.1.1'}
                        required={isRequired}
                        disabled={loading}
                        pattern="^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
                        title="Enter a valid IP address"
                    />
                );

            case 'select':
                return (
                    <select
                        id={inputId}
                        value={value || paramMeta.default || ''}
                        onChange={(e) => onChange(paramName, e.target.value)}
                        required={isRequired}
                        disabled={loading}
                    >
                        <option value="">-- Select --</option>
                        {paramMeta.options?.map(option => (
                            <option key={option} value={option}>
                                {option}
                            </option>
                        ))}
                    </select>
                );

            default: // text
                return (
                    <input
                        type="text"
                        id={inputId}
                        value={value}
                        onChange={(e) => onChange(paramName, e.target.value)}
                        placeholder={paramMeta.placeholder || ''}
                        required={isRequired}
                        disabled={loading}
                    />
                );
        }
    };

    // Check if all required parameters are filled
    const validateForm = () => {
        for (const [paramName, paramMeta] of Object.entries(parameters)) {
            if (paramMeta.required && !values[paramName]) {
                return false;
            }
        }
        return true;
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (validateForm()) {
            onSubmit(values);
        }
    };

    // If no parameters, show message
    if (!parameters || Object.keys(parameters).length === 0) {
        return (
            <div className="configuration-form no-params">
                <p>No additional configuration required.</p>
                <div className="form-actions">
                    {onCancel && (
                        <button
                            type="button"
                            className="btn btn-secondary"
                            onClick={onCancel}
                            disabled={loading}
                        >
                            Cancel
                        </button>
                    )}
                    <button
                        type="button"
                        className="btn btn-primary"
                        onClick={() => onSubmit({})}
                        disabled={loading}
                    >
                        Continue
                    </button>
                </div>
            </div>
        );
    }

    return (
        <form className="configuration-form" onSubmit={handleSubmit}>
            <h4>Configuration Parameters</h4>
            <p className="form-description">
                Fill in the required parameters for the selected checks.
            </p>

            {Object.entries(parameters).map(([paramName, paramMeta]) => (
                <div key={paramName} className="form-group">
                    <label htmlFor={`param-${paramName}`}>
                        {paramMeta.label}
                        {paramMeta.required && <span className="required-marker"> *</span>}
                    </label>

                    {renderInput(paramName, paramMeta)}

                    {paramMeta.description && (
                        <small className="form-hint">{paramMeta.description}</small>
                    )}

                    {paramMeta.default && !paramMeta.required && (
                        <small className="form-hint default-hint">
                            Default: {paramMeta.default}
                        </small>
                    )}

                    {paramMeta.checks && paramMeta.checks.length > 0 && (
                        <small className="form-hint checks-hint">
                            Used by: {paramMeta.checks.join(', ')}
                        </small>
                    )}
                </div>
            ))}

            <div className="form-actions">
                {onCancel && (
                    <button
                        type="button"
                        className="btn btn-secondary"
                        onClick={onCancel}
                        disabled={loading}
                    >
                        Back
                    </button>
                )}
                <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={loading || !validateForm()}
                >
                    {loading ? 'Processing...' : 'Continue'}
                </button>
            </div>
        </form>
    );
};

export default ConfigurationForm;
