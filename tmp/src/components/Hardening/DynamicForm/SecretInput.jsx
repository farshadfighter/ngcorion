/**
 * SecretInput - Password input with show/hide toggle
 */

import { useState } from 'react';

const SecretInput = ({
    input,
    value,
    onChange,
    error,
    disabled = false,
}) => {
    const [showPassword, setShowPassword] = useState(false);
    const inputId = `input-${input.name}`;

    return (
        <div className={`form-group ${error ? 'has-error' : ''}`}>
            <label htmlFor={inputId}>
                {input.label || input.name}
                {input.required && <span className="required-marker"> *</span>}
            </label>
            <div className="password-input-wrapper">
                <input
                    type={showPassword ? 'text' : 'password'}
                    id={inputId}
                    value={value || ''}
                    onChange={(e) => onChange(e.target.value)}
                    placeholder={input.hint || ''}
                    disabled={disabled}
                    className={error ? 'input-error' : ''}
                    autoComplete="new-password"
                />
                <button
                    type="button"
                    className="toggle-password-btn"
                    onClick={() => setShowPassword(!showPassword)}
                    disabled={disabled}
                >
                    {showPassword ? 'Hide' : 'Show'}
                </button>
            </div>
            {input.hint && !error && (
                <small className="form-hint">{input.hint}</small>
            )}
            {error && (
                <small className="form-error">{error}</small>
            )}
        </div>
    );
};

export default SecretInput;
