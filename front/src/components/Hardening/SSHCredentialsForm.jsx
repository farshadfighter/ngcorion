/**
 * SSHCredentialsForm - Reusable form for SSH credentials input
 *
 * Supports two modes:
 * 1. Uncontrolled: Uses internal state, calls onSubmit with credentials
 * 2. Controlled: Uses external credentials prop, calls onChange for updates
 */

import { useState } from 'react';

export const SSHCredentialsForm = ({
    onSubmit,
    onCancel,
    loading = false,
    // Controlled mode props
    credentials: externalCredentials,
    onChange: externalOnChange,
}) => {
    // Internal state for uncontrolled mode
    const [internalCredentials, setInternalCredentials] = useState({
        username: 'admin',  // Default from CLAUDE.md
        password: '',
        secret: '',
    });
    const [showPassword, setShowPassword] = useState(false);
    const [showSecret, setShowSecret] = useState(false);

    // Determine if we're in controlled mode
    const isControlled = externalCredentials !== undefined;
    const credentials = isControlled ? externalCredentials : internalCredentials;

    const handleChange = (e) => {
        const { name, value } = e.target;
        const newCredentials = {
            ...credentials,
            [name]: value
        };

        if (isControlled && externalOnChange) {
            externalOnChange(newCredentials);
        } else {
            setInternalCredentials(newCredentials);
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!credentials.username || !credentials.password) {
            alert('Username and password are required.');
            return;
        }
        if (onSubmit) {
            onSubmit(credentials);
        }
    };

    // In controlled mode without onSubmit, render as div instead of form
    const FormWrapper = isControlled && !onSubmit ? 'div' : 'form';
    const formProps = isControlled && !onSubmit ? {} : { onSubmit: handleSubmit };

    return (
        <FormWrapper className="ssh-credentials-form" {...formProps}>
            {!isControlled && <h4>SSH Credentials</h4>}
            {!isControlled && (
                <p className="form-description">
                    Enter the SSH credentials for the target device.
                    Credentials are used only for this operation and are not stored.
                </p>
            )}

            <div className="form-group">
                <label htmlFor="ssh-username">Username *</label>
                <input
                    type="text"
                    id="ssh-username"
                    name="username"
                    value={credentials.username}
                    onChange={handleChange}
                    placeholder="admin"
                    required
                    disabled={loading}
                />
            </div>

            <div className="form-group">
                <label htmlFor="ssh-password">Password *</label>
                <div className="password-input-wrapper">
                    <input
                        type={showPassword ? 'text' : 'password'}
                        id="ssh-password"
                        name="password"
                        value={credentials.password}
                        onChange={handleChange}
                        placeholder="Enter password"
                        required
                        disabled={loading}
                    />
                    <button
                        type="button"
                        className="toggle-password-btn"
                        onClick={() => setShowPassword(!showPassword)}
                    >
                        {showPassword ? 'Hide' : 'Show'}
                    </button>
                </div>
            </div>

            <div className="form-group">
                <label htmlFor="ssh-secret">Enable Secret (optional)</label>
                <div className="password-input-wrapper">
                    <input
                        type={showSecret ? 'text' : 'password'}
                        id="ssh-secret"
                        name="secret"
                        value={credentials.secret}
                        onChange={handleChange}
                        placeholder="Enter enable secret"
                        disabled={loading}
                    />
                    <button
                        type="button"
                        className="toggle-password-btn"
                        onClick={() => setShowSecret(!showSecret)}
                    >
                        {showSecret ? 'Hide' : 'Show'}
                    </button>
                </div>
                <small className="form-hint">
                    Required if the device uses enable mode with a secret.
                </small>
            </div>

            {/* Only show form actions in uncontrolled mode or when onSubmit is provided */}
            {(!isControlled || onSubmit || onCancel) && (
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
                    {(!isControlled || onSubmit) && (
                        <button
                            type="submit"
                            className="btn btn-primary"
                            disabled={loading || !credentials.username || !credentials.password}
                        >
                            {loading ? 'Connecting...' : 'Continue'}
                        </button>
                    )}
                </div>
            )}
        </FormWrapper>
    );
};

export default SSHCredentialsForm;
