/**
 * SSHCredentialsForm - Reusable form for SSH credentials input
 */

import { useState } from 'react';

export const SSHCredentialsForm = ({ onSubmit, onCancel, loading = false }) => {
    const [credentials, setCredentials] = useState({
        username: 'admin',  // Default from CLAUDE.md
        password: '',
        secret: '',
    });
    const [showPassword, setShowPassword] = useState(false);
    const [showSecret, setShowSecret] = useState(false);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setCredentials(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!credentials.username || !credentials.password) {
            alert('Username and password are required.');
            return;
        }
        onSubmit(credentials);
    };

    return (
        <form className="ssh-credentials-form" onSubmit={handleSubmit}>
            <h4>SSH Credentials</h4>
            <p className="form-description">
                Enter the SSH credentials for the target device.
                Credentials are used only for this operation and are not stored.
            </p>

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
                    type="submit"
                    className="btn btn-primary"
                    disabled={loading || !credentials.username || !credentials.password}
                >
                    {loading ? 'Connecting...' : 'Continue'}
                </button>
            </div>
        </form>
    );
};

export default SSHCredentialsForm;
