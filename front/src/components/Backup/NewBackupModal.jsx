import React, { useEffect, useState } from 'react';
import api from '../../config/api.js';

const NewBackupModal = ({ onClose, onSuccess }) => {
    const [assets, setAssets] = useState([]);
    const [assetsLoading, setAssetsLoading] = useState(true);
    const [form, setForm] = useState({
        asset_id: '',
        device_type: 'cisco',
        ssh_username: '',
        ssh_password: '',
        ssh_secret: '',
        ssh_port: 22,
    });
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState(null);

    useEffect(() => {
        api.get('/api/assets?page=1&page_size=500')
            .then((res) => {
                const list = res.data?.assets || res.data || [];
                setAssets(Array.isArray(list) ? list : []);
            })
            .catch(() => setAssets([]))
            .finally(() => setAssetsLoading(false));
    }, []);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setForm((prev) => ({ ...prev, [name]: value }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!form.asset_id || !form.ssh_username || !form.ssh_password) {
            setError('Asset, SSH username and password are required.');
            return;
        }
        setSubmitting(true);
        setError(null);
        try {
            await api.post('/api/backups/', {
                asset_id: parseInt(form.asset_id),
                device_type: form.device_type,
                ssh_username: form.ssh_username,
                ssh_password: form.ssh_password,
                ssh_secret: form.ssh_secret || undefined,
                ssh_port: parseInt(form.ssh_port) || 22,
            });
            onSuccess();
            onClose();
        } catch (err) {
            setError(err.response?.data?.detail || 'Backup failed. Check SSH credentials and device connectivity.');
        } finally {
            setSubmitting(false);
        }
    };

    const inputStyle = {
        width: '100%',
        padding: '8px 12px',
        border: '1px solid #D1D5DB',
        borderRadius: 6,
        fontSize: 14,
        boxSizing: 'border-box',
    };

    const labelStyle = {
        display: 'block',
        fontSize: 13,
        fontWeight: 500,
        color: '#374151',
        marginBottom: 4,
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal" style={{ maxWidth: 480 }} onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <div className="modal-title-group">
                        <h2>New Backup</h2>
                        <span className="modal-subtitle">Connect to device and save running config</span>
                    </div>
                    <button className="modal-close" onClick={onClose}>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M18 6L6 18M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                <form onSubmit={handleSubmit}>
                    <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                        {error && (
                            <div className="alert alert-error">
                                <span>{error}</span>
                            </div>
                        )}

                        <div>
                            <label style={labelStyle}>Asset *</label>
                            <select
                                name="asset_id"
                                value={form.asset_id}
                                onChange={handleChange}
                                style={inputStyle}
                                required
                                disabled={assetsLoading}
                            >
                                <option value="">{assetsLoading ? 'Loading assets…' : 'Select an asset'}</option>
                                {assets.map((a) => (
                                    <option key={a.id} value={a.id}>
                                        {a.asset_name}{a.ip_address ? ` (${a.ip_address})` : ''}
                                    </option>
                                ))}
                            </select>
                        </div>

                        <div>
                            <label style={labelStyle}>Device Type *</label>
                            <select name="device_type" value={form.device_type} onChange={handleChange} style={inputStyle}>
                                <option value="cisco">Cisco</option>
                                <option value="fortinet">Fortinet</option>
                            </select>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                            <div>
                                <label style={labelStyle}>SSH Username *</label>
                                <input
                                    name="ssh_username"
                                    value={form.ssh_username}
                                    onChange={handleChange}
                                    style={inputStyle}
                                    autoComplete="username"
                                    required
                                />
                            </div>
                            <div>
                                <label style={labelStyle}>SSH Password *</label>
                                <input
                                    type="password"
                                    name="ssh_password"
                                    value={form.ssh_password}
                                    onChange={handleChange}
                                    style={inputStyle}
                                    autoComplete="current-password"
                                    required
                                />
                            </div>
                        </div>

                        {form.device_type === 'cisco' && (
                            <div>
                                <label style={labelStyle}>Enable Secret <span style={{ color: '#9CA3AF', fontWeight: 400 }}>(optional)</span></label>
                                <input
                                    type="password"
                                    name="ssh_secret"
                                    value={form.ssh_secret}
                                    onChange={handleChange}
                                    style={inputStyle}
                                    autoComplete="off"
                                    placeholder="Cisco enable secret"
                                />
                            </div>
                        )}

                        <div style={{ width: 120 }}>
                            <label style={labelStyle}>SSH Port</label>
                            <input
                                type="number"
                                name="ssh_port"
                                value={form.ssh_port}
                                onChange={handleChange}
                                style={inputStyle}
                                min={1}
                                max={65535}
                            />
                        </div>
                    </div>

                    <div className="modal-footer">
                        <button type="button" className="btn btn-ok" onClick={onClose} disabled={submitting}>
                            Cancel
                        </button>
                        <button type="submit" className="btn btn-primary" disabled={submitting}>
                            {submitting ? 'Taking Backup…' : 'Take Backup'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default NewBackupModal;
