import React, { useEffect, useState } from 'react';
import api from '../../config/api.js';
import { t } from "../../i18n";
import { apiErrorText } from "../../utils/apiError.js";
import { FAMILY_LABELS } from "./restoreConstants.js";
import { BACKUP_FAMILIES, deviceLabel, typeFor, typeHint } from "./newBackupForm.js";
import "../../assets/AssetRequirement.css";
import "../../assets/BackupModule.css";

/**
 * Taking a backup now. The asset list is every asset with the device family detected for it
 * (GET /api/backups/devices); choosing an asset sets the device type to that family, which can still
 * be changed (e.g. MongoDB on a Linux host). `assetId` / `deviceType` preselect the device (Backup now
 * from the overview).
 */
const NewBackupModal = ({ onClose, onSuccess, assetId, assetName, deviceType }) => {
    const [devices, setDevices] = useState([]);
    const [assetsLoading, setAssetsLoading] = useState(true);
    const [loadError, setLoadError] = useState(null);
    const [form, setForm] = useState({
        asset_id: assetId ? String(assetId) : '',
        device_type: BACKUP_FAMILIES.includes(deviceType) ? deviceType : '',
        ssh_username: '',
        ssh_password: '',
        ssh_secret: '',
        ssh_port: 22,
    });
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState(null);

    useEffect(() => {
        api.get('/api/backups/devices')
            .then((res) => {
                const list = Array.isArray(res.data) ? res.data : [];
                setDevices(list);
                // A device preselected without its type takes the detected one.
                if (assetId) {
                    const device = list.find((d) => d.asset_id === assetId);
                    setForm((prev) => (prev.device_type ? prev : { ...prev, device_type: typeFor(device) }));
                }
            })
            .catch((err) => { setDevices([]); setLoadError(apiErrorText(err, t("Could not load the assets"))); })
            .finally(() => setAssetsLoading(false));
    }, [assetId]);

    const device = devices.find((d) => String(d.asset_id) === String(form.asset_id));

    const handleChange = (e) => {
        const { name, value } = e.target;
        if (name === 'asset_id') {
            const chosen = devices.find((d) => String(d.asset_id) === value);
            setForm((prev) => ({ ...prev, asset_id: value, device_type: typeFor(chosen) }));
            return;
        }
        setForm((prev) => ({ ...prev, [name]: value }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!form.asset_id || !form.ssh_username || !form.ssh_password) {
            setError(t("Asset, SSH username and password are required."));
            return;
        }
        if (!form.device_type) {
            setError(t("Choose the device type."));
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
            setError(apiErrorText(err, t("Backup failed. Check SSH credentials and device connectivity.")));
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
            <div className="modal-content" style={{ maxWidth: 480, maxHeight: '90vh', overflowY: 'auto' }}
                 onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <div>
                        <h3>{t("New Backup")}</h3>
                        <span style={{ fontSize: 13, color: '#6B7280' }}>{t("Connect to device and save running config")}</span>
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
                            <label style={labelStyle}>{t("Asset *")}</label>
                            <select
                                name="asset_id"
                                value={form.asset_id}
                                onChange={handleChange}
                                style={inputStyle}
                                required
                                disabled={assetsLoading}
                            >
                                <option value="">{assetsLoading ? t("Loading assets…") : t("Select an asset")}</option>
                                {assetId && !devices.some((d) => d.asset_id === assetId) && (
                                    <option value={assetId}>{assetName || t("Asset #{{assetId}}", { assetId })}</option>
                                )}
                                {devices.map((d) => (
                                    <option key={d.asset_id} value={d.asset_id} disabled={!d.ip_address}>
                                        {deviceLabel(d)}
                                    </option>
                                ))}
                            </select>
                            {loadError && <div style={{ fontSize: 12, color: '#B91C1C', marginTop: 4 }}>{loadError}</div>}
                        </div>

                        <div>
                            <label style={labelStyle}>{t("Device Type *")}</label>
                            <select name="device_type" value={form.device_type} onChange={handleChange} style={inputStyle} required>
                                <option value="">{t("Choose the device type")}</option>
                                {BACKUP_FAMILIES.map((value) => <option key={value} value={value}>{FAMILY_LABELS[value]}</option>)}
                            </select>
                            {device && (
                                <div style={{ fontSize: 12, color: device.family && form.device_type === device.family ? '#047857' : '#92400E', marginTop: 4 }}>
                                    {typeHint(device, form.device_type)}
                                </div>
                            )}
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                            <div>
                                <label style={labelStyle}>{t("SSH Username *")}</label>
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
                                <label style={labelStyle}>{t("SSH Password *")}</label>
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
                                <label style={labelStyle}>{t("Enable Secret")}{" "} <span style={{ color: '#9CA3AF', fontWeight: 400 }}>{t("(optional)")}</span></label>
                                <input
                                    type="password"
                                    name="ssh_secret"
                                    value={form.ssh_secret}
                                    onChange={handleChange}
                                    style={inputStyle}
                                    autoComplete="off"
                                    placeholder={t("Cisco enable secret")}
                                />
                            </div>
                        )}

                        <div style={{ width: 120 }}>
                            <label style={labelStyle}>{t("SSH Port")}</label>
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

                    <div className="modal-actions">
                        <button type="button" className="btn-cancel" onClick={onClose} disabled={submitting}>
                            {t("Cancel")}
                        </button>
                        <button type="submit" className="bkm-btn bkm-btn-primary" disabled={submitting}>
                            {submitting ? t("Taking Backup…") : t("Take Backup")}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default NewBackupModal;
