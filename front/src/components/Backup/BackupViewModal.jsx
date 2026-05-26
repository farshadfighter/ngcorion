import React, { useEffect, useState } from 'react';
import api from '../../config/api.js';

const BackupViewModal = ({ backupId, onClose }) => {
    const [backup, setBackup] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetch = async () => {
            try {
                const res = await api.get(`/api/backups/${backupId}`);
                setBackup(res.data);
            } catch (e) {
                setError(e.response?.data?.detail || 'Failed to load backup');
            } finally {
                setLoading(false);
            }
        };
        fetch();
    }, [backupId]);

    const handleDownload = () => {
        if (!backup) return;
        const date = backup.created_at
            ? new Date(backup.created_at).toISOString().slice(0, 10)
            : 'unknown';
        const name = (backup.asset_name || `asset-${backup.asset_id}`).replace(/\s+/g, '_');
        const filename = `backup_${name}_${date}.txt`;
        const blob = new Blob([backup.config_content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    };

    const formatDate = (ts) => {
        if (!ts) return '-';
        return new Date(ts).toLocaleString('en-US', {
            month: 'short', day: 'numeric', year: 'numeric',
            hour: '2-digit', minute: '2-digit', hour12: false,
        });
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div
                className="modal modal-lg"
                style={{ maxWidth: 860 }}
                onClick={(e) => e.stopPropagation()}
            >
                <div className="modal-header">
                    <div className="modal-title-group">
                        <h2>Backup Config</h2>
                        {backup && (
                            <span className="modal-subtitle">
                                {backup.asset_name || `Asset #${backup.asset_id}`} — {backup.device_ip}
                            </span>
                        )}
                    </div>
                    <button className="modal-close" onClick={onClose}>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M18 6L6 18M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                <div className="modal-body">
                    {loading && <p style={{ textAlign: 'center', color: '#6B7280' }}>Loading…</p>}
                    {error && <p style={{ color: '#ef4444' }}>{error}</p>}
                    {backup && (
                        <>
                            <div style={{ display: 'flex', gap: 24, marginBottom: 16, flexWrap: 'wrap' }}>
                                <div>
                                    <span style={{ fontSize: 12, color: '#6B7280' }}>Device Type</span>
                                    <div style={{ fontWeight: 600, textTransform: 'capitalize' }}>{backup.device_type || '-'}</div>
                                </div>
                                <div>
                                    <span style={{ fontSize: 12, color: '#6B7280' }}>Source</span>
                                    <div>
                                        <span className={`status-badge status-${backup.source === 'manual' ? 'completed' : 'running'}`}>
                                            {backup.source}
                                        </span>
                                    </div>
                                </div>
                                <div>
                                    <span style={{ fontSize: 12, color: '#6B7280' }}>Taken At</span>
                                    <div>{formatDate(backup.created_at)}</div>
                                </div>
                                {backup.created_by_username && (
                                    <div>
                                        <span style={{ fontSize: 12, color: '#6B7280' }}>By</span>
                                        <div>{backup.created_by_username}</div>
                                    </div>
                                )}
                            </div>

                            <pre style={{
                                background: '#0f172a',
                                color: '#e2e8f0',
                                borderRadius: 8,
                                padding: '12px 16px',
                                fontSize: 12,
                                lineHeight: 1.6,
                                maxHeight: 460,
                                overflow: 'auto',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-all',
                                margin: 0,
                            }}>
                                {backup.config_content}
                            </pre>
                        </>
                    )}
                </div>

                <div className="modal-footer">
                    {backup && (
                        <button className="btn btn-primary" onClick={handleDownload}>
                            Download .txt
                        </button>
                    )}
                    <button className="btn btn-ok" onClick={onClose}>Close</button>
                </div>
            </div>
        </div>
    );
};

export default BackupViewModal;
