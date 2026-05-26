import React, { useEffect, useState, useCallback } from 'react';
import api from '../../config/api.js';
import BackupViewModal from './BackupViewModal.jsx';
import NewBackupModal from './NewBackupModal.jsx';

const formatDate = (ts) => {
    if (!ts) return '-';
    return new Date(ts).toLocaleString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: '2-digit', minute: '2-digit', hour12: false,
    });
};

export const BackupPage = () => {
    const [backups, setBackups] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [sourceFilter, setSourceFilter] = useState('all');
    const [viewId, setViewId] = useState(null);
    const [showNew, setShowNew] = useState(false);
    const [deleteId, setDeleteId] = useState(null);
    const [deleting, setDeleting] = useState(false);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const params = new URLSearchParams({ limit: 200 });
            if (sourceFilter !== 'all') params.append('source', sourceFilter);
            const res = await api.get(`/api/backups/?${params}`);
            setBackups(res.data || []);
        } catch (e) {
            setError(e.response?.data?.detail || 'Failed to load backups');
        } finally {
            setLoading(false);
        }
    }, [sourceFilter]);

    useEffect(() => {
        load();
    }, [load]);

    const handleDelete = async (id) => {
        setDeleting(true);
        try {
            await api.delete(`/api/backups/${id}`);
            setDeleteId(null);
            setBackups((prev) => prev.filter((b) => b.id !== id));
        } catch (e) {
            alert(e.response?.data?.detail || 'Delete failed');
        } finally {
            setDeleting(false);
        }
    };

    return (
        <div style={{ padding: '0 0 32px' }}>
            {/* Toolbar */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', gap: 4 }}>
                    {['all', 'manual', 'hardening'].map((s) => (
                        <button
                            key={s}
                            onClick={() => setSourceFilter(s)}
                            style={{
                                padding: '6px 14px',
                                borderRadius: 6,
                                border: '1px solid',
                                borderColor: sourceFilter === s ? '#3B82F6' : '#D1D5DB',
                                background: sourceFilter === s ? '#EFF6FF' : 'white',
                                color: sourceFilter === s ? '#1D4ED8' : '#374151',
                                fontWeight: sourceFilter === s ? 600 : 400,
                                cursor: 'pointer',
                                fontSize: 13,
                                textTransform: 'capitalize',
                            }}
                        >
                            {s === 'all' ? 'All' : s}
                        </button>
                    ))}
                </div>

                <div style={{ marginLeft: 'auto' }}>
                    <button
                        className="btn btn-primary"
                        onClick={() => setShowNew(true)}
                        style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                    >
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M12 5v14M5 12h14" />
                        </svg>
                        New Backup
                    </button>
                </div>
            </div>

            {/* Error */}
            {error && (
                <div className="alert alert-error" style={{ marginBottom: 16 }}>
                    <span>{error}</span>
                </div>
            )}

            {/* Table */}
            {loading ? (
                <div style={{ textAlign: 'center', padding: 60, color: '#6B7280' }}>
                    <div className="spinner-lg" />
                    <p>Loading backups…</p>
                </div>
            ) : backups.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 80, color: '#6B7280' }}>
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" style={{ opacity: 0.4 }}>
                        <path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z" />
                        <polyline points="17 21 17 13 7 13 7 21" />
                        <polyline points="7 3 7 8 15 8" />
                    </svg>
                    <p style={{ marginTop: 12 }}>No backups found.</p>
                    <p style={{ fontSize: 13 }}>Run a hardening job or click <strong>New Backup</strong> to get started.</p>
                </div>
            ) : (
                <div className="table-container">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>Asset</th>
                                <th>Device IP</th>
                                <th>Type</th>
                                <th>Source</th>
                                <th>Taken At</th>
                                <th>By</th>
                                <th className="col-actions">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {backups.map((b) => (
                                <tr key={b.id}>
                                    <td>
                                        <span style={{ fontWeight: 500 }}>
                                            {b.asset_name || `Asset #${b.asset_id}`}
                                        </span>
                                    </td>
                                    <td>
                                        <code style={{ fontSize: 12 }}>{b.device_ip || '-'}</code>
                                    </td>
                                    <td>
                                        <span style={{ textTransform: 'capitalize' }}>
                                            {b.device_type || '-'}
                                        </span>
                                    </td>
                                    <td>
                                        <span
                                            style={{
                                                display: 'inline-flex',
                                                alignItems: 'center',
                                                padding: '2px 10px',
                                                borderRadius: 12,
                                                fontSize: 12,
                                                fontWeight: 600,
                                                background: b.source === 'manual' ? '#EFF6FF' : '#F0FDF4',
                                                color: b.source === 'manual' ? '#1D4ED8' : '#15803D',
                                            }}
                                        >
                                            {b.source}
                                        </span>
                                    </td>
                                    <td>{formatDate(b.created_at)}</td>
                                    <td>{b.created_by_username || '-'}</td>
                                    <td className="col-actions">
                                        <div className="action-buttons">
                                            <button
                                                className="btn btn-sm btn-ghost"
                                                onClick={() => setViewId(b.id)}
                                                title="View config"
                                            >
                                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                                                    <circle cx="12" cy="12" r="3" />
                                                </svg>
                                                View
                                            </button>
                                            <button
                                                className="btn btn-sm btn-ghost btn-danger"
                                                onClick={() => setDeleteId(b.id)}
                                                title="Delete backup"
                                            >
                                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                                    <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
                                                </svg>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* Delete Confirm */}
            {deleteId && (
                <div className="modal-overlay" onClick={() => setDeleteId(null)}>
                    <div className="modal" style={{ maxWidth: 380 }} onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h2>Delete Backup</h2>
                        </div>
                        <div className="modal-body">
                            <p>Are you sure you want to delete this backup? This action cannot be undone.</p>
                        </div>
                        <div className="modal-footer">
                            <button className="btn btn-ok" onClick={() => setDeleteId(null)} disabled={deleting}>
                                Cancel
                            </button>
                            <button
                                className="btn btn-danger"
                                onClick={() => handleDelete(deleteId)}
                                disabled={deleting}
                            >
                                {deleting ? 'Deleting…' : 'Delete'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* View Modal */}
            {viewId && (
                <BackupViewModal backupId={viewId} onClose={() => setViewId(null)} />
            )}

            {/* New Backup Modal */}
            {showNew && (
                <NewBackupModal
                    onClose={() => setShowNew(false)}
                    onSuccess={load}
                />
            )}
        </div>
    );
};

export default BackupPage;
