import React, { useEffect, useState, useCallback, useMemo } from 'react';
import api from '../../config/api.js';
import BackupViewModal from './BackupViewModal.jsx';
import NewBackupModal from './NewBackupModal.jsx';
import '../../assets/Backup.css';

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
    const [typeFilter, setTypeFilter] = useState('all');
    const [viewId, setViewId] = useState(null);
    const [showNew, setShowNew] = useState(false);
    const [deleteId, setDeleteId] = useState(null);
    const [deleting, setDeleting] = useState(false);

    // برای NewBackupModal onSuccess
    const load = useCallback(async () => {
        const params = new URLSearchParams({ limit: 200 });
        if (sourceFilter !== 'all') params.append('source', sourceFilter);
        const res = await api.get(`/api/backups/?${params}`);
        setBackups(res.data || []);
    }, [sourceFilter]);

    // fetch اصلی داخل useEffect
    useEffect(() => {
        const fetchBackups = async () => {
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
        };
        fetchBackups();
    }, [sourceFilter]);

    // Device-type groups derived from the loaded backups (fortinet, cisco, …)
    const normalizeType = (b) => (b.device_type || 'unknown').toLowerCase();
    const deviceTypes = useMemo(() => {
        const counts = {};
        backups.forEach((b) => {
            const t = normalizeType(b);
            counts[t] = (counts[t] || 0) + 1;
        });
        return Object.entries(counts).sort(([a], [b]) => a.localeCompare(b));
    }, [backups]);

    // If the selected type vanished after a reload/delete, fall back to All
    useEffect(() => {
        if (typeFilter !== 'all' && !deviceTypes.some(([t]) => t === typeFilter)) {
            setTypeFilter('all');
        }
    }, [deviceTypes, typeFilter]);

    const visibleBackups = useMemo(
        () => (typeFilter === 'all' ? backups : backups.filter((b) => normalizeType(b) === typeFilter)),
        [backups, typeFilter]
    );

    const typeLabel = (t) => (t === 'unknown' ? 'Unknown' : t.charAt(0).toUpperCase() + t.slice(1));

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
        <div className="backup-container">
            {/* Header */}
            <div className="backup-header">
                <h1 className="page-title">Backup</h1>
                <button className="btn-header" onClick={() => setShowNew(true)}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 5v14M5 12h14" />
                    </svg>
                    New Backup
                </button>
            </div>

            {/* Device Type Tabs */}
            <div className="backup-filters backup-type-tabs">
                <button
                    onClick={() => setTypeFilter('all')}
                    className={`backup-filter-btn ${typeFilter === 'all' ? 'active' : ''}`}
                >
                    All Devices <span className="backup-tab-count">{backups.length}</span>
                </button>
                {deviceTypes.map(([t, count]) => (
                    <button
                        key={t}
                        onClick={() => setTypeFilter(t)}
                        className={`backup-filter-btn ${typeFilter === t ? 'active' : ''}`}
                    >
                        {typeLabel(t)} <span className="backup-tab-count">{count}</span>
                    </button>
                ))}
            </div>

            {/* Source Filter */}
            <div className="backup-filters">
                {['all', 'manual', 'hardening'].map((s) => (
                    <button
                        key={s}
                        onClick={() => setSourceFilter(s)}
                        className={`backup-filter-btn ${sourceFilter === s ? 'active' : ''}`}
                    >
                        {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
                    </button>
                ))}
            </div>

            {/* Error */}
            {error && (
                <div className="alert alert-error" style={{ marginBottom: 16 }}>
                    <span>{error}</span>
                </div>
            )}

            {/* Table */}
            {loading ? (
                <div className="backup-loading">
                    <div className="spinner-lg" />
                    <p>Loading backups…</p>
                </div>
            ) : visibleBackups.length === 0 ? (
                <div className="backup-empty">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z" />
                        <polyline points="17 21 17 13 7 13 7 21" />
                        <polyline points="7 3 7 8 15 8" />
                    </svg>
                    <p>{typeFilter === 'all' ? 'No backups found.' : `No ${typeLabel(typeFilter)} backups found.`}</p>
                    <p>Run a hardening job or click <strong>New Backup</strong> to get started.</p>
                </div>
            ) : (
                <div className="backup-table-container">
                    <table className="backup-table">
                        <thead>
                        <tr>
                            <th>Asset</th>
                            <th>Device IP</th>
                            <th>Type</th>
                            <th>Source</th>
                            <th>Taken At</th>
                            <th>By</th>
                            <th>Actions</th>
                        </tr>
                        </thead>
                        <tbody>
                        {visibleBackups.map((b) => (
                            <tr key={b.id}>
                                <td>
                                        <span className="backup-asset-name">
                                            {b.asset_name || `Asset #${b.asset_id}`}
                                        </span>
                                </td>
                                <td>
                                    <code className="backup-ip">{b.device_ip || '-'}</code>
                                </td>
                                <td>
                                    <span className="backup-type">{b.device_type || '-'}</span>
                                </td>
                                <td>
                                        <span className={`backup-source-badge ${b.source}`}>
                                            {b.source}
                                        </span>
                                </td>
                                <td>{formatDate(b.created_at)}</td>
                                <td>{b.created_by_username || '-'}</td>
                                <td>
                                    <div className="backup-actions">
                                        <button
                                            className="btn-icon"
                                            onClick={() => setViewId(b.id)}
                                            title="View config"
                                        >
                                            <i className="fa-solid fa-eye"></i>
                                        </button>
                                        <button
                                            className="btn-icon"
                                            onClick={() => setDeleteId(b.id)}
                                            title="Delete backup"
                                        >
                                            <i className="fa-solid fa-trash"></i>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                        </tbody>
                    </table>
                </div>
            )}

            {/* Delete Confirm Modal */}
            {deleteId && (
                <div className="modal-overlay" onClick={() => setDeleteId(null)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Delete Backup</h3>
                            <button className="modal-close" onClick={() => setDeleteId(null)}>×</button>
                        </div>
                        <div className="modal-body">
                            <p>Are you sure you want to delete this backup?</p>
                            <p style={{ color: '#dc2626', fontSize: 13 }}>This action cannot be undone.</p>
                        </div>
                        <div className="modal-actions">
                            <button className="btn-cancel" onClick={() => setDeleteId(null)} disabled={deleting}>
                                Cancel
                            </button>
                            <button className="btn-delete2" onClick={() => handleDelete(deleteId)} disabled={deleting}>
                                {deleting ? 'Deleting…' : 'Delete'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* View Modal */}
            {viewId && <BackupViewModal backupId={viewId} onClose={() => setViewId(null)} />}

            {/* New Backup Modal */}
            {showNew && <NewBackupModal onClose={() => setShowNew(false)} onSuccess={load} />}
        </div>
    );
};

export default BackupPage;