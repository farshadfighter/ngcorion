import React, { useEffect, useMemo, useState } from 'react';

import api from '../../config/api.js';
import { Pagination } from '../Logs/Pagination.jsx';

const formatDate = (ts) => {
    if (!ts) return '-';
    return new Date(ts).toLocaleString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: '2-digit', minute: '2-digit', hour12: false,
    });
};

/**
 * Level two: the backups of a single asset.
 *
 * Fetched with ?asset_id= rather than filtered from the full list, so this
 * view is unaffected by how many backups the rest of the estate has.
 */
export const BackupAssetDetail = ({ group, onBack, onView, onDelete }) => {
    const [backups, setBackups] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [sourceFilter, setSourceFilter] = useState('all');
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(25);

    // The effect owns the fetch so state is only set from inside it.
    useEffect(() => {
        let cancelled = false;
        (async () => {
            setLoading(true);
            setError(null);
            try {
                const params = new URLSearchParams({
                    asset_id: group.asset_id,
                    limit: 500,
                });
                const res = await api.get(`/api/backups/?${params}`);
                if (!cancelled) setBackups(res.data || []);
            } catch (e) {
                if (!cancelled) {
                    setError(e.response?.data?.detail || 'Failed to load backups');
                }
            } finally {
                if (!cancelled) setLoading(false);
            }
        })();
        return () => { cancelled = true; };
    }, [group.asset_id]);

    const visible = useMemo(
        () => (sourceFilter === 'all'
            ? backups
            : backups.filter((b) => b.source === sourceFilter)),
        [backups, sourceFilter]
    );

    // Filtering can leave `page` past the end of the new result set. Clamping
    // while rendering avoids an effect that would set state and re-render.
    const safePage = Math.min(
        page,
        Math.max(1, Math.ceil(visible.length / pageSize))
    );

    const paged = useMemo(
        () => visible.slice((safePage - 1) * pageSize, safePage * pageSize),
        [visible, safePage, pageSize]
    );

    const applySource = (value) => {
        setSourceFilter(value);
        setPage(1);
    };

    // Keeps the row out of the list without a refetch after a delete.
    const removeLocal = (id) => setBackups((prev) => prev.filter((b) => b.id !== id));

    return (
        <>
            <div className="backup-detail-head">
                <button className="backup-back-btn" onClick={onBack}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                         stroke="currentColor" strokeWidth="2.5"
                         strokeLinecap="round" strokeLinejoin="round">
                        <path d="M15 18l-6-6 6-6" />
                    </svg>
                    All Assets
                </button>
                <div className="backup-detail-title">
                    <span className="backup-asset-name">
                        {group.asset_name || `Asset #${group.asset_id}`}
                    </span>
                    <code className="backup-ip">{group.device_ip || '-'}</code>
                </div>
            </div>

            <div className="backup-filters">
                {['all', 'manual', 'hardening'].map((s) => (
                    <button
                        key={s}
                        onClick={() => applySource(s)}
                        className={`backup-filter-btn ${sourceFilter === s ? 'active' : ''}`}
                    >
                        {s === 'all' ? 'All' : s.charAt(0).toUpperCase() + s.slice(1)}
                    </button>
                ))}
            </div>

            {loading ? (
                <div className="backup-loading">
                    <div className="spinner-lg" />
                    <p>Loading backups…</p>
                </div>
            ) : error ? (
                <div className="backup-empty"><p>{error}</p></div>
            ) : visible.length === 0 ? (
                <div className="backup-empty">
                    <p>No backups match this filter.</p>
                </div>
            ) : (
                <>
                    <div className="table-container">
                        <table className="requirement-table">
                            <thead>
                                <tr>
                                    <th>Date</th>
                                    <th>Source</th>
                                    <th>Created By</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {paged.map((b) => (
                                    <tr key={b.id}>
                                        <td>{formatDate(b.created_at)}</td>
                                        <td>
                                            <span className={`backup-source-badge ${b.source}`}>
                                                {b.source}
                                            </span>
                                        </td>
                                        <td>{b.created_by_username || '-'}</td>
                                        <td>
                                            <div className="backup-actions">
                                                <button
                                                    className="btn-see-result"
                                                    onClick={() => onView(b.id)}
                                                >
                                                    View
                                                </button>
                                                <button
                                                    className="btn-delete-icon"
                                                    title="Delete backup"
                                                    onClick={() => onDelete(b.id, removeLocal)}
                                                >
                                                    <svg width="16" height="16" viewBox="0 0 24 24"
                                                         fill="none" stroke="currentColor" strokeWidth="2">
                                                        <path d="M3 6h18M8 6V4a1 1 0 011-1h6a1 1 0 011 1v2m2 0v14a1 1 0 01-1 1H7a1 1 0 01-1-1V6" />
                                                    </svg>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    <Pagination
                        page={safePage}
                        pageSize={pageSize}
                        totalItems={visible.length}
                        onPageChange={setPage}
                        onPageSizeChange={(size) => { setPageSize(size); setPage(1); }}
                    />
                </>
            )}
        </>
    );
};

export default BackupAssetDetail;
