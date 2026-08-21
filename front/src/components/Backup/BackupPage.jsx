import React, { useEffect, useState, useCallback, useMemo } from 'react';
import api from '../../config/api.js';
import BackupViewModal from './BackupViewModal.jsx';
import NewBackupModal from './NewBackupModal.jsx';
import { BackupAssetList } from './BackupAssetList.jsx';
import { BackupAssetDetail } from './BackupAssetDetail.jsx';
import '../../assets/Backup.css';
import '../../assets/LogsPage.css';
import '../../assets/AssetRequirement.css';

/**
 * Configuration Backup, in two levels.
 *
 * Level one lists the assets that have backups; level two shows one asset's
 * backups. The flat "every backup of every device in one table" layout it
 * replaced became unusable past a few hundred assets, and its device-type tabs
 * only filtered the same long list rather than shortening it.
 */
export const BackupPage = () => {
    const [groups, setGroups] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [typeFilter, setTypeFilter] = useState('all');
    const [search, setSearch] = useState('');
    const [selected, setSelected] = useState(null);
    const [viewId, setViewId] = useState(null);
    const [showNew, setShowNew] = useState(false);
    const [deleteId, setDeleteId] = useState(null);
    const [deleting, setDeleting] = useState(false);
    const [afterDelete, setAfterDelete] = useState(null);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(25);

    // Grouped server-side: counting client-side would be wrong past the list
    // endpoint's 500-row ceiling.
    // `reload` is a counter rather than a callback so the effect owns the
    // fetch — calling a loader straight from an effect body sets state
    // synchronously and cascades renders.
    const [reload, setReload] = useState(0);
    const load = useCallback(() => setReload((n) => n + 1), []);

    useEffect(() => {
        let cancelled = false;
        (async () => {
            setLoading(true);
            setError(null);
            try {
                const res = await api.get('/api/backups/by-asset');
                if (!cancelled) setGroups(res.data || []);
            } catch (e) {
                if (!cancelled) {
                    setError(e.response?.data?.detail || 'Failed to load backups');
                }
            } finally {
                if (!cancelled) setLoading(false);
            }
        })();
        return () => { cancelled = true; };
    }, [reload]);

    const deviceTypes = useMemo(() => {
        const counts = {};
        groups.forEach((g) => {
            const t = (g.device_type || 'unknown').toLowerCase();
            counts[t] = (counts[t] || 0) + 1;
        });
        return Object.entries(counts).sort((a, b) => b[1] - a[1]);
    }, [groups]);

    const visibleGroups = useMemo(() => {
        const term = search.trim().toLowerCase();
        return groups.filter((g) => {
            const type = (g.device_type || 'unknown').toLowerCase();
            if (typeFilter !== 'all' && type !== typeFilter) return false;
            if (!term) return true;
            return (
                String(g.asset_name || '').toLowerCase().includes(term) ||
                String(g.device_ip || '').toLowerCase().includes(term)
            );
        });
    }, [groups, typeFilter, search]);

    const typeLabel = (t) =>
        t === 'unknown' ? 'Unknown' : t.charAt(0).toUpperCase() + t.slice(1);

    // A new filter is a new result set, so start reading it from the top.
    const applyTypeFilter = (value) => {
        setTypeFilter(value);
        setPage(1);
    };

    const applySearch = (value) => {
        setSearch(value);
        setPage(1);
    };

    /* The detail view passes a callback so its own list updates too. */
    const requestDelete = (id, onRemoved) => {
        setDeleteId(id);
        setAfterDelete(() => onRemoved || null);
    };

    const handleDelete = async (id) => {
        setDeleting(true);
        try {
            await api.delete(`/api/backups/${id}`);
            if (afterDelete) afterDelete(id);
            setDeleteId(null);
            setAfterDelete(null);
            // Counts on the asset list came from the server, so refresh them.
            load();
        } catch (e) {
            alert(e.response?.data?.detail || 'Delete failed');
        } finally {
            setDeleting(false);
        }
    };

    const handleNewBackupSuccess = () => {
        setShowNew(false);
        load();
    };

    return (
        <div className="backup-container">
            <div className="backup-header">
                <h1 className="page-title">Backup</h1>
                <button className="btn-header" onClick={() => setShowNew(true)}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                         stroke="currentColor" strokeWidth="2">
                        <path d="M12 5v14M5 12h14" />
                    </svg>
                    New Backup
                </button>
            </div>

            {selected ? (
                <BackupAssetDetail
                    group={selected}
                    onBack={() => setSelected(null)}
                    onView={setViewId}
                    onDelete={requestDelete}
                />
            ) : loading ? (
                <div className="backup-loading">
                    <div className="spinner-lg" />
                    <p>Loading backups…</p>
                </div>
            ) : error ? (
                <div className="backup-empty"><p>{error}</p></div>
            ) : (
                <>
                    <div className="backup-filters backup-type-tabs">
                        <button
                            onClick={() => applyTypeFilter('all')}
                            className={`backup-filter-btn ${typeFilter === 'all' ? 'active' : ''}`}
                        >
                            All Devices <span className="backup-tab-count">{groups.length}</span>
                        </button>
                        {deviceTypes.map(([t, count]) => (
                            <button
                                key={t}
                                onClick={() => applyTypeFilter(t)}
                                className={`backup-filter-btn ${typeFilter === t ? 'active' : ''}`}
                            >
                                {typeLabel(t)} <span className="backup-tab-count">{count}</span>
                            </button>
                        ))}
                    </div>

                    <div className="backup-search">
                        <input
                            type="text"
                            value={search}
                            onChange={(e) => applySearch(e.target.value)}
                            placeholder="Search by asset name or IP…"
                        />
                    </div>

                    <BackupAssetList
                        groups={visibleGroups}
                        page={page}
                        pageSize={pageSize}
                        onPageChange={setPage}
                        onPageSizeChange={(size) => { setPageSize(size); setPage(1); }}
                        onOpenAsset={setSelected}
                    />
                </>
            )}

            {deleteId && (
                <div className="modal-overlay" onClick={() => setDeleteId(null)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Delete Backup</h3>
                            <button className="modal-close" onClick={() => setDeleteId(null)}>×</button>
                        </div>
                        <div className="modal-body">
                            <p>Are you sure you want to delete this backup?</p>
                            <p style={{ color: '#dc2626', fontSize: 13 }}>
                                This action cannot be undone.
                            </p>
                        </div>
                        <div className="modal-actions">
                            <button className="btn-cancel" onClick={() => setDeleteId(null)}
                                    disabled={deleting}>
                                Cancel
                            </button>
                            <button className="btn-delete2" onClick={() => handleDelete(deleteId)}
                                    disabled={deleting}>
                                {deleting ? 'Deleting…' : 'Delete'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {viewId && (
                <BackupViewModal backupId={viewId} onClose={() => setViewId(null)} />
            )}

            {showNew && (
                <NewBackupModal
                    onClose={() => setShowNew(false)}
                    onSuccess={handleNewBackupSuccess}
                />
            )}
        </div>
    );
};

export default BackupPage;
