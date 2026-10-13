import React, { useEffect, useMemo, useState } from 'react';

import api from '../../config/api.js';
import { Pagination } from '../Logs/Pagination.jsx';
import AssetIcon from '../shared/AssetIcon.jsx';
import {
    RESTORE_STATUS_LABELS, formatDateTime, isRestorable, sourceLabel,
} from './restoreConstants.js';
import { t, sep } from "../../i18n";
import { ChangeBadge } from './ChangeBadge.jsx';

const formatDate = formatDateTime;

const SOURCE_FILTERS = ['all', 'changes', 'scheduled', 'manual', 'hardening', 'pre_restore'];

/**
 * Level two: the backups of a single asset.
 *
 * Fetched with ?asset_id= rather than filtered from the full list, so this
 * view is unaffected by how many backups the rest of the estate has.
 */
export const BackupAssetDetail = ({
    group, onBack, onView, onDelete, onRestore, onOpenRestore, onCompare, canRestore = false, refreshKey = 0,
}) => {
    // two backups ticked for "Compare selected"
    const [picked, setPicked] = useState([]);
    const togglePick = (id) => setPicked((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id].slice(-2)));
    const [backups, setBackups] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [sourceFilter, setSourceFilter] = useState('all');
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(25);
    const [restores, setRestores] = useState([]);

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
                    setError(e.response?.data?.detail || t("Failed to load backups"));
                }
            } finally {
                if (!cancelled) setLoading(false);
            }
        })();
        return () => { cancelled = true; };
    }, [group.asset_id, refreshKey]);

    // Recent restores of this asset. Failure here is not worth an error
    // state of its own: the backups list is what the page is for.
    useEffect(() => {
        let cancelled = false;
        (async () => {
            try {
                const params = new URLSearchParams({ asset_id: group.asset_id, limit: 10 });
                const res = await api.get(`/api/backups/restores?${params}`);
                if (!cancelled) setRestores(res.data || []);
            } catch {
                if (!cancelled) setRestores([]);
            }
        })();
        return () => { cancelled = true; };
    }, [group.asset_id, refreshKey]);

    const visible = useMemo(
        () => (sourceFilter === 'all'
            ? backups
            : sourceFilter === 'changes'
                ? backups.filter((b) => b.changed)
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
                    {t("All Assets")}
                </button>
                <div className="backup-detail-title">
                    <AssetIcon icon={group.icon} size={32} />
                    <span className="backup-asset-name">
                        {group.asset_name || t("Asset #{{asset_id}}", { asset_id: group.asset_id })}
                    </span>
                    <code className="backup-ip">{group.device_ip || '-'}</code>
                </div>
            </div>

            <div className="backup-filters">
                {SOURCE_FILTERS.map((s) => (
                    <button
                        key={s}
                        onClick={() => applySource(s)}
                        className={`backup-filter-btn ${sourceFilter === s ? 'active' : ''}`}
                    >
                        {s === 'all' ? t("All") : s === 'changes' ? t("Changes only") : sourceLabel(s)}
                    </button>
                ))}
            </div>

            {restores.length > 0 && (
                <div className="backup-restores">
                    <div className="backup-restores-title">{t("Restores")}</div>
                    {restores.map((r) => (
                        <div key={r.id} className="backup-restore-row">
                            <span className={`backup-restore-status ${r.status}`}>
                                {RESTORE_STATUS_LABELS[r.status] || r.status}
                            </span>
                            <span className="backup-restore-what">
                                {t("From backup #{{id}}", { id: r.backup_id ?? "-" })}
                                <span className="backup-restore-reason" title={r.reason}>{r.reason}</span>
                            </span>
                            <span className="backup-restore-meta">
                                {r.requested_by_username || '-'}{sep()}{formatDate(r.created_at)}
                            </span>
                            <button className="backup-restore-open" onClick={() => onOpenRestore(r.id)}>
                                {t("Details")}
                            </button>
                        </div>
                    ))}
                </div>
            )}

            {loading ? (
                <div className="backup-loading">
                    <div className="spinner-lg" />
                    <p>{t("Loading backups…")}</p>
                </div>
            ) : error ? (
                <div className="backup-empty"><p>{error}</p></div>
            ) : visible.length === 0 ? (
                <div className="backup-empty">
                    <p>{t("No backups match this filter.")}</p>
                </div>
            ) : (
                <>
                    {picked.length === 2 && (
                        <div className="bk-pick-bar">
                            <span>{t("Two backups selected")}</span>
                            <button type="button" className="bkm-btn bkm-btn-sm bkm-btn-primary"
                                    onClick={() => onCompare(picked[0], picked[1])}>{t("Compare selected")}</button>
                            <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => setPicked([])}>{t("Clear selection")}</button>
                        </div>
                    )}
                    <div className="table-container">
                        <table className="requirement-table">
                            <thead>
                                <tr>
                                    <th style={{ width: 36 }} aria-label={t("Select to compare")} />
                                    <th>{t("Date")}</th>
                                    <th>{t("Source")}</th>
                                    <th>{t("Change from the previous backup")}</th>
                                    <th>{t("Created By")}</th>
                                    <th>{t("Actions")}</th>
                                </tr>
                            </thead>
                            <tbody>
                                {paged.map((b) => (
                                    <tr key={b.id}>
                                        <td><input type="checkbox" checked={picked.includes(b.id)} onChange={() => togglePick(b.id)}
                                                   aria-label={t("Select to compare")} /></td>
                                        <td>{formatDate(b.created_at)}</td>
                                        <td>
                                            <span className={`backup-source-badge ${b.source}`}>
                                                {sourceLabel(b.source)}
                                            </span>
                                        </td>
                                        <td><ChangeBadge backup={b} /></td>
                                        <td>{b.created_by_username || (b.source === 'scheduled' ? t("Schedule") : '-')}</td>
                                        <td>
                                            <div className="backup-actions">
                                                <button
                                                    className="btn-see-result"
                                                    onClick={() => onView(b.id)}
                                                >
                                                    {t("View")}
                                                </button>
                                                {b.previous_backup_id && b.changed && (
                                                    <button className="btn-see-result" onClick={() => onCompare(b.previous_backup_id, b.id)}>
                                                        {t("What changed")}
                                                    </button>
                                                )}
                                                {canRestore && isRestorable(b.device_type) && (
                                                    <button
                                                        className="btn-restore"
                                                        onClick={() => onRestore(b.id)}
                                                    >
                                                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
                                                             stroke="currentColor" strokeWidth="2"
                                                             strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                                            <path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5" />
                                                        </svg>
                                                        {t("Restore")}
                                                    </button>
                                                )}
                                                <button
                                                    className="btn-delete-icon"
                                                    title={t("Delete backup")}
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
