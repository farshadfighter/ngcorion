import React from 'react';

import { Pagination } from '../Logs/Pagination.jsx';

const formatDate = (ts) => {
    if (!ts) return '-';
    return new Date(ts).toLocaleString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: '2-digit', minute: '2-digit', hour12: false,
    });
};

const typeLabel = (t) =>
    !t || t === 'unknown' ? 'Unknown' : t.charAt(0).toUpperCase() + t.slice(1);

/**
 * Level one of the backup screen: one row per asset that has backups.
 *
 * The flat list this replaced put every backup of every asset in a single
 * table, which does not survive a few hundred assets. Counts come from the
 * backend's grouped query, so the numbers stay right however many rows exist.
 */
export const BackupAssetList = ({
    groups,
    page,
    pageSize,
    onPageChange,
    onPageSizeChange,
    onOpenAsset,
}) => {
    // Clamped while rendering: a filter change can leave `page` past the end.
    const safePage = Math.min(
        page,
        Math.max(1, Math.ceil(groups.length / pageSize))
    );
    const paged = groups.slice((safePage - 1) * pageSize, safePage * pageSize);

    if (groups.length === 0) {
        return (
            <div className="backup-empty">
                <p>No backups match this view.</p>
            </div>
        );
    }

    return (
        <>
            <div className="table-container">
                <table className="requirement-table backup-asset-table">
                    <thead>
                        <tr>
                            <th>Asset</th>
                            <th>IP Address</th>
                            <th>Device Type</th>
                            <th>Backups</th>
                            <th>Last Backup</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {paged.map((g) => (
                            <tr
                                key={g.asset_id}
                                className="backup-asset-row"
                                onClick={() => onOpenAsset(g)}
                            >
                                <td>
                                    <span className="backup-asset-name">
                                        {g.asset_name || `Asset #${g.asset_id}`}
                                    </span>
                                </td>
                                <td>
                                    <code className="backup-ip">{g.device_ip || '-'}</code>
                                </td>
                                <td>
                                    <span
                                        className={`backup-type backup-type-${
                                            (g.device_type || 'unknown').toLowerCase()
                                        }`}
                                    >
                                        {typeLabel(g.device_type)}
                                    </span>
                                </td>
                                <td>
                                    <span className="backup-count-total">
                                        {g.backup_count}
                                    </span>
                                    <span className="backup-count-split">
                                        {g.manual_count > 0 && (
                                            <span className="backup-source-badge manual">
                                                {g.manual_count} manual
                                            </span>
                                        )}
                                        {g.hardening_count > 0 && (
                                            <span className="backup-source-badge hardening">
                                                {g.hardening_count} hardening
                                            </span>
                                        )}
                                    </span>
                                </td>
                                <td>{formatDate(g.last_backup_at)}</td>
                                <td>
                                    <button
                                        className="btn-see-result"
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onOpenAsset(g);
                                        }}
                                    >
                                        View Backups
                                        <svg width="14" height="14" viewBox="0 0 24 24"
                                             fill="none" stroke="currentColor" strokeWidth="2.5"
                                             strokeLinecap="round" strokeLinejoin="round">
                                            <path d="M9 18l6-6-6-6" />
                                        </svg>
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            <Pagination
                page={safePage}
                pageSize={pageSize}
                totalItems={groups.length}
                onPageChange={onPageChange}
                onPageSizeChange={onPageSizeChange}
            />
        </>
    );
};

export default BackupAssetList;
