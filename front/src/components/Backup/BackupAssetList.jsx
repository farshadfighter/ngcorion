import React from 'react';

import { Pagination } from '../Logs/Pagination.jsx';
import AssetIcon from '../shared/AssetIcon.jsx';
import { t as tr, uiLocale } from "../../i18n";

const formatDate = (ts) => {
    if (!ts) return '-';
    return new Date(ts).toLocaleString(uiLocale(),  {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: '2-digit', minute: '2-digit', hour12: false,
    });
};

const typeLabel = (t) =>
    !t || t === 'unknown' ? tr("Unknown") : t.charAt(0).toUpperCase() + t.slice(1);

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
                <p>{tr("No backups match this view.")}</p>
            </div>
        );
    }

    return (
        <>
            <div className="table-container">
                <table className="requirement-table backup-asset-table">
                    <thead>
                        <tr>
                            <th>{tr("Asset")}</th>
                            <th>{tr("IP Address")}</th>
                            <th>{tr("Device Type")}</th>
                            <th>{tr("Backups")}</th>
                            <th>{tr("Last Backup")}</th>
                            <th>{tr("Actions")}</th>
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
                                    <span className="backup-asset-name-cell">
                                        <AssetIcon icon={g.icon} size={28} />
                                        <span className="backup-asset-name">
                                            {g.asset_name || tr("Asset #{{asset_id}}", { asset_id: g.asset_id })}
                                        </span>
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
                                                {tr("{{manual_count}} manual", { manual_count: g.manual_count })}
                                            </span>
                                        )}
                                        {g.hardening_count > 0 && (
                                            <span className="backup-source-badge hardening">
                                                {tr("{{hardening_count}} hardening", { hardening_count: g.hardening_count })}
                                            </span>
                                        )}
                                        {g.pre_restore_count > 0 && (
                                            <span className="backup-source-badge pre_restore">
                                                {tr("{{pre_restore_count}} before restore", { pre_restore_count: g.pre_restore_count })}
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
                                        {tr("View Backups")}
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
