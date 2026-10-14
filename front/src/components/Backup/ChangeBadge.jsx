/**
 * How a backup compares with the previous backup of its device: the first one, unchanged, or changed
 * (lines added and removed) outside NGCorion or by NGCorion itself (a hardening or restore). A backup
 * taken because the device reported the change over syslog also says who changed it and from where.
 */
import { n, t } from "../../i18n";
import { formatDateTime } from "./restoreConstants.js";

export function ReportedBy({ backup }) {
    if (!backup.reported_by && !backup.reported_from) return null;
    return (
        <span className="bkm-small bk-reported">
            {t("Changed by")} <bdi className="bk-reported-v">{backup.reported_by || t("unknown user")}</bdi>
            {" "}{t("from")} <bdi className="bk-reported-v">{backup.reported_from || t("unknown address")}</bdi>
        </span>
    );
}

export function ChangeBadge({ backup, compact = false }) {
    const o = backup.change_origin;
    if (!o) return compact ? null : <span className="bkm-muted">—</span>;
    if (o === "first") return <span className="bkm-pill bkm-pill-muted">{t("First backup")}</span>;
    if (o === "unchanged") {
        return (
            <span className="bk-change-wrap">
                <span className="bkm-pill bkm-pill-ok">{t("Unchanged")}</span>
                {!compact && backup.confirmed_at && (
                    <span className="bkm-small bkm-muted">{t("still the same on {{date}}", { date: formatDateTime(backup.confirmed_at) })}</span>
                )}
            </span>
        );
    }
    const external = o === "external";
    return (
        <span className="bk-change-wrap">
            <span className={`bkm-pill ${external ? "bkm-pill-orange" : "bkm-pill-run"}`}>
                {external ? t("Changed outside NGCorion") : t("Changed by NGCorion")}
            </span>
            {!compact && <ReportedBy backup={backup} />}
            {!compact && (
                <span className="ag-diff-count"><b className="ag-plus">+{n(backup.added_lines ?? 0)}</b> <b className="ag-minus">−{n(backup.removed_lines ?? 0)}</b></span>
            )}
            {!compact && backup.confirmed_at && (
                <span className="bkm-small bkm-muted">{t("still the same on {{date}}", { date: formatDateTime(backup.confirmed_at) })}</span>
            )}
        </span>
    );
}

export default ChangeBadge;
