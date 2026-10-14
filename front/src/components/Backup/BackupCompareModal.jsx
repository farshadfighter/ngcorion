/**
 * What changed between two backups of a device (GET /api/backups/compare): "+" lines are only in
 * the newer version, "-" lines only in the older one. Cisco IOS and FortiOS are compared as
 * configuration trees, so a new timestamp or byte count is not a change; server file bundles are
 * compared file by file.
 */
import { useEffect, useState } from "react";

import api from "../../config/api.js";
import { n, t } from "../../i18n";
import { errorText } from "../AssetGroups/groupFormat.js";
import { ChangeBadge, ReportedBy } from "./ChangeBadge.jsx";
import { formatDateTime, sourceLabel } from "./restoreConstants.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/AssetGroups.css";

export function BackupCompareModal({ oldId, newId, onClose }) {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        let alive = true;
        api.get("/api/backups/compare", { params: { old: oldId, new: newId } })
            .then(({ data: d }) => { if (alive) setData(d); })
            .catch((e) => { if (alive) setError(errorText(e, t("Could not compare the backups"))); });
        return () => { alive = false; };
    }, [oldId, newId]);

    const side = (b) => (
        <div className="bk-cmp-side">
            <b>{formatDateTime(b.created_at)}</b>
            <span>{sourceLabel(b.source)}{b.created_by_username ? ` · ${b.created_by_username}` : ""}</span>
        </div>
    );

    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="bk-cmp-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer bk-cmp-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="bk-cmp-title" dir="auto">{data ? (data.new.asset_name || data.new.device_ip) : t("Compare backups")}</h2>
                        {data && (
                            <span className="bkm-sub">
                                <span className="ag-diff-count"><b className="ag-plus">+{n(data.added)}</b> <b className="ag-minus">−{n(data.removed)}</b></span>
                                {" "}<ChangeBadge backup={data.new} compact />
                            </span>
                        )}
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                    {!data && !error && <p className="bkm-muted">{t("Loading…")}</p>}
                    {data && (
                        <>
                            <div className="bk-cmp-head">
                                <div><span className="bkm-small bkm-muted">{t("Older")}</span>{side(data.old)}</div>
                                <span className="bk-cmp-arrow" aria-hidden="true">→</span>
                                <div><span className="bkm-small bkm-muted">{t("Newer")}</span>{side(data.new)}</div>
                            </div>
                            {(data.new.reported_by || data.new.reported_from) && (
                                <div className="bkm-note bk-reported-note">
                                    <b>{t("The device reported this change over syslog")}</b>
                                    <ReportedBy backup={data.new} />
                                    {data.new.reported_at && <span className="bkm-small bkm-muted">{formatDateTime(data.new.reported_at)}</span>}
                                </div>
                            )}
                            {data.sections.length === 0 && (
                                <div className="bkm-empty"><b>{t("The two configurations are the same")}</b>
                                    <span>{t("Only capture details such as the timestamp differ.")}</span></div>
                            )}
                            {data.sections.map((sec, i) => (
                                <section key={i} className="bk-diff">
                                    <h3 className="bk-diff-title" dir="ltr">{sec.title}</h3>
                                    <pre className="bk-diff-body" dir="ltr">
                                        {sec.lines.map((l, j) => (
                                            <div key={j} className={l.op === "+" ? "bk-add" : l.op === "-" ? "bk-del" : "bk-ctx"}>
                                                <span className="bk-op">{l.op === " " ? "" : l.op}</span>{l.text}
                                            </div>
                                        ))}
                                    </pre>
                                </section>
                            ))}
                            {data.truncated && <p className="bkm-note bkm-note-orange">{t("Only the first part of a very large difference is shown.")}</p>}
                        </>
                    )}
                </div>
            </aside>
        </div>
    );
}

export default BackupCompareModal;
