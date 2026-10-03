import React, { useCallback, useEffect, useState } from "react";
import { useSelector } from "react-redux";
import AssetIcon from "../shared/AssetIcon.jsx";
import api from "../../config/api.js";
import { usePermission } from "../../hooks/usePermission";
import { t, n } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { formatDate } from "../../utils/dates";
import { AssetSoftwareDrawer } from "../Software/AssetSoftwareDrawer.jsx";
import { COLLECTOR, SEVERITY } from "../Software/softwareFormat.js";
import "../../assets/Software.css";

/** Asset list, Software tab: what each asset has installed, from its latest collection. */
export const SoftwareTab = ({ assets, isNewAsset, selectedIds, onToggleSelect, onToggleAll, allSelected }) => {
    const canWrite = usePermission("asset_list", "write");
    const { role } = useSelector((state) => state.auth);
    const [byAsset, setByAsset] = useState(null);
    const [openId, setOpenId] = useState(null);
    const [reload, setReload] = useState(0);
    const refresh = useCallback(() => setReload((x) => x + 1), []);

    useEffect(() => {
        let alive = true;
        api.get("/api/software/assets")
            .then(({ data }) => alive && setByAsset(Object.fromEntries(data.map((r) => [r.asset_id, r]))))
            .catch(() => alive && setByAsset({}));
        return () => { alive = false; };
    }, [reload]);

    const rows = Array.isArray(assets) ? assets : [];

    return (
        <>
            <div className="asset-table-container">
                <table className="assets-table">
                    <thead>
                    <tr>
                        <th style={{ width: "40px" }}>
                            <input type="checkbox" checked={allSelected} onChange={onToggleAll}
                                   title={t("Select all")} style={{ cursor: "pointer", accentColor: "#1e3a5f" }} />
                        </th>
                        <th>{t("Number")}</th>
                        <th>{t("Asset Name")}</th>
                        <th>{t("Installed")}</th>
                        <th>{t("Outside the distribution")}</th>
                        <th>{t("Vulnerabilities")}</th>
                        <th>{t("Unidentified")}</th>
                        <th>{t("Last collected")}</th>
                        <th>{t("Actions")}</th>
                    </tr>
                    </thead>
                    <tbody>
                    {rows.map((asset, index) => {
                        const s = byAsset?.[asset.id];
                        const last = s?.last;
                        const single = s && !s.packages && (s.firmware || s.os);
                        return (
                            <tr key={asset.id}
                                className={`${isNewAsset(asset) ? "new-asset-row" : ""} ${selectedIds.has(asset.id) ? "selected-row" : ""}`}
                                style={{ background: selectedIds.has(asset.id) ? "#eef2f7" : undefined }}>
                                <td>
                                    <input type="checkbox" checked={selectedIds.has(asset.id)} onChange={() => onToggleSelect(asset.id)}
                                           style={{ cursor: "pointer", accentColor: "#1e3a5f" }} />
                                </td>
                                <td>{n(index + 1)}</td>
                                <td>
                                    <span className="asset-name-cell">
                                        <AssetIcon icon={asset.resolved_icon} size={28} />
                                        {asset.asset_name}
                                    </span>
                                </td>
                                <td>
                                    {!byAsset ? "…" : !s ? <span style={{ color: "#6b7280" }}>{t("No list yet")}</span>
                                        : single ? <span className="sw-ver">{s.firmware || s.os}</span>
                                            : <>
                                                {t("{{count}} packages", { count: s.packages })}
                                                {s.hotfixes > 0 && <span className="bkm-sub">{t("{{count}} Windows updates", { count: s.hotfixes })}</span>}
                                            </>}
                                </td>
                                <td>{s && s.packages ? n(s.outside_distro) : "-"}</td>
                                <td>
                                    {s?.cves ? (
                                        <span>
                                            <span className={`sw-sev ${SEVERITY.high.cls}`}>{t("{{count}} CVEs", { count: s.cves })}</span>
                                            {s.kev && <span className="sw-kev">KEV</span>}
                                        </span>
                                    ) : s ? <span style={{ color: "#6b7280" }}>{t("None known")}</span> : "-"}
                                </td>
                                <td>{s?.unidentified ? <span style={{ color: "#a16207", fontWeight: 600 }}>{n(s.unidentified)}</span> : s ? n(0) : "-"}</td>
                                <td>
                                    {last ? <>{formatDate(last.collected_at)}<span className="bkm-sub">{COLLECTOR[last.collector] || last.collector}</span></>
                                        : s?.last_failed ? <span style={{ color: "#b91c1c" }} title={tb(s.last_failed.error || "")}>{t("Failed")}</span> : "-"}
                                </td>
                                <td className="actions-cell">
                                    <button className="btn-icon" title={t("View software")} aria-label={t("View software")}
                                            onClick={() => setOpenId(asset.id)}>
                                        <i className="fa-solid fa-box-open"></i>
                                    </button>
                                </td>
                            </tr>
                        );
                    })}
                    </tbody>
                </table>
            </div>
            {openId && <AssetSoftwareDrawer key={openId} assetId={openId} canWrite={canWrite}
                                            canMap={role === "admin" || role === "manager"}
                                            onClose={() => setOpenId(null)} onChanged={refresh} />}
        </>
    );
};
