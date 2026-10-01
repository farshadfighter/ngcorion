import { useEffect, useState } from "react";
import api from "../../config/api.js";
import { SEVERITY, epssColor, epssLabel, formatDate } from "./cveFormat.js";
import { Icon } from "./CveIcons.jsx";
import { t } from "../../i18n";

function range(p) {
    const parts = [];
    if (p.version && !["*", "-"].includes(p.version)) return p.version;
    if (p.start_incl) parts.push(`from ${p.start_incl}`);
    if (p.start_excl) parts.push(`after ${p.start_excl}`);
    if (p.end_excl) parts.push(`before ${p.end_excl}`);
    if (p.end_incl) parts.push(`up to ${p.end_incl}`);
    return parts.length ? parts.join(", ") : "all versions";
}

/** Side panel with one CVE from the local database. */
export function CveDetail({ cveId, finding, onClose }) {
    const [entry, setEntry] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        let alive = true;
        api.get(`/api/cve/entries/${encodeURIComponent(cveId)}`)
            .then(({ data }) => alive && setEntry(data))
            .catch((err) => alive && setError(err.response?.data?.detail || t("Could not load the CVE")));
        const onKey = (e) => e.key === "Escape" && onClose();
        window.addEventListener("keydown", onKey);
        return () => { alive = false; window.removeEventListener("keydown", onKey); };
    }, [cveId, onClose]);

    const sev = SEVERITY[entry?.severity] || SEVERITY.low;

    return (
        <div className="cvx-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="cvx-detail-title">
            <button type="button" className="cvx-drawer-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="cvx-drawer">
                <header className="cvx-drawer-head">
                    <div>
                        <h2 id="cvx-detail-title" className="cvx-mono">{cveId}</h2>
                        {entry && <div className="cvx-sub">{t("Published {{published}} · updated {{last_modified}}", { published: formatDate(entry.published), last_modified: formatDate(entry.last_modified) })}{entry.cwe ? ` · ${entry.cwe}` : ""}</div>}
                    </div>
                    <button type="button" className="cvx-icon-btn" aria-label={t("Close")} onClick={onClose}><Icon name="x" size={18} /></button>
                </header>
                <div className="cvx-drawer-body">
                    {error && <div className="cvx-note cvx-note-error">{error}</div>}
                    {!entry && !error && <div className="cvx-muted">{t("Loading…")}</div>}
                    {entry && (
                        <>
                            <div className="cvx-detail-badges">
                                {entry.cvss_score != null && (
                                    <span className="cvx-score" style={{ background: sev.bg, color: sev.fg }}>
                                        <b>{entry.cvss_score.toFixed(1)}</b> {t("{{label}} · CVSS {{cvss_version}}", { label: sev.label, cvss_version: entry.cvss_version })}
                                    </span>
                                )}
                                {entry.epss != null && (
                                    <span className="cvx-score" style={{ background: "#f1f5f9", color: epssColor(entry.epss) }}>
                                        <b>{epssLabel(entry.epss)}</b> {" "}{t("chance of exploitation (30 days)")}
                                    </span>
                                )}
                            </div>

                            {entry.kev && (
                                <div className="cvx-kev-box">
                                    <div className="cvx-kev-title"><Icon name="flame" size={16} /> {" "}{t("Exploited in the wild (CISA KEV)")}</div>
                                    <div>{t("Added {{kev_added}}", { kev_added: formatDate(entry.kev_added) })}{entry.kev_due ? t(" · US federal deadline {{kev_due}}", { kev_due: formatDate(entry.kev_due) }) : ""}{entry.kev_ransomware === "Known" ? t(" · used in ransomware campaigns") : ""}</div>
                                    {entry.kev_action && <div className="cvx-kev-action">{entry.kev_action}</div>}
                                </div>
                            )}

                            <p className="cvx-desc">{entry.description}</p>

                            {finding?.asset_name && (
                                <div className="cvx-summary-box">
                                    <div className="cvx-kv"><span>{t("Asset")}</span><b>{finding.asset_name}</b></div>
                                    <div className="cvx-kv"><span>{t("Product")}</span><b>{finding.product}</b></div>
                                    <div className="cvx-kv"><span>{t("Installed")}</span><b className="cvx-mono">{finding.installed || "?"}</b></div>
                                    <div className="cvx-kv"><span>{t("Fixed in")}</span><b className="cvx-mono cvx-good">{finding.fixed_in || t("see the advisory")}</b></div>
                                </div>
                            )}

                            {entry.cvss_vector && (
                                <>
                                    <h3 className="cvx-h3">{t("CVSS vector")}</h3>
                                    <div className="cvx-mono cvx-vector">{entry.cvss_vector}</div>
                                </>
                            )}

                            {entry.products.length > 0 && (
                                <>
                                    <h3 className="cvx-h3">{t("Affected products")}</h3>
                                    <ul className="cvx-affected">
                                        {entry.products.slice(0, 40).map((p, i) => (
                                            <li key={i}><span className="cvx-mono">{p.vendor}:{p.product}</span><span>{range(p)}</span></li>
                                        ))}
                                        {entry.products.length > 40 && <li className="cvx-muted">{t("…and {{value}} more", { value: entry.products.length - 40 })}</li>}
                                    </ul>
                                </>
                            )}

                            {entry.references.length > 0 && (
                                <>
                                    <h3 className="cvx-h3">{t("Advisories and references")}</h3>
                                    <ul className="cvx-refs">
                                        {entry.references.filter((u) => /^https?:\/\//i.test(u)).map((u) => (
                                            <li key={u}><a href={u} target="_blank" rel="noreferrer noopener">{u}<Icon name="external" size={13} /></a></li>
                                        ))}
                                    </ul>
                                </>
                            )}
                        </>
                    )}
                </div>
            </aside>
        </div>
    );
}
