import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../../config/api.js";
import { isRtl, t, n } from "../../i18n";
import { relativeDays } from "../../utils/dates.js";
import { PRIORITY } from "../CVE/cveFormat.js";
import { SEVERITY } from "./softwareFormat.js";

const SHOW = 8;

const STATUS_TEXT = {
    unknown: () => t("The Linux release of this asset is not recorded yet. It is read at the next audit or “Collect now”; then its packages are checked against the distribution's advisories."),
    unsupported: (d) => t("{{platform}} has no security advisories NGCorion can read (Ubuntu, Debian, Red Hat, Rocky Linux and AlmaLinux are covered). Its distribution packages are not checked.", { platform: d.label || d.platform || "—" }),
    not_loaded: (d) => t("The security advisories of {{release}} are not loaded yet. They are downloaded automatically within the hour, or from CVE › Database.", { release: d.label }),
};

/** The distribution's security updates this asset is missing: what to install, what it closes, and how. */
export function SecurityUpdates({ assetId, reload }) {
    const [data, setData] = useState(null);
    const [all, setAll] = useState(false);
    const [copied, setCopied] = useState(false);

    useEffect(() => {
        let alive = true;
        api.get(`/api/software/assets/${assetId}/updates`)
            .then(({ data: d }) => alive && setData(d))
            .catch(() => alive && setData(null));
        return () => { alive = false; };
    }, [assetId, reload]);

    if (!data || data.status === "no_inventory") return null;
    if (data.status !== "ok") {
        return (
            <section className="sw-panel su-panel">
                <h3 className="bkm-h3">{t("Security updates")}</h3>
                <p className="alr-hint">{(STATUS_TEXT[data.status] || STATUS_TEXT.unknown)(data)}</p>
                {data.status === "not_loaded" && <Link className="bkm-link" to="/cve/database">{t("CVE › Database")}</Link>}
            </section>
        );
    }
    const s = data.summary;
    const updates = all ? data.updates : data.updates.slice(0, SHOW);
    const arrow = isRtl() ? "←" : "→";
    const copy = () => {
        navigator.clipboard?.writeText(data.commands.join("\n")).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1800);
        }).catch(() => {});
    };

    return (
        <section className="sw-panel su-panel">
            <div className="bkm-row-between">
                <div>
                    <h3 className="bkm-h3">{t("Security updates")}</h3>
                    <span className="bkm-sub">
                        <span className="sw-ltr-inline">{data.platform || data.label}</span>
                        {data.feed?.updated_at && <> · {t("advisories updated {{when}}", { when: relativeDays(data.feed.updated_at) })}</>}
                    </span>
                </div>
            </div>

            <div className="su-stats">
                <div className={s.packages ? "is-bad" : "is-ok"}><b>{n(s.packages)}</b><span>{t("packages with a security fix")}</span></div>
                <div className={s.cves ? "is-bad" : ""}><b>{n(s.cves)}</b><span>{t("CVEs these updates close")}</span></div>
                <div className={s.kev ? "is-bad" : ""}><b>{n(s.kev)}</b><span>{t("exploited in the wild (KEV)")}</span></div>
                <div><b>{n(s.unfixed)}</b><span>{t("CVEs with no fix from the distribution yet")}</span></div>
            </div>

            {data.reboot_required && (
                <div className="bkm-note bkm-note-orange su-reboot" role="status">
                    <b>{t("Reboot needed")}</b>{" "}
                    {data.running_kernel && data.newest_kernel
                        ? t("The running kernel is {{running}}, but {{newest}} is installed. Kernel fixes count as open until the server restarts.", { running: data.running_kernel, newest: data.newest_kernel })
                        : t("Updated packages wait for a restart.")}
                </div>
            )}

            {data.updates.length === 0 ? (
                <p className="alr-hint">{t("Every distribution package has its latest security fix.")}</p>
            ) : (
                <div className="bkm-table-wrap">
                    <table className="bkm-table sw-table su-table">
                        <thead><tr>
                            <th style={{ width: 74 }}>{t("Priority")}</th><th>{t("Package")}</th><th>{t("Installed and fixed version")}</th>
                            <th>{t("Advisory")}</th><th>{t("CVEs")}</th><th>{t("Fix")}</th>
                        </tr></thead>
                        <tbody>
                            {updates.map((u) => {
                                const p = PRIORITY[u.priority] || PRIORITY[4];
                                return (
                                    <tr key={u.package}>
                                        <td><span className="su-prio" style={{ background: p.bg, color: p.fg }} title={p.hint}>{p.label}</span></td>
                                        <td>
                                            <b className="sw-ltr-inline">{u.package}</b>{u.kernel && <span className="su-tag">{t("kernel")}</span>}
                                            <span className="bkm-sub sw-ltr-inline su-clip" title={u.binaries.join(", ")}>
                                                {u.binaries.length > 3 ? `${u.binaries.slice(0, 3).join(", ")} +${u.binaries.length - 3}` : u.binaries.join(", ")}
                                            </span>
                                        </td>
                                        <td>
                                            <span className="sw-vers-change">
                                                <span className="sw-ver" title={u.installed}>{u.installed}</span>
                                                <span aria-hidden="true">{arrow}</span>
                                                <span className="sw-ver su-fixed" title={u.fixed_in}>{u.fixed_in}</span>
                                            </span>
                                        </td>
                                        <td>{u.advisories.length ? u.advisories.slice(0, 2).map((a) => <span key={a} className="su-adv">{a}</span>) : "—"}
                                            {u.advisories.length > 2 && <span className="bkm-sub">+{n(u.advisories.length - 2)}</span>}</td>
                                        <td>
                                            <span className={`sw-sev ${SEVERITY[u.severity]?.cls || ""}`}>{t("{{count}} CVEs", { count: u.cves.length })}</span>
                                            {u.kev && <span className="sw-kev">KEV</span>}
                                            <span className="su-cves">
                                                {u.cves.slice(0, 2).map((c) => <span key={c.cve_id} className={`su-cve ${c.kev ? "is-kev" : ""}`}>{c.cve_id}</span>)}
                                                {u.cves.length > 2 && <span className="bkm-sub">+{n(u.cves.length - 2)}</span>}
                                            </span>
                                        </td>
                                        <td>
                                            {u.reboot
                                                ? <span className="bkm-pill bkm-pill-amber">{t("Installed; reboot needed")}</span>
                                                : u.availability === "pro"
                                                    ? <span className="bkm-pill su-pro" title={t("The fix is published only in Ubuntu Pro (ESM): attach the server to a Pro subscription to install it.")}>{t("Ubuntu Pro only")}</span>
                                                    : <span className="bkm-pill bkm-pill-ok">{t("Standard repository")}</span>}
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            )}
            {data.updates.length > SHOW && (
                <button type="button" className="bkm-link" onClick={() => setAll(!all)}>
                    {all ? t("Show fewer") : t("Show all {{count}} packages", { count: data.updates.length })}
                </button>
            )}

            {data.commands.length > 0 && (
                <div className="su-cmd-wrap">
                    <div className="bkm-row-between">
                        <h4 className="sw-h4">{t("Commands to install them")}</h4>
                        <button type="button" className="bkm-btn bkm-btn-sm" onClick={copy}>{copied ? t("Copied") : t("Copy")}</button>
                    </div>
                    <pre className="su-cmd" dir="ltr">{data.commands.join("\n")}</pre>
                    <p className="alr-hint">{t("For you to run. NGCorion does not install anything on the server.")}{s.pro_only > 0 && <> {t("Packages fixed only in Ubuntu Pro are left out: run “sudo pro attach” with a subscription token first.")}</>}</p>
                </div>
            )}

            {data.unfixed.length > 0 && (
                <details className="su-unfixed">
                    <summary>{t("CVEs the distribution has not fixed yet ({{count}})", { count: s.unfixed })}</summary>
                    <p className="alr-hint">{t("There is nothing to install for these, so they are not counted in the risk score or the remediation list. They move to the table above when the distribution publishes a fix. Kernel CVEs without a fix are not listed.")}</p>
                    <div className="bkm-table-wrap su-unfixed-list">
                        <table className="bkm-table sw-table">
                            <thead><tr><th>{t("CVE")}</th><th>{t("Package")}</th><th>{t("Severity")}</th></tr></thead>
                            <tbody>
                                {data.unfixed.slice(0, 200).map((u) => (
                                    <tr key={`${u.package}-${u.cve_id}`}>
                                        <td><span className="sw-ltr-inline bkm-mono">{u.cve_id}</span></td>
                                        <td><span className="sw-ltr-inline">{u.package}</span></td>
                                        <td><span className={`sw-sev ${SEVERITY[u.severity]?.cls || ""}`}>{SEVERITY[u.severity]?.label || "—"}</span></td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </details>
            )}
        </section>
    );
}
