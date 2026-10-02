import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import api from "../../config/api.js";
import { usePermission } from "../../hooks/usePermission";
import { t, n } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { formatDate, formatWhen } from "../../utils/dates.js";
import { STATUS, download } from "./reportFormat.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/Reports.css";

/** Every report template, grouped by module, with the last few reports on top. */
export function ReportsCatalog() {
    const canWrite = usePermission("reports", "write");
    const navigate = useNavigate();
    const [data, setData] = useState(null);
    const [group, setGroup] = useState("");
    const [query, setQuery] = useState("");
    const [error, setError] = useState(null);

    useEffect(() => {
        api.get("/api/reports/catalog")
            .then(({ data: d }) => setData(d))
            .catch(() => setError(t("Could not load the reports")));
    }, []);

    const templates = (data?.templates || []).filter((tpl) => {
        if (group && tpl.group !== group) return false;
        const q = query.trim().toLowerCase();
        return !q || tb(tpl.title).toLowerCase().includes(q) || tb(tpl.description).toLowerCase().includes(q);
    });
    const count = (g) => (data?.templates || []).filter((tpl) => tpl.group === g).length;

    return (
        <div className="bkm-page">
            <div className="bkm-head rep-head">
                <div>
                    <h1>{t("Reports")}</h1>
                    <p>{t("Each report starts from a ready template. You choose the period, the assets, the sections, the language and the file format.")}</p>
                </div>
                <div className="bkm-actions">
                    <Link className="bkm-btn" to="/reports/archive">{t("Archive")}</Link>
                    <Link className="bkm-btn" to="/reports/schedules">{t("Schedules")}</Link>
                </div>
            </div>

            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}

            {data?.recent?.length > 0 && (
                <div className="rep-recent" aria-label={t("Latest reports")}>
                    {data.recent.map((r) => (
                        <div key={r.id} className="rep-rc">
                            <div>
                                <b title={r.title}>{r.title}</b>
                                <span className="bkm-sub">
                                    {r.schedule ? t("Scheduled") : r.created_by} · {formatWhen(r.created_at)}
                                    {r.page_count ? ` · ${t("{{count}} pages", { count: r.page_count })}` : ""}
                                </span>
                            </div>
                            {r.status === "ready"
                                ? <div className="bkm-actions">{r.files.map((f) => (
                                    <button key={f.kind} type="button" className="bkm-btn bkm-btn-sm"
                                            onClick={() => download(r, f.kind)}>{f.kind === "pdf" ? "PDF" : "Excel"}</button>
                                ))}</div>
                                : <span className={`bkm-pill ${STATUS[r.status]?.pill}`}>{STATUS[r.status]?.label}</span>}
                        </div>
                    ))}
                </div>
            )}

            <div className="bkm-toolbar">
                <div className="bkm-chips" role="group" aria-label={t("Filter reports")}>
                    <button type="button" aria-pressed={!group} className={`bkm-chip ${!group ? "is-on" : ""}`}
                            onClick={() => setGroup("")}>{t("All")} <b>{n(data?.templates?.length || 0)}</b></button>
                    {(data?.groups || []).filter((g) => count(g.id)).map((g) => (
                        <button key={g.id} type="button" aria-pressed={group === g.id}
                                className={`bkm-chip ${group === g.id ? "is-on" : ""}`} onClick={() => setGroup(g.id)}>
                            {tb(g.title)} <b>{n(count(g.id))}</b>
                        </button>
                    ))}
                </div>
                <label className="bkm-search">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
                    <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("Search reports…")} aria-label={t("Search reports")} />
                </label>
            </div>

            {(data?.groups || []).map((g) => {
                const list = templates.filter((tpl) => tpl.group === g.id);
                if (!list.length) return null;
                return (
                    <section key={g.id} className="rep-group">
                        <h2>{tb(g.title)}</h2>
                        <div className="rep-cards">
                            {list.map((tpl) => (
                                <article key={tpl.id} className={`rep-card ${tpl.available ? "" : "is-planned"}`}>
                                    <div className="bkm-row-between">
                                        <h3>{tb(tpl.title)}</h3>
                                        {!tpl.available && <span className="rep-soon">{t("Coming later")}</span>}
                                    </div>
                                    <p>{tb(tpl.description)}</p>
                                    <span className="rep-card-meta">
                                        {t("PDF and Excel")}
                                        {tpl.last_built ? ` · ${t("Last built {{date}}", { date: formatDate(tpl.last_built) })}` : ""}
                                    </span>
                                    {tpl.available && canWrite && (
                                        <div className="bkm-actions">
                                            <button type="button" className="bkm-btn bkm-btn-sm bkm-btn-primary"
                                                    onClick={() => navigate(`/reports/new/${tpl.id}`)}>{t("Build report")}</button>
                                            <button type="button" className="bkm-btn bkm-btn-sm"
                                                    onClick={() => navigate(`/reports/new/${tpl.id}?schedule=1`)}>{t("Schedule")}</button>
                                        </div>
                                    )}
                                </article>
                            ))}
                        </div>
                    </section>
                );
            })}
            {data && templates.length === 0 && (
                <div className="bkm-empty"><b>{t("No report matches")}</b></div>
            )}
        </div>
    );
}
