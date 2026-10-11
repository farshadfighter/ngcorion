/**
 * Audit trail: the whole security audit trail for review, searched, filtered and paged on the server
 * (GET /api/audit-trail/events, /logins), with CSV export of what the filters select. Two tabs:
 * security events (audit_logs: who did what, to what, from where, with what result) and sign-ins
 * (login_logs). Nothing here can change the trail; exporting is itself recorded in it.
 */
import React, { useEffect, useState } from "react";

import api from "../../config/api.js";
import "../../assets/AuditTrail.css";
import { t, uiLocale, n } from "../../i18n";
import { tbDetail } from "../../i18n/backendText.js";
import { DateInput } from "../shared/DateInput.jsx";

const PAGE_SIZE = 50;

const EMPTY_EVENTS = { q: "", module: "", action: "", result: "", username: "", ip: "", date_from: "", date_to: "" };
const EMPTY_LOGINS = { username: "", success: "", ip: "", date_from: "", date_to: "" };

const formatTime = (iso) => {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(uiLocale(), {
        year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
};

const resultLabel = (result) => {
    if (result === "success") return t("Successful");
    if (result === "failed" || result === "failure") return t("Failed");
    return result;
};

/** Only the filters that are set, as query parameters. */
const params = (filters, extra = {}) => Object.fromEntries(
    Object.entries({ ...filters, ...extra }).filter(([, v]) => v !== "" && v !== null && v !== undefined));

export const AuditTrailPage = () => {
    const [tab, setTab] = useState("events");
    const [draft, setDraft] = useState(EMPTY_EVENTS);
    const [filters, setFilters] = useState(EMPTY_EVENTS);
    const [page, setPage] = useState(1);
    const [data, setData] = useState(null);
    const [facets, setFacets] = useState({ modules: [], actions: [], results: [] });
    const [error, setError] = useState(null);
    const [loadedKey, setLoadedKey] = useState(null);
    const [exporting, setExporting] = useState(false);
    // Bumped to reload the filter lists: an export, or another tab, may have added actions.
    const [facetsStamp, setFacetsStamp] = useState(0);

    const path = tab === "events" ? "/api/audit-trail/events" : "/api/audit-trail/logins";
    // The request the table should show; it is loading until the answer to this very request arrives.
    const requestKey = JSON.stringify([path, filters, page]);
    const loading = loadedKey !== requestKey;

    useEffect(() => {
        let current = true;
        api.get(path, { params: params(filters, { page, page_size: PAGE_SIZE }) })
            .then(({ data: body }) => { if (current) { setData(body); setError(null); } })
            .catch((e) => {
                if (current) setError(typeof e.response?.data?.detail === "string"
                    ? e.response.data.detail : t("Could not load the audit trail"));
            })
            .finally(() => { if (current) setLoadedKey(requestKey); });
        return () => { current = false; };
    }, [path, filters, page, requestKey]);

    useEffect(() => {
        api.get("/api/audit-trail/events/facets").then(({ data: body }) => setFacets(body)).catch(() => {});
    }, [facetsStamp]);

    const switchTab = (next) => {
        if (next === tab) return;
        const empty = next === "events" ? EMPTY_EVENTS : EMPTY_LOGINS;
        setTab(next);
        setDraft(empty);
        setFilters(empty);
        setPage(1);
        setData(null);
        setFacetsStamp((v) => v + 1);
    };

    const apply = (e) => {
        e?.preventDefault();
        setFilters(draft);
        setPage(1);
    };

    const clear = () => {
        const empty = tab === "events" ? EMPTY_EVENTS : EMPTY_LOGINS;
        setDraft(empty);
        setFilters(empty);
        setPage(1);
    };

    const exportCsv = () => {
        setExporting(true);
        api.get(`${path}/export.csv`, { params: params(filters), responseType: "blob" })
            .then((response) => {
                const disposition = response.headers?.["content-disposition"] || "";
                const name = /filename="([^"]+)"/.exec(disposition)?.[1] || "audit-trail.csv";
                const url = URL.createObjectURL(response.data);
                const link = document.createElement("a");
                link.href = url;
                link.download = name;
                document.body.appendChild(link);
                link.click();
                link.remove();
                URL.revokeObjectURL(url);
                setFacetsStamp((v) => v + 1);
            })
            .catch(() => setError(t("Could not export the audit trail")))
            .finally(() => setExporting(false));
    };

    const set = (key) => (e) => setDraft((d) => ({ ...d, [key]: e.target.value }));
    const total = data?.total ?? 0;
    const first = total ? (page - 1) * PAGE_SIZE + 1 : 0;
    const last = Math.min(page * PAGE_SIZE, total);
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

    return (
        <div className="at-wrapper">
            <p className="at-intro">
                {t("Every security-relevant action and every sign-in attempt, kept unchanged. Search and filter here; the export is recorded in the trail too.")}
            </p>

            <div className="at-tabs" role="tablist">
                <button type="button" role="tab" aria-selected={tab === "events"}
                        className={`at-tab ${tab === "events" ? "is-on" : ""}`} onClick={() => switchTab("events")}>
                    {t("Security events")}
                </button>
                <button type="button" role="tab" aria-selected={tab === "logins"}
                        className={`at-tab ${tab === "logins" ? "is-on" : ""}`} onClick={() => switchTab("logins")}>
                    {t("Sign-ins")}
                </button>
            </div>

            <form className="at-filters" onSubmit={apply}>
                {tab === "events" && (
                    <>
                        <input className="at-input at-grow" value={draft.q} onChange={set("q")} maxLength={200}
                               placeholder={t("Search action, user, module or detail")} aria-label={t("Search action, user, module or detail")} />
                        <select className="at-input" value={draft.module} onChange={set("module")} aria-label={t("Module")}>
                            <option value="">{t("All modules")}</option>
                            {facets.modules.map((m) => <option key={m} value={m}>{m}</option>)}
                        </select>
                        <select className="at-input" value={draft.action} onChange={set("action")} aria-label={t("Action")}>
                            <option value="">{t("All actions")}</option>
                            {facets.actions.map((a) => <option key={a} value={a}>{a}</option>)}
                        </select>
                        <select className="at-input" value={draft.result} onChange={set("result")} aria-label={t("Result")}>
                            <option value="">{t("Any result")}</option>
                            {facets.results.map((r) => <option key={r} value={r}>{resultLabel(r)}</option>)}
                        </select>
                    </>
                )}
                {tab === "logins" && (
                    <select className="at-input" value={draft.success} onChange={set("success")} aria-label={t("Result")}>
                        <option value="">{t("Any result")}</option>
                        <option value="true">{t("Successful")}</option>
                        <option value="false">{t("Failed")}</option>
                    </select>
                )}
                <input className="at-input" value={draft.username} onChange={set("username")} maxLength={100}
                       placeholder={t("User name")} aria-label={t("User name")} />
                <input className="at-input" value={draft.ip} onChange={set("ip")} maxLength={64} dir="ltr"
                       placeholder={t("Address")} aria-label={t("Address")} />
                <label className="at-date">
                    <span>{t("From date")}</span>
                    <DateInput className="at-input" value={draft.date_from} onChange={set("date_from")} />
                </label>
                <label className="at-date">
                    <span>{t("To date")}</span>
                    <DateInput className="at-input" value={draft.date_to} onChange={set("date_to")} />
                </label>
                <div className="at-actions">
                    <button type="submit" className="at-btn at-btn-primary">
                        <i className="fa-solid fa-magnifying-glass" aria-hidden="true" /> {t("Search")}
                    </button>
                    <button type="button" className="at-btn" onClick={clear}>{t("Clear")}</button>
                    <button type="button" className="at-btn" onClick={exportCsv} disabled={exporting || !total}>
                        <i className="fa-solid fa-file-csv" aria-hidden="true" /> {exporting ? t("Exporting…") : t("Export CSV")}
                    </button>
                </div>
            </form>

            {error && <p className="at-error">{error}</p>}

            <div className="at-summary">
                {loading ? t("Loading…") : t("{{first}}–{{last}} of {{total}}", { first: n(first), last: n(last), total: n(total) })}
            </div>

            <div className="at-table-wrap">
                {tab === "events" ? (
                    <table className="at-table">
                        <thead>
                            <tr>
                                <th>{t("Time")}</th><th>{t("User")}</th><th>{t("Action")}</th><th>{t("Module")}</th>
                                <th>{t("Target")}</th><th>{t("Address")}</th><th>{t("Result")}</th><th>{t("Detail")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(data?.items || []).map((e) => (
                                <tr key={e.id}>
                                    <td className="at-nowrap">{formatTime(e.timestamp)}</td>
                                    <td dir="auto">{e.username || "—"}</td>
                                    <td dir="ltr" className="at-mono">{e.action}</td>
                                    <td dir="ltr" className="at-mono">{e.module || "—"}</td>
                                    <td>{e.target_id ?? "—"}</td>
                                    <td dir="ltr" className="at-mono">{e.ip_address || "—"}</td>
                                    <td><span className={`at-badge ${e.result === "success" ? "ok" : "fail"}`}>{resultLabel(e.result)}</span></td>
                                    <td dir="auto" className="at-detail">{e.detail ? tbDetail(e.detail) : ""}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                ) : (
                    <table className="at-table">
                        <thead>
                            <tr>
                                <th>{t("Time")}</th><th>{t("User")}</th><th>{t("Result")}</th><th>{t("Address")}</th>
                                <th>{t("Browser")}</th><th>{t("Detail")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(data?.items || []).map((e) => (
                                <tr key={e.id}>
                                    <td className="at-nowrap">{formatTime(e.timestamp)}</td>
                                    <td dir="auto">{e.username}</td>
                                    <td><span className={`at-badge ${e.success ? "ok" : "fail"}`}>{e.success ? t("Successful") : t("Failed")}</span></td>
                                    <td dir="ltr" className="at-mono">{e.ip_address || "—"}</td>
                                    <td dir="ltr" className="at-detail at-muted">{e.user_agent || "—"}</td>
                                    <td dir="auto" className="at-detail">{e.message ? tbDetail(e.message) : ""}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
                {data && data.items.length === 0 && !loading && <p className="at-empty">{t("Nothing matches these filters.")}</p>}
            </div>

            <div className="at-pager">
                <button type="button" className="at-btn" disabled={page <= 1 || loading} onClick={() => setPage((p) => p - 1)}>
                    {t("Previous page")}
                </button>
                <span>{t("Page {{page}} of {{pages}}", { page: n(page), pages: n(pages) })}</span>
                <button type="button" className="at-btn" disabled={page >= pages || loading} onClick={() => setPage((p) => p + 1)}>
                    {t("Next page")}
                </button>
            </div>
        </div>
    );
};

export default AuditTrailPage;
