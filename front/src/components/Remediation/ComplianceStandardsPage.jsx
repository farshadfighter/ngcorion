/**
 * Compliance with standards (/compliance, GET /api/compliance/...): how far the latest audits meet PCI
 * DSS, ISO/IEC 27001, NIST SP 800-53 or a standard of the organisation's own (e.g. national
 * requirements), for every asset or one asset group.
 *
 * Each requirement is evidenced by the audit checks of its security domains (password, audit log,
 * encryption ...), named topics or named checks; a requirement no check covers is assessed by hand,
 * with a note and a date it is valid until. Views: requirements by section (status, score, evidence),
 * gaps (the failing checks behind them, the most urgent first), the domains of every check (an
 * administrator corrects them) and the standards themselves (turn on and off, export, import, and the
 * requirements of the organisation's own).
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useSelector } from "react-redux";

import api from "../../config/api.js";
import { currentLanguage, n, t } from "../../i18n";
import { formatDate, formatDateTime } from "../../utils/dates.js";
import { usePermission } from "../../hooks/usePermission";
import { errorText } from "../AssetGroups/groupFormat.js";
import { DateInput } from "../shared/DateInput.jsx";
import "../../assets/BackupModule.css";
import "../../assets/Syslog.css";
import "../../assets/UnknownDevices.css";
import "../../assets/BenchmarkPolicy.css";
import "../../assets/Reports.css";
import "../../assets/Compliance.css";

const STATUS = {
    met: { label: t("Met"), pill: "bkm-pill-ok" },
    partial: { label: t("Partly met"), pill: "bkm-pill-orange" },
    not_met: { label: t("Not met"), pill: "bkm-pill-bad" },
    not_applicable: { label: t("Not applicable"), pill: "bkm-pill-muted" },
    not_assessed: { label: t("Not assessed"), pill: "bkm-pill-muted" },
};
const MANUAL_STATUSES = ["met", "partial", "not_met", "not_applicable"];
const SEVERITY = { critical: t("Critical"), high: t("High"), medium: t("Medium"), low: t("Low"), info: t("Info") };
const DOMAIN_NAMES = {
    accounts: t("Accounts and privileges"),
    authentication: t("Authentication and passwords"),
    remote_access: t("Remote administration"),
    session: t("Session lock and logon notice"),
    logging: t("Audit logging"),
    time: t("Clock synchronisation"),
    services: t("Unneeded services and software"),
    network_filtering: t("Firewall and network filtering"),
    network_hardening: t("Network protocol hardening"),
    crypto: t("Encryption in transit"),
    data_protection: t("Data at rest and secrets"),
    filesystem: t("File permissions and storage"),
    integrity: t("Integrity and secure boot"),
    isolation: t("Process isolation and exploit protection"),
    malware: t("Malware protection"),
    patching: t("Updates and supported versions"),
    web_hardening: t("Web server hardening"),
    availability: t("Resource limits and availability"),
};
const TOPIC_NAMES = {
    lockout: t("Lockout after failed logons"),
    password_quality: t("Password length and complexity"),
    password_history: t("Password reuse"),
    password_age: t("Password age and expiry"),
    mfa: t("Multi-factor authentication"),
    idle_session: t("Idle session timeout"),
    screen_lock: t("Screen lock"),
    logon_banner: t("Logon notice"),
    privileged_access: t("Privileged accounts"),
    privileged_utilities: t("Privileged utilities"),
    inactive_accounts: t("Inactive and unused accounts"),
    service_accounts: t("System and service accounts"),
    audit_content: t("What audit records contain"),
    audit_protection: t("Protection of audit logs"),
    central_logging: t("Logs sent to a central server"),
    log_retention: t("Log retention"),
    log_capacity: t("Log storage capacity"),
    file_integrity: t("File integrity monitoring"),
    backup: t("Backup and recovery"),
    memory_protection: t("Memory protection"),
    segmentation: t("Network segmentation"),
    monitoring: t("Monitoring and alerting"),
};

const Mono = ({ children }) => <bdi dir="ltr" className="bkm-mono">{children}</bdi>;
const pct = (v) => (v === null || v === undefined ? "—" : n(`${Math.round(v * 10) / 10}%`));
const fa = () => currentLanguage() === "fa";
const title = (o) => (fa() && o?.title_fa ? o.title_fa : o?.title);
const stdName = (s) => (fa() && s?.name_fa ? s.name_fa : s?.name);
const domainName = (d) => d.split("+").map((x) => DOMAIN_NAMES[x] || x).join(" + ");
const tone = (v) => (v === null || v === undefined ? "none" : v >= 90 ? "good" : v >= 60 ? "fair" : "poor");
const dayOffset = (days) => {
    const d = new Date();
    d.setDate(d.getDate() + days);
    return d.toISOString().slice(0, 10);
};

function useBenchmarkNames() {
    const [names, setNames] = useState({});
    useEffect(() => {
        api.get("/api/targets/catalog").then(({ data }) => {
            const out = {};
            for (const target of data.targets || []) out[target.id] = target.label;
            setNames(out);
        }).catch(() => setNames({}));
    }, []);
    return useCallback((b) => names[b] || b, [names]);
}

function ScoreBar({ value }) {
    return (
        <span className={`cmp-bar cmp-${tone(value)}`} aria-hidden="true">
            <span style={{ width: `${Math.max(0, Math.min(100, value || 0))}%` }} />
        </span>
    );
}

function MappingChips({ mapping }) {
    const m = mapping || {};
    if (!m.all && !m.domains?.length && !m.topics?.length && !m.checks?.length) {
        return <span className="bkm-small bkm-muted">{t("No check covers it: assessed by hand")}</span>;
    }
    return (
        <div className="cmp-chips">
            {m.all && <span className="cmp-chip cmp-chip-all">{t("Every audit check")}</span>}
            {(m.domains || []).map((d) => <span key={d} className="cmp-chip">{domainName(d)}</span>)}
            {(m.topics || []).map((x) => <span key={x} className="cmp-chip cmp-chip-topic">{TOPIC_NAMES[x] || x}</span>)}
            {(m.checks || []).map((c) => <span key={c} className="cmp-chip cmp-chip-check"><Mono>{c}</Mono></span>)}
        </div>
    );
}

// ── failing assets of one check ──────────────────────────────────────────

function FailingAssets({ check, groupId }) {
    const [rows, setRows] = useState(null);
    useEffect(() => {
        api.get("/api/compliance/failing-assets", { params: { benchmark: check.benchmark, check_number: check.check_number, group_id: groupId || undefined } })
            .then(({ data }) => setRows(data.assets)).catch(() => setRows([]));
    }, [check, groupId]);
    if (!rows) return <span className="bkm-small bkm-muted">{t("Loading…")}</span>;
    return (
        <ul className="cmp-assets">
            {rows.map((a) => (
                <li key={a.asset_id}>
                    <Link to={`/assets/inventory/${a.asset_id}`}><bdi>{a.name}</bdi></Link>
                    <span className="bkm-small bkm-muted"><Mono>{a.ip}</Mono>{a.audited_at && ` · ${formatDate(a.audited_at)}`}</span>
                </li>
            ))}
        </ul>
    );
}

// ── one requirement ──────────────────────────────────────────────────────

function RequirementDrawer({ requirementId, groupId, nameOf, canAssess, onClose, onChanged }) {
    const [d, setD] = useState(null);
    const [error, setError] = useState(null);
    const [form, setForm] = useState(null);
    const [busy, setBusy] = useState(false);
    const [open, setOpen] = useState(null);
    const load = useCallback(() => {
        api.get(`/api/compliance/requirements/${requirementId}`, { params: { group_id: groupId || undefined } })
            .then(({ data }) => setD(data)).catch((e) => setError(errorText(e, t("Could not load the requirement"))));
    }, [requirementId, groupId]);
    useEffect(() => { load(); }, [load]);

    const hasEvidence = d && d.passed + d.failed > 0;
    const startForm = () => setForm({
        status: d.assessment?.status || (hasEvidence ? "not_applicable" : "met"),
        note: d.assessment?.note || "",
        valid_until: d.assessment?.valid_until?.slice(0, 10) || dayOffset(365),
    });
    const save = () => {
        setBusy(true);
        setError(null);
        api.put(`/api/compliance/requirements/${requirementId}/assessment`, {
            group_id: groupId || null, status: form.status, note: form.note.trim(),
            valid_until: form.valid_until ? `${form.valid_until}T23:59:59` : null,
        }).then(() => { setForm(null); load(); onChanged(); })
            .catch((e) => setError(errorText(e, t("Could not save")))).finally(() => setBusy(false));
    };
    const remove = () => {
        setBusy(true);
        api.delete(`/api/compliance/requirements/${requirementId}/assessment`, { params: { group_id: groupId || undefined } })
            .then(() => { load(); onChanged(); }).catch((e) => setError(errorText(e, t("Could not save"))))
            .finally(() => setBusy(false));
    };

    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="cmp-req-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer cmp-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="cmp-req-title">{d ? <><Mono>{d.ref}</Mono> {title(d)}</> : t("Requirement")}</h2>
                        {d && <span className="bkm-sub">{stdName(d.standard)} {d.standard.version}</span>}
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                    {!d ? <p className="bkm-muted">{t("Loading…")}</p> : (
                        <>
                            <div className="cmp-req-head">
                                <span className={`bkm-pill ${STATUS[d.status].pill}`}>{STATUS[d.status].label}</span>
                                {d.score !== null && <b className="cmp-big">{pct(d.score)}</b>}
                                <span className="bkm-small bkm-muted">
                                    {d.source === "audit" ? t("From {{passed}} passed and {{failed}} failed results in {{checks}} checks",
                                        { passed: n(d.passed), failed: n(d.failed), checks: n(d.checks) })
                                        : d.source === "manual" ? t("Assessed by hand") : t("No evidence yet")}
                                </span>
                            </div>
                            <h3 className="cmp-h3">{t("Evidence comes from")}</h3>
                            <MappingChips mapping={d.mapping} />

                            <h3 className="cmp-h3">{t("Assessment by hand")}</h3>
                            {d.assessment && !form && (
                                <div className={`cmp-assess ${d.assessment.expired ? "is-expired" : ""}`}>
                                    <span className={`bkm-pill ${STATUS[d.assessment.status].pill}`}>{STATUS[d.assessment.status].label}</span>
                                    <p dir="auto">{d.assessment.note}</p>
                                    <span className="bkm-small bkm-muted">
                                        {t("By {{user}} on {{date}}", { user: d.assessment.assessed_by || "—", date: formatDateTime(d.assessment.assessed_at) })}
                                        {" · "}
                                        {d.assessment.expired ? t("Expired on {{date}}", { date: formatDate(d.assessment.valid_until) })
                                            : t("Valid until {{date}}", { date: formatDate(d.assessment.valid_until) })}
                                    </span>
                                </div>
                            )}
                            {!d.assessment && !form && (
                                <p className="bkm-small bkm-muted">{hasEvidence
                                    ? t("The audits give evidence for this requirement. It can be marked not applicable by hand, with the reason.")
                                    : t("No audit check covers this requirement: assess it by hand, with what shows it is met.")}</p>
                            )}
                            {canAssess && !form && (
                                <div className="cmp-row-actions">
                                    <button type="button" className="bkm-btn bkm-btn-sm" onClick={startForm}>
                                        {d.assessment ? t("Change the assessment") : t("Assess by hand")}</button>
                                    {d.assessment && <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy} onClick={remove}>{t("Remove")}</button>}
                                </div>
                            )}
                            {form && (
                                <div className="cmp-form">
                                    <div className="bp-seg" role="radiogroup" aria-label={t("Status")}>
                                        {MANUAL_STATUSES.map((s) => {
                                            const off = hasEvidence && s !== "not_applicable";
                                            return (
                                                <button key={s} type="button" role="radio" aria-checked={form.status === s} disabled={off}
                                                        className={`bp-seg-btn ${form.status === s ? "is-on" : ""}`}
                                                        onClick={() => setForm({ ...form, status: s })}>{STATUS[s].label}</button>
                                            );
                                        })}
                                    </div>
                                    <label className="alr-lbl">{t("Note")}
                                        <textarea className="bkm-select cmp-note" rows={3} value={form.note} dir="auto" maxLength={4000}
                                                  placeholder={t("What shows this, or why it does not apply")}
                                                  onChange={(e) => setForm({ ...form, note: e.target.value })} />
                                    </label>
                                    <label className="alr-lbl">{t("Valid until")}
                                        <DateInput value={form.valid_until} min={dayOffset(1)} onChange={(v) => setForm({ ...form, valid_until: v })} />
                                    </label>
                                    <div className="cmp-row-actions">
                                        <button type="button" className="bkm-btn bkm-btn-primary bkm-btn-sm" disabled={busy || form.note.trim().length < 5} onClick={save}>{t("Save")}</button>
                                        <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => setForm(null)}>{t("Cancel")}</button>
                                    </div>
                                </div>
                            )}

                            {d.evidence.length > 0 && (
                                <>
                                    <h3 className="cmp-h3">{t("Checks ({{value}})", { value: n(d.evidence_total) })}</h3>
                                    <ul className="cmp-evidence">
                                        {d.evidence.map((c) => {
                                            const key = `${c.benchmark}|${c.check_number}`;
                                            return (
                                                <li key={key} className={c.failed ? "is-fail" : ""}>
                                                    <div className="cmp-ev-main">
                                                        <span className="bkm-small bkm-muted">{nameOf(c.benchmark)} · {SEVERITY[c.severity] || c.severity}</span>
                                                        <span><Mono>{c.check_number}</Mono><bdi className="bp-title" dir="auto">{c.title}</bdi></span>
                                                    </div>
                                                    <div className="cmp-ev-side">
                                                        {c.failed > 0
                                                            ? <button type="button" className="bkm-link" onClick={() => setOpen(open === key ? null : key)}>
                                                                {t("{{value}} assets fail", { value: n(c.failing_assets) })}</button>
                                                            : <span className="bkm-small cmp-ok">{t("Passes on {{value}}", { value: n(c.passed) })}</span>}
                                                    </div>
                                                    {open === key && <FailingAssets check={c} groupId={groupId} />}
                                                </li>
                                            );
                                        })}
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

// ── views ────────────────────────────────────────────────────────────────

const FILTERS = [["all", t("All")], ["gaps", t("With gaps")], ["not_assessed", t("Not assessed")], ["met", t("Met")]];

function Requirements({ std, onOpen, onEdit }) {
    const [filter, setFilter] = useState("all");
    const [q, setQ] = useState("");
    const rows = useMemo(() => std.requirements.filter((r) => {
        if (filter === "gaps" && !["partial", "not_met"].includes(r.status)) return false;
        if (filter === "not_assessed" && r.status !== "not_assessed") return false;
        if (filter === "met" && r.status !== "met") return false;
        const needle = q.trim().toLowerCase();
        return !needle || r.ref.toLowerCase().includes(needle) || (r.title || "").toLowerCase().includes(needle)
            || (r.title_fa || "").includes(needle);
    }), [std, filter, q]);
    const sections = std.sections.length ? std.sections : [{ ref: null, title: "" }];
    const bySection = (ref) => rows.filter((r) => (std.sections.length ? r.section === ref : true));
    const orphans = std.sections.length ? rows.filter((r) => !std.sections.some((s) => s.ref === r.section)) : [];
    const groups = [...sections.map((s) => [s, bySection(s.ref)]), ...(orphans.length ? [[{ ref: "", title: t("Other") }, orphans]] : [])];
    return (
        <section className="bkm-card bkm-flush">
            <div className="cmp-toolbar">
                <div className="bkm-chips" role="tablist" aria-label={t("Show")}>
                    {FILTERS.map(([k, label]) => (
                        <button key={k} type="button" role="tab" aria-selected={filter === k}
                                className={`bkm-chip ${filter === k ? "is-on" : ""}`} onClick={() => setFilter(k)}>{label}</button>
                    ))}
                </div>
                <input className="bkm-select cmp-search" type="search" value={q} placeholder={t("Search requirements…")}
                       onChange={(e) => setQ(e.target.value)} aria-label={t("Search requirements…")} />
            </div>
            {rows.length === 0 ? <div className="bkm-empty"><b>{t("Nothing here")}</b></div> : (
                <div className="bkm-table-wrap">
                    <table className="bkm-table cmp-table">
                        <thead><tr><th>{t("Requirement")}</th><th>{t("Status")}</th><th>{t("Score")}</th><th>{t("Evidence")}</th>{onEdit && <th />}</tr></thead>
                        {groups.filter(([, list]) => list.length).map(([s, list]) => (
                            <tbody key={s.ref || "none"}>
                                {s.ref !== null && (
                                    <tr className="cmp-section"><th colSpan={onEdit ? 5 : 4}><Mono>{s.ref}</Mono> {title(s)}</th></tr>
                                )}
                                {list.map((r) => (
                                    <tr key={r.id} className="cmp-row" tabIndex={0} onClick={() => onOpen(r.id)}
                                        onKeyDown={(e) => { if (e.key === "Enter") onOpen(r.id); }}>
                                        <td><div className="cmp-req"><Mono>{r.ref}</Mono><span dir="auto">{title(r)}</span></div></td>
                                        <td>
                                            <div className="bp-stack">
                                                <span className={`bkm-pill ${STATUS[r.status].pill}`}>{STATUS[r.status].label}</span>
                                                {r.assessment_expired && <span className="bkm-small cmp-warn">{t("Assessment expired")}</span>}
                                            </div>
                                        </td>
                                        <td className="cmp-score-cell">{r.score !== null ? <><b>{pct(r.score)}</b><ScoreBar value={r.score} /></> : <span className="bkm-muted">—</span>}</td>
                                        <td className="bkm-small">
                                            {r.source === "audit" ? t("{{failing}} of {{checks}} checks failing", { failing: n(r.failing_checks), checks: n(r.checks) })
                                                : r.source === "manual" ? t("By hand") : r.manual_only ? t("Needs an assessment by hand") : t("No audit result yet")}
                                        </td>
                                        {onEdit && <td><button type="button" className="bkm-btn bkm-btn-sm" onClick={(e) => { e.stopPropagation(); onEdit(r); }}>{t("Edit")}</button></td>}
                                    </tr>
                                ))}
                            </tbody>
                        ))}
                    </table>
                </div>
            )}
        </section>
    );
}

function Gaps({ std, groupId, nameOf }) {
    const [data, setData] = useState(null);
    const [open, setOpen] = useState(null);
    useEffect(() => {
        api.get(`/api/compliance/standards/${std.id}/gaps`, { params: { group_id: groupId || undefined, limit: 500 } })
            .then(({ data: d }) => setData(d)).catch(() => setData({ total: 0, gaps: [] }));
    }, [std.id, groupId]);
    if (!data) return <section className="bkm-card"><p className="bkm-muted">{t("Loading…")}</p></section>;
    return (
        <section className="bkm-card bkm-flush">
            <div className="bkm-card-head">
                <div>
                    <h2>{t("Gaps")}</h2>
                    <p>{t("The failing checks behind the standard's requirements: high severity, the most specific to a requirement and the most assets first. Fixing them raises the score.")}</p>
                </div>
            </div>
            {data.gaps.length === 0 ? <div className="bkm-empty"><b>{t("No failing check holds this standard back")}</b></div> : (
                <div className="bkm-table-wrap">
                    <table className="bkm-table cmp-table">
                        <thead><tr><th>{t("Check")}</th><th>{t("Severity")}</th><th>{t("Assets failing")}</th><th>{t("Requirements")}</th></tr></thead>
                        <tbody>
                            {data.gaps.map((g) => {
                                const key = `${g.benchmark}|${g.check_number}`;
                                return [
                                    <tr key={key}>
                                        <td>
                                            <div className="ud-addr">
                                                <span className="bkm-small bkm-muted">{nameOf(g.benchmark)}</span>
                                                <span><Mono>{g.check_number}</Mono><bdi className="bp-title" dir="auto">{g.title}</bdi></span>
                                            </div>
                                        </td>
                                        <td><span className={`cmp-sev cmp-sev-${g.severity}`}>{SEVERITY[g.severity] || g.severity}</span></td>
                                        <td><button type="button" className="bkm-link" onClick={() => setOpen(open === key ? null : key)}>{n(g.failing_assets)}</button></td>
                                        <td><div className="cmp-chips">{g.requirements.map((r) => <span key={r} className="cmp-chip cmp-chip-check"><Mono>{r}</Mono></span>)}</div></td>
                                    </tr>,
                                    open === key && <tr key={`${key}-assets`} className="cmp-sub"><td colSpan={4}><FailingAssets check={g} groupId={groupId} /></td></tr>,
                                ];
                            })}
                        </tbody>
                    </table>
                    {data.total > data.gaps.length && <p className="bkm-small bkm-muted cmp-pad">{t("Showing {{shown}} of {{total}}", { shown: n(data.gaps.length), total: n(data.total) })}</p>}
                </div>
            )}
        </section>
    );
}

function DomainEditor({ check, onClose, onDone }) {
    const [chosen, setChosen] = useState(new Set(check.domains));
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const send = (domains) => {
        setBusy(true);
        api.put("/api/compliance/checks/domains", { benchmark: check.benchmark, check_number: check.check_number, domains })
            .then(onDone).catch((e) => setError(errorText(e, t("Could not save")))).finally(() => setBusy(false));
    };
    const toggle = (d) => setChosen((s) => { const x = new Set(s); if (x.has(d)) x.delete(d); else x.add(d); return x; });
    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="cmp-dom-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer ud-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="cmp-dom-title">{t("Domains of the check")}</h2>
                        <span className="bkm-sub"><Mono>{check.check_number}</Mono> <bdi dir="auto">{check.title}</bdi></span>
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    <p className="bkm-small bkm-muted">{t("The requirements of every standard that name these domains take this check as evidence.")}</p>
                    <div className="cmp-domain-list">
                        {Object.keys(DOMAIN_NAMES).map((d) => (
                            <label key={d} className={`rep-check ${chosen.has(d) ? "is-on" : ""}`}>
                                <input type="checkbox" checked={chosen.has(d)} onChange={() => toggle(d)} />
                                <span>{DOMAIN_NAMES[d]}</span>
                            </label>
                        ))}
                    </div>
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                </div>
                <footer className="bkm-drawer-foot">
                    {check.overridden && <button type="button" className="bkm-btn" disabled={busy} onClick={() => send(null)}>{t("Back to automatic")}</button>}
                    <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy}
                            onClick={() => send(Object.keys(DOMAIN_NAMES).filter((d) => chosen.has(d)))}>{t("Save")}</button>
                </footer>
            </aside>
        </div>
    );
}

function CheckDomains({ nameOf, isAdmin, onChanged }) {
    const [filters, setFilters] = useState({ benchmark: "", q: "", domain: "", unclassified: false });
    const [data, setData] = useState(null);
    const [editing, setEditing] = useState(null);
    const [page, setPage] = useState(0);
    const PAGE = 100;
    const load = useCallback(() => {
        api.get("/api/compliance/checks", { params: { benchmark: filters.benchmark || undefined, q: filters.q || undefined,
            domain: filters.domain || undefined, unclassified: filters.unclassified || undefined, offset: page * PAGE, limit: PAGE } })
            .then(({ data: d }) => setData(d)).catch(() => setData({ total: 0, checks: [], benchmarks: [] }));
    }, [filters, page]);
    useEffect(() => { load(); }, [load]);
    const set = (k, v) => { setPage(0); setFilters((f) => ({ ...f, [k]: v })); };
    return (
        <section className="bkm-card bkm-flush">
            <div className="bkm-card-head">
                <div>
                    <h2>{t("Domains of the checks")}</h2>
                    <p>{t("Every check of the latest audits is put in security domains from its title; the requirements of the standards take as evidence the checks of their domains. An administrator can correct a check's domains.")}</p>
                </div>
            </div>
            <div className="cmp-toolbar">
                <select className="bkm-select" value={filters.benchmark} onChange={(e) => set("benchmark", e.target.value)} aria-label={t("Benchmark")}>
                    <option value="">{t("Every benchmark")}</option>
                    {(data?.benchmarks || []).map((b) => <option key={b} value={b}>{nameOf(b)}</option>)}
                </select>
                <select className="bkm-select" value={filters.domain} onChange={(e) => set("domain", e.target.value)} aria-label={t("Domain")}>
                    <option value="">{t("Every domain")}</option>
                    {Object.entries(DOMAIN_NAMES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                </select>
                <label className={`rep-check ${filters.unclassified ? "is-on" : ""}`}>
                    <input type="checkbox" checked={filters.unclassified} onChange={(e) => set("unclassified", e.target.checked)} />
                    <span>{t("Only checks without a domain")}</span>
                </label>
                <input className="bkm-select cmp-search" type="search" value={filters.q} placeholder={t("Search checks…")}
                       onChange={(e) => set("q", e.target.value)} aria-label={t("Search checks…")} />
            </div>
            {!data ? <p className="bkm-muted cmp-pad">{t("Loading…")}</p> : data.checks.length === 0 ? <div className="bkm-empty"><b>{t("Nothing here")}</b></div> : (
                <div className="bkm-table-wrap">
                    <table className="bkm-table cmp-table">
                        <thead><tr><th>{t("Check")}</th><th>{t("Domains")}</th><th>{t("Latest results")}</th>{isAdmin && <th />}</tr></thead>
                        <tbody>
                            {data.checks.map((c) => (
                                <tr key={`${c.benchmark}|${c.check_number}`}>
                                    <td>
                                        <div className="ud-addr">
                                            <span className="bkm-small bkm-muted">{nameOf(c.benchmark)}</span>
                                            <span><Mono>{c.check_number}</Mono><bdi className="bp-title" dir="auto">{c.title}</bdi></span>
                                        </div>
                                    </td>
                                    <td>
                                        <div className="cmp-chips">
                                            {c.domains.length ? c.domains.map((d) => <span key={d} className="cmp-chip">{DOMAIN_NAMES[d] || d}</span>)
                                                : <span className="bkm-small bkm-muted">{t("No domain: counts for secure configuration only")}</span>}
                                            {c.overridden && <span className="cmp-chip cmp-chip-set">{t("Set by hand")}</span>}
                                        </div>
                                    </td>
                                    <td className="bkm-small">{t("{{passed}} passed, {{failed}} failed", { passed: n(c.passed), failed: n(c.failed) })}</td>
                                    {isAdmin && <td><button type="button" className="bkm-btn bkm-btn-sm" onClick={() => setEditing(c)}>{t("Change")}</button></td>}
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    <div className="cmp-pager">
                        <span className="bkm-small bkm-muted">{t("{{from}}–{{to}} of {{total}}", { from: n(page * PAGE + 1), to: n(Math.min((page + 1) * PAGE, data.total)), total: n(data.total) })}</span>
                        <button type="button" className="bkm-btn bkm-btn-sm" disabled={page === 0} onClick={() => setPage(page - 1)}>{t("Previous")}</button>
                        <button type="button" className="bkm-btn bkm-btn-sm" disabled={(page + 1) * PAGE >= data.total} onClick={() => setPage(page + 1)}>{t("Next")}</button>
                    </div>
                </div>
            )}
            {editing && <DomainEditor check={editing} onClose={() => setEditing(null)} onDone={() => { setEditing(null); load(); onChanged(); }} />}
        </section>
    );
}

// ── the organisation's own standards ─────────────────────────────────────

function StandardDrawer({ onClose, onDone }) {
    const [mode, setMode] = useState("new");
    const [form, setForm] = useState({ name: "", name_fa: "", version: "", description: "" });
    const [file, setFile] = useState(null);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const submit = async () => {
        setBusy(true);
        setError(null);
        try {
            if (mode === "new") {
                const { data } = await api.post("/api/compliance/standards", {
                    name: form.name.trim(), name_fa: form.name_fa.trim() || null, version: form.version.trim() || null,
                    description: form.description.trim() || null,
                });
                onDone(data);
            } else {
                let body;
                try {
                    body = JSON.parse(await file.text());
                } catch {
                    setError(t("The file is not a standard definition (JSON)."));
                    return;
                }
                const { data } = await api.post("/api/compliance/standards/import", body);
                onDone(data);
            }
        } catch (e) {
            setError(errorText(e, t("Could not save")));
        } finally {
            setBusy(false);
        }
    };
    const ready = mode === "new" ? form.name.trim().length >= 2 : !!file;
    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="cmp-std-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer ud-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="cmp-std-title">{t("Add a standard")}</h2>
                        <span className="bkm-sub">{t("For example the national requirements or the organisation's own baseline.")}</span>
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    <div className="bp-seg" role="radiogroup" aria-label={t("How")}>
                        {[["new", t("Start empty")], ["import", t("Import a file")]].map(([k, label]) => (
                            <button key={k} type="button" role="radio" aria-checked={mode === k}
                                    className={`bp-seg-btn ${mode === k ? "is-on" : ""}`} onClick={() => setMode(k)}>{label}</button>
                        ))}
                    </div>
                    {mode === "new" ? (
                        <>
                            <label className="alr-lbl">{t("Name")}
                                <input className="bkm-select" value={form.name} maxLength={120} dir="auto" onChange={(e) => setForm({ ...form, name: e.target.value })} />
                            </label>
                            <label className="alr-lbl">{t("Persian name (optional)")}
                                <input className="bkm-select" value={form.name_fa} maxLength={160} dir="rtl" onChange={(e) => setForm({ ...form, name_fa: e.target.value })} />
                            </label>
                            <label className="alr-lbl">{t("Version (optional)")}
                                <input className="bkm-select" value={form.version} maxLength={40} dir="auto" onChange={(e) => setForm({ ...form, version: e.target.value })} />
                            </label>
                            <label className="alr-lbl">{t("Description (optional)")}
                                <textarea className="bkm-select cmp-note" rows={3} value={form.description} maxLength={4000} dir="auto"
                                          onChange={(e) => setForm({ ...form, description: e.target.value })} />
                            </label>
                            <p className="bkm-small bkm-muted">{t("Then add its requirements one by one, each mapped to security domains, topics or checks.")}</p>
                        </>
                    ) : (
                        <>
                            <label className="alr-lbl">{t("Definition file (JSON)")}
                                <input type="file" accept=".json,application/json" onChange={(e) => setFile(e.target.files?.[0] || null)} />
                            </label>
                            <p className="bkm-small bkm-muted">{t("The format of Export: name, sections and requirements, each with its mapping. Export a built-in standard to see an example.")}</p>
                        </>
                    )}
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                </div>
                <footer className="bkm-drawer-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !ready} onClick={submit}>
                        {mode === "new" ? t("Create") : t("Import")}</button>
                </footer>
            </aside>
        </div>
    );
}

function RequirementEditor({ std, requirement, onClose, onDone }) {
    const m = requirement?.mapping || {};
    const [form, setForm] = useState({
        ref: requirement?.ref || "", section: requirement?.section || "", title: requirement?.title || "",
        title_fa: requirement?.title_fa || "", all: !!m.all, domains: new Set(m.domains || []), topics: new Set(m.topics || []),
        checks: (m.checks || []).join("\n"),
    });
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const toggle = (k, v) => setForm((f) => { const x = new Set(f[k]); if (x.has(v)) x.delete(v); else x.add(v); return { ...f, [k]: x }; });
    const body = () => ({
        ref: form.ref.trim(), section: form.section.trim() || null, title: form.title.trim(), title_fa: form.title_fa.trim() || null,
        mapping: { all: form.all, domains: [...form.domains], topics: [...form.topics],
            checks: form.checks.split(/\s*[\n,]\s*/).map((x) => x.trim()).filter(Boolean) },
    });
    const save = () => {
        setBusy(true);
        setError(null);
        const req = requirement ? api.put(`/api/compliance/requirements/${requirement.id}`, body())
            : api.post(`/api/compliance/standards/${std.id}/requirements`, body());
        req.then(onDone).catch((e) => setError(errorText(e, t("Could not save")))).finally(() => setBusy(false));
    };
    const remove = () => {
        setBusy(true);
        api.delete(`/api/compliance/requirements/${requirement.id}`).then(onDone)
            .catch((e) => setError(errorText(e, t("Could not save")))).finally(() => setBusy(false));
    };
    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="cmp-redit-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer cmp-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="cmp-redit-title">{requirement ? t("Edit the requirement") : t("New requirement")}</h2>
                        <span className="bkm-sub">{stdName(std)}</span>
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    <div className="cmp-two">
                        <label className="alr-lbl">{t("Reference")}
                            <input className="bkm-select" value={form.ref} maxLength={40} dir="ltr" onChange={(e) => setForm({ ...form, ref: e.target.value })} />
                        </label>
                        <label className="alr-lbl">{t("Section (optional)")}
                            <input className="bkm-select" value={form.section} maxLength={40} dir="ltr" onChange={(e) => setForm({ ...form, section: e.target.value })} />
                        </label>
                    </div>
                    <label className="alr-lbl">{t("Title")}
                        <input className="bkm-select" value={form.title} maxLength={500} dir="auto" onChange={(e) => setForm({ ...form, title: e.target.value })} />
                    </label>
                    <label className="alr-lbl">{t("Persian title (optional)")}
                        <input className="bkm-select" value={form.title_fa} maxLength={500} dir="rtl" onChange={(e) => setForm({ ...form, title_fa: e.target.value })} />
                    </label>
                    <fieldset className="cmp-fs">
                        <legend>{t("Evidence comes from")}</legend>
                        <label className={`rep-check ${form.all ? "is-on" : ""}`}>
                            <input type="checkbox" checked={form.all} onChange={(e) => setForm({ ...form, all: e.target.checked })} />
                            <span>{t("Every audit check (secure configuration as a whole)")}</span>
                        </label>
                        <span className="cmp-fs-label">{t("Security domains")}</span>
                        <div className="cmp-domain-list">
                            {Object.entries(DOMAIN_NAMES).map(([k, v]) => (
                                <label key={k} className={`rep-check ${form.domains.has(k) ? "is-on" : ""}`}>
                                    <input type="checkbox" checked={form.domains.has(k)} onChange={() => toggle("domains", k)} /><span>{v}</span>
                                </label>
                            ))}
                        </div>
                        <span className="cmp-fs-label">{t("Topics")}</span>
                        <div className="cmp-domain-list">
                            {Object.entries(TOPIC_NAMES).map(([k, v]) => (
                                <label key={k} className={`rep-check ${form.topics.has(k) ? "is-on" : ""}`}>
                                    <input type="checkbox" checked={form.topics.has(k)} onChange={() => toggle("topics", k)} /><span>{v}</span>
                                </label>
                            ))}
                        </div>
                        <label className="alr-lbl">{t("Checks by number (one per line, optionally benchmark:number)")}
                            <textarea className="bkm-select cmp-note" rows={3} value={form.checks} dir="ltr" placeholder="linux:LNX-L1-5.3.2"
                                      onChange={(e) => setForm({ ...form, checks: e.target.value })} />
                        </label>
                        <p className="bkm-small bkm-muted">{t("Leave all of these empty for a requirement that is assessed by hand.")}</p>
                    </fieldset>
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                </div>
                <footer className="bkm-drawer-foot">
                    {requirement && <button type="button" className="bkm-btn bp-danger" disabled={busy} onClick={remove}>{t("Delete")}</button>}
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !form.ref.trim() || form.title.trim().length < 2} onClick={save}>{t("Save")}</button>
                </footer>
            </aside>
        </div>
    );
}

function Standards({ list, canManage, onChanged, onSelect }) {
    const [error, setError] = useState(null);
    const toggle = (s) => api.patch(`/api/compliance/standards/${s.id}`, { enabled: !s.enabled }).then(onChanged)
        .catch((e) => setError(errorText(e, t("Could not save"))));
    const remove = (s) => api.delete(`/api/compliance/standards/${s.id}`).then(onChanged)
        .catch((e) => setError(errorText(e, t("Could not save"))));
    const exportIt = (s) => api.get(`/api/compliance/standards/${s.id}/export`).then(({ data }) => {
        const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 1)], { type: "application/json" }));
        const a = document.createElement("a");
        a.href = url;
        a.download = `${s.key}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }).catch((e) => setError(errorText(e, t("Could not load the standard"))));
    return (
        <section className="bkm-card bkm-flush">
            <div className="bkm-card-head">
                <div>
                    <h2>{t("Standards")}</h2>
                    <p>{t("The built-in standards follow the versions shipped with NGCorion; a standard that is off is hidden from the page and reports. The organisation's own standards can be edited.")}</p>
                </div>
            </div>
            {error && <div className="bkm-note bkm-note-error">{error}</div>}
            <div className="bkm-table-wrap">
                <table className="bkm-table cmp-table">
                    <thead><tr><th>{t("Standard")}</th><th>{t("Kind")}</th><th>{t("State")}</th><th /></tr></thead>
                    <tbody>
                        {list.map((s) => (
                            <tr key={s.id}>
                                <td>
                                    <div className="ud-addr">
                                        <b dir="auto">{stdName(s)} {s.version && <span className="bkm-muted">{s.version}</span>}</b>
                                        {(fa() ? s.description_fa || s.description : s.description) &&
                                            <span className="bkm-small bkm-muted" dir="auto">{fa() ? s.description_fa || s.description : s.description}</span>}
                                    </div>
                                </td>
                                <td>{s.builtin ? t("Built in") : t("The organisation's")}</td>
                                <td><span className={`bkm-pill ${s.enabled ? "bkm-pill-ok" : "bkm-pill-muted"}`}>{s.enabled ? t("On") : t("Off")}</span></td>
                                <td>
                                    <div className="cmp-row-actions">
                                        {s.enabled && <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => onSelect(s.id)}>{t("Open")}</button>}
                                        <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => exportIt(s)}>{t("Export")}</button>
                                        {canManage && <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => toggle(s)}>{s.enabled ? t("Turn off") : t("Turn on")}</button>}
                                        {canManage && !s.builtin && <button type="button" className="bkm-btn bkm-btn-sm bp-danger" onClick={() => remove(s)}>{t("Delete")}</button>}
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </section>
    );
}

// ── page ─────────────────────────────────────────────────────────────────

export function ComplianceStandardsPage() {
    const role = useSelector((s) => s.auth.role);
    const canWrite = usePermission("auditing", "write");
    const canManage = canWrite && (role === "admin" || role === "manager");
    const isAdmin = role === "admin";
    const nameOf = useBenchmarkNames();
    const [groups, setGroups] = useState([]);
    const [groupId, setGroupId] = useState("");
    const [overview, setOverview] = useState(null);
    const [all, setAll] = useState([]);
    const [selected, setSelected] = useState(null);
    const [std, setStd] = useState(null);
    const [view, setView] = useState("requirements");
    const [error, setError] = useState(null);
    const [openReq, setOpenReq] = useState(null);
    const [adding, setAdding] = useState(false);
    const [editingReq, setEditingReq] = useState(undefined);
    const [tick, setTick] = useState(0);
    const refresh = () => setTick((x) => x + 1);

    useEffect(() => {
        api.get("/api/asset-groups").then(({ data }) => setGroups(Array.isArray(data) ? data : data.groups || []))
            .catch(() => setGroups([]));
    }, []);
    useEffect(() => {
        const params = { group_id: groupId || undefined };
        api.get("/api/compliance/standards", { params }).then(({ data }) => {
            setOverview(data);
            setSelected((cur) => (cur && data.standards.some((s) => s.id === cur) ? cur : data.standards[0]?.id || null));
        }).catch((e) => setError(errorText(e, t("Could not load the standards"))));
        api.get("/api/compliance/standards", { params: { include_disabled: true } }).then(({ data }) => setAll(data.standards))
            .catch(() => setAll([]));
    }, [groupId, tick]);
    useEffect(() => {
        if (!selected) return;
        api.get(`/api/compliance/standards/${selected}`, { params: { group_id: groupId || undefined } })
            .then(({ data }) => setStd(data)).catch((e) => setError(errorText(e, t("Could not load the standard"))));
    }, [selected, groupId, tick]);

    const reportLink = std ? `/reports/new/compliance_standard?standard=${encodeURIComponent(std.key)}&group=${groupId || "all"}` : null;
    const counts = std?.summary?.counts || {};

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <h1>{t("Compliance with standards")}</h1>
                    <p>{t("How far the latest audits meet each standard: every requirement takes as evidence the audit checks of its security domains, and what no check covers is assessed by hand. The score is indicative; it does not replace an assessment by an auditor of the standard.")}</p>
                </div>
                <div className="cmp-head-actions">
                    <label className="cmp-scope">{t("Assets")}
                        <select className="bkm-select" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
                            <option value="">{t("Every asset")}</option>
                            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
                        </select>
                    </label>
                    {reportLink && <Link className="bkm-btn" to={reportLink}>{t("Report")}</Link>}
                    {canManage && <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => setAdding(true)}>{t("Add a standard")}</button>}
                </div>
            </div>
            {error && <div className="bkm-note bkm-note-error">{error}</div>}
            {overview && overview.audited_assets === 0 && (
                <div className="bkm-note bkm-note-orange">{t("No asset in this scope has been audited yet: the requirements have no evidence until the first audit.")}</div>
            )}

            {overview && (
                <div className="cmp-cards" role="tablist" aria-label={t("Standards")}>
                    {overview.standards.map((s) => {
                        const sm = s.summary || {};
                        return (
                            <button key={s.id} type="button" role="tab" aria-selected={selected === s.id}
                                    className={`cmp-card ${selected === s.id ? "is-on" : ""}`} onClick={() => { setSelected(s.id); setView("requirements"); }}>
                                <span className="cmp-card-name" dir="auto">{stdName(s)} <span className="bkm-muted">{s.version}</span></span>
                                <span className={`cmp-card-score cmp-${tone(sm.score)}`}>{pct(sm.score)}</span>
                                <ScoreBar value={sm.score} />
                                <span className="bkm-small bkm-muted">
                                    {t("{{met}} met · {{gaps}} with gaps · {{open}} to assess", {
                                        met: n(sm.counts?.met || 0), gaps: n((sm.counts?.partial || 0) + (sm.counts?.not_met || 0)),
                                        open: n(sm.counts?.not_assessed || 0) })}
                                </span>
                            </button>
                        );
                    })}
                </div>
            )}

            {std && selected === std.id && (
                <>
                    <div className="cmp-summary">
                        <div><span className="bkm-small bkm-muted">{t("Requirements")}</span><b>{n(std.summary.requirements)}</b></div>
                        <div><span className="bkm-small bkm-muted">{t("Met")}</span><b className="cmp-good-text">{n(counts.met || 0)}</b></div>
                        <div><span className="bkm-small bkm-muted">{t("Partly met")}</span><b className="cmp-fair-text">{n(counts.partial || 0)}</b></div>
                        <div><span className="bkm-small bkm-muted">{t("Not met")}</span><b className="cmp-poor-text">{n(counts.not_met || 0)}</b></div>
                        <div><span className="bkm-small bkm-muted">{t("Not assessed")}</span><b>{n(counts.not_assessed || 0)}</b></div>
                        <div><span className="bkm-small bkm-muted">{t("Coverage")}</span><b>{pct(std.summary.coverage)}</b></div>
                    </div>
                    <div className="bkm-chips" role="tablist" aria-label={t("View")}>
                        {[["requirements", t("Requirements")], ["gaps", t("Gaps")], ["domains", t("Domains of the checks")], ["standards", t("Standards")]].map(([k, label]) => (
                            <button key={k} type="button" role="tab" aria-selected={view === k}
                                    className={`bkm-chip ${view === k ? "is-on" : ""}`} onClick={() => setView(k)}>{label}</button>
                        ))}
                        {view === "requirements" && canManage && !std.builtin && (
                            <button type="button" className="bkm-btn bkm-btn-sm cmp-push" onClick={() => setEditingReq(null)}>{t("New requirement")}</button>
                        )}
                    </div>
                    {view === "requirements" && <Requirements std={std} onOpen={setOpenReq} onEdit={canManage && !std.builtin ? setEditingReq : null} />}
                    {view === "gaps" && <Gaps std={std} groupId={groupId} nameOf={nameOf} />}
                    {view === "domains" && <CheckDomains nameOf={nameOf} isAdmin={isAdmin} onChanged={refresh} />}
                    {view === "standards" && <Standards list={all} canManage={canManage} onChanged={refresh} onSelect={(id) => { setSelected(id); setView("requirements"); }} />}
                </>
            )}
            {overview && overview.standards.length === 0 && view !== "standards" && (
                <Standards list={all} canManage={canManage} onChanged={refresh} onSelect={(id) => { setSelected(id); setView("requirements"); }} />
            )}

            {openReq && <RequirementDrawer requirementId={openReq} groupId={groupId} nameOf={nameOf} canAssess={canWrite}
                                           onClose={() => setOpenReq(null)} onChanged={refresh} />}
            {adding && <StandardDrawer onClose={() => setAdding(false)}
                                       onDone={(s) => { setAdding(false); setSelected(s.id); setView("requirements"); refresh(); }} />}
            {editingReq !== undefined && std && (
                <RequirementEditor std={std} requirement={editingReq} onClose={() => setEditingReq(undefined)}
                                   onDone={() => { setEditingReq(undefined); refresh(); }} />
            )}
        </div>
    );
}
