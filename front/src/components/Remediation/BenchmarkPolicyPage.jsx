/**
 * Benchmark policy (/remediation/policy, GET /api/audit-policy/...): the organisation decides which
 * checks of a benchmark it does not require - one check, or a whole level such as L2 - as optional
 * (recommended, out of the score and remediation) or excluded (not applicable: also out of the risk
 * score), for every asset or one asset group, with a reason and an optional expiry. A rule applies once
 * someone other than the requester approves it; audit scores, remediation and reports then follow it.
 *
 * Views: in force, waiting for a decision, ended; every benchmark (the 17 families, audited or not) with
 * its score under the policy and without it. New rule drawer: benchmark, one check (searchable, with how many latest audits fail it) or
 * a level, decision, scope, reason, expiry.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSelector } from "react-redux";

import api from "../../config/api.js";
import { n, t } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { formatDate, formatDateTime, relativeDays } from "../../utils/dates.js";
import { usePermission } from "../../hooks/usePermission";
import { errorText } from "../AssetGroups/groupFormat.js";
import { DateInput } from "../shared/DateInput.jsx";
import "../../assets/BackupModule.css";
import "../../assets/Syslog.css";
import "../../assets/UnknownDevices.css";
import "../../assets/BenchmarkPolicy.css";

const DECISION = {
    optional: { label: t("Optional"), pill: "bkm-pill-muted", hint: t("Recommended, not required: shown in the results, but out of the score and of remediation.") },
    excluded: { label: t("Excluded"), pill: "bkm-pill-orange", hint: t("Not applicable to this organisation: out of the score, remediation and the risk score.") },
};
const STATUS = {
    pending: { label: t("Waiting for a decision"), pill: "bkm-pill-orange" },
    approved: { label: t("In force"), pill: "bkm-pill-ok" },
    rejected: { label: t("Rejected"), pill: "bkm-pill-bad" },
    revoked: { label: t("Withdrawn"), pill: "bkm-pill-muted" },
    expired: { label: t("Expired"), pill: "bkm-pill-muted" },
};
const SEVERITY = { critical: t("Critical"), high: t("High"), medium: t("Medium"), low: t("Low"), info: t("Info") };

const Mono = ({ children }) => <bdi dir="ltr" className="bkm-mono">{children}</bdi>;
const pct = (v) => (v === null || v === undefined ? "—" : n(`${Math.round(v * 10) / 10}%`));

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
            // A benchmark is the audit's device type, which is the target's id (e.g. "linux").
            for (const target of data.targets || []) out[target.id] = target.label;
            setNames(out);
        }).catch(() => setNames({}));
    }, []);
    return useCallback((b) => names[b] || b, [names]);
}

function NewRuleDrawer({ benchmarks, nameOf, onClose, onDone }) {
    const [form, setForm] = useState({
        benchmark: benchmarks[0]?.benchmark || "", mode: "check", check_number: "", level: "",
        decision: "optional", group_id: "", reason: "", expires: "",
    });
    const [checks, setChecks] = useState(null);
    const [levels, setLevels] = useState([]);
    const [total, setTotal] = useState(0);
    const [query, setQuery] = useState("");
    const [groups, setGroups] = useState([]);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        api.get("/api/asset-groups").then(({ data }) => setGroups(Array.isArray(data) ? data : data.items || []))
            .catch(() => setGroups([]));
    }, []);
    useEffect(() => {
        if (!form.benchmark) return;
        const timer = setTimeout(() => {
            api.get("/api/audit-policy/checks", { params: { benchmark: form.benchmark, q: query || undefined } })
                .then(({ data }) => { setChecks(data.checks); setLevels(data.levels); setTotal(data.total); })
                .catch((e) => setError(errorText(e, t("Could not load the checks"))));
        }, 250);
        return () => clearTimeout(timer);
    }, [form.benchmark, query]);

    const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));
    const chosen = form.mode === "check" ? form.check_number : form.level;
    const save = () => {
        setBusy(true);
        setError(null);
        api.post("/api/audit-policy/rules", {
            benchmark: form.benchmark, decision: form.decision, reason: form.reason.trim(),
            check_number: form.mode === "check" ? form.check_number : null,
            level: form.mode === "level" ? form.level : null,
            group_id: form.group_id ? Number(form.group_id) : null,
            expires_at: form.expires ? `${form.expires}T23:59:59` : null,
        }).then(onDone).catch((e) => setError(errorText(e, t("Could not save")))).finally(() => setBusy(false));
    };

    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="bp-new-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer bp-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="bp-new-title">{t("New policy rule")}</h2>
                        <span className="bkm-sub">{t("It applies once someone else approves it.")}</span>
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    <label className="alr-lbl">{t("Benchmark")}
                        <select className="bkm-select" value={form.benchmark}
                                onChange={(e) => setForm((f) => ({ ...f, benchmark: e.target.value, check_number: "", level: "" }))}>
                            {benchmarks.map((b) => (
                                <option key={b.benchmark} value={b.benchmark}>
                                    {nameOf(b.benchmark)}{b.assets === 0 ? ` (${t("not audited yet")})` : ""}
                                </option>
                            ))}
                        </select>
                    </label>
                    <div className="bp-seg" role="radiogroup" aria-label={t("Applies to")}>
                        {[["check", t("One check")], ["level", t("A whole level")]].map(([k, label]) => (
                            <button key={k} type="button" role="radio" aria-checked={form.mode === k}
                                    className={`bp-seg-btn ${form.mode === k ? "is-on" : ""}`} onClick={() => set("mode", k)}>{label}</button>
                        ))}
                    </div>
                    {form.mode === "check" ? (
                        <div className="bp-checks">
                            <input className="bkm-select" value={query} dir="auto" placeholder={t("Search number or title…")}
                                   onChange={(e) => setQuery(e.target.value)} aria-label={t("Search")} />
                            {checks !== null && total > checks.length && (
                                <span className="bkm-small bkm-muted">{t("{{shown}} of {{total}} checks; search to narrow the list.", { shown: checks.length, total })}</span>
                            )}
                            <div className="bp-check-list" role="radiogroup" aria-label={t("Check")}>
                                {checks === null ? <div className="bkm-muted bkm-small">{t("Loading…")}</div>
                                    : checks.length === 0 ? <div className="bkm-muted bkm-small">{t("No check found")}</div>
                                        : checks.map((c) => (
                                            <label key={c.check_number} className={`bp-check ${form.check_number === c.check_number ? "is-on" : ""}`}>
                                                <input type="radio" name="bp-check" checked={form.check_number === c.check_number}
                                                       onChange={() => set("check_number", c.check_number)} />
                                                <span className="bp-check-main">
                                                    <span><Mono>{c.check_number}</Mono><bdi className="bp-title" dir="auto">{c.title}</bdi></span>
                                                    <span className="bkm-small bkm-muted bp-meta">
                                                        <span>{SEVERITY[(c.severity || "").toLowerCase()] || c.severity || "—"}</span>
                                                        {c.level && <span>{c.level}</span>}
                                                        {c.failed_now > 0 && <span>{t("fails on {{value}} assets now", { value: n(c.failed_now) })}</span>}
                                                    </span>
                                                </span>
                                            </label>
                                        ))}
                            </div>
                        </div>
                    ) : (
                        <label className="alr-lbl">{t("Level")}
                            <select className="bkm-select" value={form.level} onChange={(e) => set("level", e.target.value)}>
                                <option value="">{t("Choose…")}</option>
                                {levels.map((l) => <option key={l} value={l}>{l}</option>)}
                            </select>
                        </label>
                    )}
                    <fieldset className="bp-decision">
                        <legend>{t("Decision")}</legend>
                        {Object.entries(DECISION).map(([k, d]) => (
                            <label key={k} className={`bp-choice ${form.decision === k ? "is-on" : ""}`}>
                                <input type="radio" name="bp-decision" checked={form.decision === k} onChange={() => set("decision", k)} />
                                <span><b>{d.label}</b><span className="bkm-small bkm-muted">{d.hint}</span></span>
                            </label>
                        ))}
                    </fieldset>
                    <label className="alr-lbl">{t("Assets")}
                        <select className="bkm-select" value={form.group_id} onChange={(e) => set("group_id", e.target.value)}>
                            <option value="">{t("Every asset")}</option>
                            {groups.map((g) => <option key={g.id} value={g.id}>{t("Group: {{name}}", { name: g.name })}</option>)}
                        </select>
                    </label>
                    <label className="alr-lbl">{t("Reason")}
                        <textarea className="bkm-select bp-reason" value={form.reason} maxLength={2000} dir="auto" rows={3}
                                  placeholder={t("Why the organisation does not require it (at least 10 characters)")}
                                  onChange={(e) => set("reason", e.target.value)} />
                    </label>
                    <label className="alr-lbl">{t("Until (optional)")}
                        <DateInput className="bkm-select" value={form.expires} min={dayOffset(1)}
                                   onChange={(e) => set("expires", e.target.value)} />
                    </label>
                    {(form.mode === "level" || form.decision === "excluded") && (
                        <p className="bkm-small bkm-muted">{t("A whole level, or excluding a high or critical check, is decided by an administrator.")}</p>
                    )}
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                </div>
                <footer className="bkm-drawer-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" onClick={save}
                            disabled={busy || !chosen || form.reason.trim().length < 10}>
                        {busy ? t("Sending…") : t("Ask for approval")}
                    </button>
                </footer>
            </aside>
        </div>
    );
}

function DecideDrawer({ rule, approve, nameOf, onClose, onDone }) {
    const [note, setNote] = useState("");
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const save = () => {
        setBusy(true);
        api.post(`/api/audit-policy/rules/${rule.id}/decide`, { approve, note: note.trim() || null })
            .then(onDone).catch((e) => setError(errorText(e, t("Could not save")))).finally(() => setBusy(false));
    };
    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="bp-dec-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer ud-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="bp-dec-title">{approve ? t("Approve the rule") : t("Reject the rule")}</h2>
                        <span className="bkm-sub">{nameOf(rule.benchmark)}</span>
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    <dl className="ud-facts">
                        <dt>{t("Check")}</dt><dd>{rule.check_number ? <><Mono>{rule.check_number}</Mono><bdi className="bp-title" dir="auto">{rule.check_title}</bdi></> : t("Level {{level}}", { level: rule.level })}</dd>
                        <dt>{t("Decision")}</dt><dd>{DECISION[rule.decision].label}</dd>
                        <dt>{t("Assets")}</dt><dd dir="auto">{rule.group ? rule.group.name : t("Every asset")}</dd>
                        <dt>{t("Reason")}</dt><dd dir="auto">{rule.reason}</dd>
                        <dt>{t("Asked by")}</dt><dd>{rule.requested_by || "—"}</dd>
                    </dl>
                    {approve && <p className="bkm-small">{t("Once approved, every audit of this benchmark is scored again under the rule.")}</p>}
                    <label className="alr-lbl">{t("Note (optional)")}
                        <input className="bkm-select" value={note} maxLength={1000} dir="auto" onChange={(e) => setNote(e.target.value)} />
                    </label>
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                </div>
                <footer className="bkm-drawer-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className={`bkm-btn ${approve ? "bkm-btn-primary" : "bp-danger"}`} onClick={save} disabled={busy}>
                        {approve ? t("Approve") : t("Reject")}
                    </button>
                </footer>
            </aside>
        </div>
    );
}

function RuleTable({ rules, nameOf, onDecide, onEnd }) {
    return (
        <div className="bkm-table-wrap">
            <table className="bkm-table ud-table">
                <thead>
                    <tr>
                        <th>{t("Benchmark and check")}</th><th>{t("Decision")}</th><th>{t("Assets")}</th>
                        <th>{t("Reason")}</th><th>{t("Who and when")}</th><th />
                    </tr>
                </thead>
                <tbody>
                    {rules.map((r) => (
                        <tr key={r.id}>
                            <td>
                                <div className="ud-addr">
                                    <b>{nameOf(r.benchmark)}</b>
                                    {r.check_number
                                        ? <span><Mono>{r.check_number}</Mono><bdi className="bp-title bkm-small" dir="auto">{r.check_title}</bdi></span>
                                        : <span className="bkm-small">{t("Level {{level}}", { level: r.level })}</span>}
                                    {r.severity && <span className="bkm-small bkm-muted">{SEVERITY[r.severity.toLowerCase()] || r.severity}</span>}
                                </div>
                            </td>
                            <td>
                                <div className="bp-stack">
                                    <span className={`bkm-pill ${DECISION[r.decision].pill}`}>{DECISION[r.decision].label}</span>
                                    <span className={`bkm-pill ${STATUS[r.status].pill}`}>{STATUS[r.status].label}</span>
                                    {r.in_force && r.results > 0 && <span className="bkm-small bkm-muted">{t("{{value}} results in the latest audits", { value: n(r.results) })}</span>}
                                </div>
                            </td>
                            <td dir="auto">{r.group ? r.group.name : t("Every asset")}</td>
                            <td><span className="bp-reason-text" dir="auto">{r.reason}</span>
                                {r.decision_note && <span className="bkm-sub" dir="auto">{t("Note: {{note}}", { note: r.decision_note })}</span>}</td>
                            <td className="bkm-small">
                                <div className="bp-stack">
                                    <span title={formatDateTime(r.requested_at)}>{t("Asked by {{user}}, {{when}}", { user: r.requested_by || "—", when: relativeDays(r.requested_at) })}</span>
                                    {r.decided_by && <span title={formatDateTime(r.decided_at)}>{t("Decided by {{user}}, {{when}}", { user: r.decided_by, when: relativeDays(r.decided_at) })}</span>}
                                    {r.expires_at && <span className={r.in_force ? "" : "bkm-muted"}>{t("Until {{date}}", { date: formatDate(r.expires_at) })}</span>}
                                </div>
                            </td>
                            <td className="ud-actions">
                                <div className="bp-stack bp-end">
                                    {r.status === "pending" && !r.can_decide && (
                                        <span>
                                            <button type="button" className="bkm-btn bkm-btn-sm bkm-btn-primary" onClick={() => onDecide(r, true)}>{t("Approve")}</button>
                                            <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => onDecide(r, false)}>{t("Reject")}</button>
                                        </span>
                                    )}
                                    {r.status === "pending" && r.can_decide && <span className="bkm-small bkm-muted bp-why">{tb(r.can_decide)}</span>}
                                    {r.can_end && (
                                        <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => onEnd(r)}>
                                            {r.status === "pending" ? t("Withdraw") : t("End the rule")}
                                        </button>
                                    )}
                                </div>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function Benchmarks({ data, nameOf }) {
    return (
        <section className="bkm-card bkm-flush">
            <div className="bkm-card-head">
                <div>
                    <h2>{t("Benchmarks")}</h2>
                    <p>{t("Every benchmark, and for each asset's latest audit the average score under the policy and without it, and how many results the policy covers. Rules can be set before a benchmark's first audit.")}</p>
                </div>
            </div>
            {data.benchmarks.length === 0 ? <div className="bkm-empty"><b>{t("No audit yet")}</b></div> : (
                <div className="bkm-table-wrap">
                    <table className="bkm-table">
                        <thead><tr><th>{t("Benchmark")}</th><th>{t("Checks")}</th><th>{t("Assets audited")}</th><th>{t("Score under the policy")}</th>
                            <th>{t("Without the policy")}</th><th>{t("Optional results")}</th><th>{t("Excluded results")}</th></tr></thead>
                        <tbody>
                            {data.benchmarks.map((b) => (
                                <tr key={b.benchmark}>
                                    <td><b>{nameOf(b.benchmark)}</b></td>
                                    <td>{n(b.checks)}</td>
                                    <td>{b.assets ? n(b.assets) : <span className="bkm-muted">{t("not audited yet")}</span>}</td>
                                    <td><b>{pct(b.score)}</b></td>
                                    <td className="bkm-muted">{pct(b.raw_score)}</td>
                                    <td>{n(b.optional)}</td>
                                    <td>{n(b.excluded)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </section>
    );
}

export function BenchmarkPolicyPage() {
    const role = useSelector((s) => s.auth.role);
    const canWrite = usePermission("auditing", "write");
    const nameOf = useBenchmarkNames();
    const [view, setView] = useState("in_force");
    const [overview, setOverview] = useState(null);
    const [rules, setRules] = useState(null);
    const [error, setError] = useState(null);
    const [notice, setNotice] = useState(null);
    const [creating, setCreating] = useState(false);
    const [deciding, setDeciding] = useState(null);

    const load = useCallback(() => {
        api.get("/api/audit-policy/benchmarks").then(({ data }) => setOverview(data))
            .catch((e) => setError(errorText(e, t("Could not load the policy"))));
        if (view !== "benchmarks") {
            api.get("/api/audit-policy/rules", { params: { status: view } }).then(({ data }) => setRules(data))
                .catch((e) => setError(errorText(e, t("Could not load the policy"))));
        }
    }, [view]);
    useEffect(() => { load(); }, [load]);

    const end = (r) => api.post(`/api/audit-policy/rules/${r.id}/end`)
        .then(() => { setNotice(r.status === "pending" ? t("Request withdrawn.") : t("The rule ended; the checks count again.")); load(); })
        .catch((e) => setNotice(errorText(e, t("Could not save"))));
    const decideAllowed = role === "admin" || role === "manager";
    const benchmarks = useMemo(() => overview?.benchmarks || [], [overview]);

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <h1>{t("Benchmark policy")}</h1>
                    <p>{t("The organisation's decisions on the audit benchmarks: checks it does not require, for every asset or a group. Audit scores, remediation, the risk score and reports follow the rules in force.")}</p>
                </div>
                {canWrite && benchmarks.length > 0 && (
                    <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => setCreating(true)}>{t("New rule")}</button>
                )}
            </div>
            {error && <div className="bkm-note bkm-note-error">{error}</div>}
            {notice && <div className="bkm-note bkm-note-ok">{notice}</div>}
            {overview && overview.pending > 0 && decideAllowed && view !== "pending" && (
                <div className="bkm-note bkm-note-orange sl-banner">
                    <span className="sl-banner-text">{t("{{value}} rules are waiting for a decision.", { value: n(overview.pending) })}</span>
                    <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => setView("pending")}>{t("Show")}</button>
                </div>
            )}

            <div className="bkm-chips" role="tablist" aria-label={t("Benchmark policy")}>
                {[["in_force", t("In force"), overview?.in_force], ["pending", t("Waiting for a decision"), overview?.pending],
                  ["ended", t("Ended")], ["benchmarks", t("Benchmarks")]].map(([k, label, count]) => (
                    <button key={k} type="button" role="tab" aria-selected={view === k}
                            className={`bkm-chip ${view === k ? "is-on" : ""}`} onClick={() => { setRules(null); setView(k); }}>
                        {label}{count !== undefined && <span className="ud-count">{n(count)}</span>}
                    </button>
                ))}
            </div>

            {view === "benchmarks" && overview && <Benchmarks data={overview} nameOf={nameOf} />}
            {view !== "benchmarks" && (
                <section className="bkm-card bkm-flush">
                    {rules && rules.length === 0 && (
                        <div className="bkm-empty">
                            <b>{view === "in_force" ? t("Every check is required") : t("Nothing here")}</b>
                            {view === "in_force" && <span>{t("No rule is in force: every check of every benchmark counts in the score.")}</span>}
                        </div>
                    )}
                    {rules && rules.length > 0 && <RuleTable rules={rules} nameOf={nameOf} onDecide={(r, approve) => setDeciding({ r, approve })} onEnd={end} />}
                </section>
            )}

            {creating && (
                <NewRuleDrawer benchmarks={benchmarks} nameOf={nameOf} onClose={() => setCreating(false)}
                               onDone={() => { setCreating(false); setNotice(t("Sent for approval.")); setView("pending"); load(); }} />
            )}
            {deciding && (
                <DecideDrawer rule={deciding.r} approve={deciding.approve} nameOf={nameOf} onClose={() => setDeciding(null)}
                              onDone={() => { setDeciding(null); setNotice(deciding.approve ? t("Approved: the audits are scored again.") : t("Rejected.")); load(); }} />
            )}
        </div>
    );
}

export default BenchmarkPolicyPage;
