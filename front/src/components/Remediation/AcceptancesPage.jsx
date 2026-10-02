import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../../config/api.js";
import { t } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { ACCEPTANCE_STATUS, SEVERITY, SOURCE, count, errorText, shortDate } from "./remediationFormat.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/Remediation.css";

const VIEWS = [
    ["pending", t("Awaiting approval")],
    ["active", t("Active")],
    ["expiring", t("Ending within 7 days")],
    ["ended", t("Expired or withdrawn")],
    ["rejected", t("Rejected")],
];

/** Accepted risks: every exception with its reason, compensating control, approver and end date. */
export function AcceptancesPage() {
    const [view, setView] = useState("pending");
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [deciding, setDeciding] = useState(null);   // { acc, approve }
    const [busy, setBusy] = useState(null);
    const [reload, setReload] = useState(0);
    const refresh = useCallback(() => setReload((x) => x + 1), []);

    useEffect(() => {
        let alive = true;
        api.get("/api/remediation/acceptances", { params: { view } })
            .then(({ data: d }) => { if (alive) { setData(d); setError(null); } })
            .catch(() => alive && setError(t("Could not load the risk acceptances")));
        return () => { alive = false; };
    }, [view, reload]);

    const withdraw = (acc) => {
        setBusy(acc.id);
        api.post(`/api/remediation/acceptances/${acc.id}/withdraw`)
            .then(refresh)
            .catch((e) => setError(errorText(e, t("Could not withdraw the risk acceptance"))))
            .finally(() => setBusy(null));
    };

    const items = data?.items || [];
    const counts = data?.counts || {};

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <div className="bkm-crumb"><Link to="/remediation">{t("Remediation")}</Link> › {t("Accepted Risks")}</div>
                    <h1>{t("Accepted Risks")}</h1>
                    <p>{t("Every exception with its reason, compensating control, approver and end date. An accepted finding does not count in the risk score until the acceptance ends.")}</p>
                </div>
            </div>

            <div className="bkm-toolbar">
                <div className="bkm-chips" role="group" aria-label={t("Filter risk acceptances")}>
                    {VIEWS.map(([value, label]) => (
                        <button key={value} type="button" aria-pressed={view === value}
                                className={`bkm-chip ${view === value ? "is-on" : ""}`} onClick={() => setView(value)}>
                            {label} <b>{count(counts[value])}</b>
                        </button>
                    ))}
                </div>
            </div>

            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}

            <section className="bkm-card bkm-flush">
                <div className="bkm-table-wrap">
                    <table className="bkm-table rem-table rem-list-table">
                        <thead>
                            <tr>
                                <th style={{ width: 75 }}>{t("Severity")}</th>
                                <th style={{ width: 180 }}>{t("Finding and scope")}</th>
                                <th>{t("Reason and compensating control")}</th>
                                <th style={{ width: 110 }}>{t("Requested by")}</th>
                                <th style={{ width: 95 }}>{t("Until")}</th>
                                <th style={{ width: 175 }}>{t("Status")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {items.map((a) => (
                                <tr key={a.id}>
                                    <td>
                                        <span className={`bkm-pill ${SEVERITY[a.severity]?.pill}`}>{SEVERITY[a.severity]?.label || a.severity}</span>
                                        {a.kev && <span className="bkm-pill rem-kev rem-kev-block">KEV</span>}
                                    </td>
                                    <td>
                                        <b className={a.source === "arch" ? "" : "bkm-mono"}>{a.source === "arch" ? tb(a.title) : a.ref}</b>
                                        <span className="bkm-sub">
                                            {SOURCE[a.source]} · {a.scope === "ref"
                                                ? t("every asset ({{count}} now)", { count: a.items ?? 0 })
                                                : (a.item_id ? <Link className="bkm-link" to={`/remediation?item=${a.item_id}`}>{a.asset_name || t("this finding")}</Link> : "—")}
                                        </span>
                                    </td>
                                    <td>
                                        <span className="bidi-auto rem-block">{a.justification}</span>
                                        {a.compensating_control && <span className="bkm-sub bidi-auto rem-block">{a.compensating_control}</span>}
                                        {a.decision_note && <span className="bkm-sub bidi-auto rem-block">{t("Decision note")}: {a.decision_note}</span>}
                                    </td>
                                    <td>
                                        {a.requested_by || "—"}<span className="bkm-sub">{shortDate(a.requested_at)}</span>
                                        {a.decided_by && <span className="bkm-sub">{t("Decided by {{user}}", { user: a.decided_by })}</span>}
                                    </td>
                                    <td className={`rem-nowrap ${a.expiring ? "rem-due-soon" : ""}`}>{shortDate(a.expires_at)}</td>
                                    <td>
                                        <span className={`bkm-pill ${ACCEPTANCE_STATUS[a.status]?.pill}`}>{ACCEPTANCE_STATUS[a.status]?.label || a.status}</span>
                                        <div className="alr-row-actions rem-acc-actions">
                                            {a.status === "pending" && (
                                                <>
                                                    <button type="button" className="bkm-btn bkm-btn-sm bkm-btn-primary" disabled={!a.can_decide}
                                                            title={a.decide_blocked ? tb(a.decide_blocked) : undefined}
                                                            onClick={() => setDeciding({ acc: a, approve: true })}>{t("Approve")}</button>
                                                    <button type="button" className="bkm-btn bkm-btn-sm alr-danger" disabled={!a.can_decide}
                                                            title={a.decide_blocked ? tb(a.decide_blocked) : undefined}
                                                            onClick={() => setDeciding({ acc: a, approve: false })}>{t("Reject")}</button>
                                                </>
                                            )}
                                            {a.can_withdraw && (
                                                <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy === a.id}
                                                        onClick={() => withdraw(a)}>{a.status === "pending" ? t("Cancel request") : t("Withdraw")}</button>
                                            )}
                                        </div>
                                        {a.status === "pending" && a.decide_blocked && <span className="bkm-sub">{tb(a.decide_blocked)}</span>}
                                    </td>
                                </tr>
                            ))}
                            {data && items.length === 0 && (
                                <tr><td colSpan={6}>
                                    <div className="bkm-empty">
                                        <b>{view === "pending" ? t("No request is waiting for approval") : t("Nothing here")}</b>
                                        <span>{t("Ask for a risk acceptance from a finding on the Remediation page.")}</span>
                                    </div>
                                </td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </section>

            {deciding && <DecisionModal {...deciding} onClose={() => setDeciding(null)} onDone={() => { setDeciding(null); refresh(); }} />}
        </div>
    );
}

function DecisionModal({ acc, approve, onClose, onDone }) {
    const [note, setNote] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const decide = () => {
        setBusy(true);
        api.post(`/api/remediation/acceptances/${acc.id}/${approve ? "approve" : "reject"}`, { note: note.trim() || null })
            .then(onDone)
            .catch((e) => { setError(errorText(e, t("Could not save the decision"))); setBusy(false); });
    };
    return (
        <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="rem-dec-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <div className="alr-modal">
                <h2 id="rem-dec-title">{approve ? t("Approve risk acceptance") : t("Reject risk acceptance")}</h2>
                <p><b className={acc.source === "arch" ? "" : "bkm-mono"}>{acc.source === "arch" ? tb(acc.title) : acc.ref}</b>
                    {" · "}{acc.scope === "ref" ? t("every asset") : acc.asset_name} · {t("until {{date}}", { date: shortDate(acc.expires_at) })}</p>
                <p className="bkm-muted bidi-auto">{acc.justification}</p>
                <label className="alr-lbl">{approve ? t("Note (optional)") : t("Reason for rejecting")}
                    <textarea className="bkm-select" rows={2} maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
                </label>
                {approve && <p className="alr-hint">{t("The finding leaves the risk score until the end date; the requester is reminded 7 days before.")}</p>}
                {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                <div className="alr-modal-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className={`bkm-btn ${approve ? "bkm-btn-primary" : "alr-danger"}`}
                            disabled={busy || (!approve && !note.trim())} onClick={decide}>
                        {approve ? t("Approve") : t("Reject")}
                    </button>
                </div>
            </div>
        </div>
    );
}
