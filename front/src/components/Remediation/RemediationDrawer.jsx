import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import api from "../../config/api.js";
import { t, n } from "../../i18n";
import { formatDateTime } from "../../utils/dates.js";
import { AcceptanceModal } from "./AcceptanceModal.jsx";
import {
    ACCEPTANCE_STATUS, SEVERITY, SOURCE, STATUS, dueClass, dueText, errorText, eventText, itemTitle, shortDate, sourceLink,
} from "./remediationFormat.js";

const toDateInput = (iso) => (iso ? iso.slice(0, 10) : "");

/** One finding: what it is, who owns it, by when, and its history. */
export function RemediationDrawer({ itemId, canWrite, onClose, onChanged }) {
    const [item, setItem] = useState(null);
    const [users, setUsers] = useState([]);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const [note, setNote] = useState("");
    const [asking, setAsking] = useState(false);

    useEffect(() => {
        let alive = true;
        api.get(`/api/remediation/items/${itemId}`)
            .then(({ data }) => alive && setItem(data))
            .catch((e) => alive && setError(e.response?.status === 404 ? t("This finding no longer exists") : t("Could not load the finding")));
        return () => { alive = false; };
    }, [itemId]);

    useEffect(() => {
        api.get("/api/remediation/users").then(({ data }) => setUsers(data)).catch(() => {});
    }, []);

    useEffect(() => {
        const onKey = (e) => e.key === "Escape" && !asking && onClose();
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onClose, asking]);

    const save = (patch) => {
        setBusy(true);
        setError(null);
        api.patch(`/api/remediation/items/${itemId}`, patch)
            .then(({ data }) => { setItem(data); onChanged(); })
            .catch((e) => setError(errorText(e, t("Could not save the change"))))
            .finally(() => setBusy(false));
    };

    const active = item && ["open", "in_progress", "pending_verification"].includes(item.status);
    const editable = canWrite && active;
    const link = item && sourceLink(item);
    const d = item?.detail || {};

    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="rem-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer rem-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="rem-title">
                            {item ? (item.source === "arch" ? itemTitle(item) : <span className="bkm-mono">{item.ref}</span>) : t("Finding")}
                            {item?.asset_name ? ` · ${item.asset_name}` : ""}
                        </h2>
                        {item && (
                            <div className="rem-pills">
                                <span className={`bkm-pill ${SEVERITY[item.severity]?.pill}`}>{SEVERITY[item.severity]?.label}</span>
                                {item.kev && <span className="bkm-pill rem-kev">{t("Exploited in the wild (CISA KEV)")}</span>}
                                <span className={`bkm-pill ${STATUS[item.status]?.pill}`}>{STATUS[item.status]?.label}</span>
                                {item.overdue && <span className="bkm-pill rem-sev-critical">{dueText(item)}</span>}
                            </div>
                        )}
                    </div>
                    <button type="button" className="bkm-icon-btn" aria-label={t("Close")} onClick={onClose}>×</button>
                </header>

                <div className="bkm-drawer-body">
                    {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                    {!item && !error && <div className="bkm-muted">{t("Loading…")}</div>}
                    {item && (
                        <>
                            <section className="rem-sec">
                                <h3 className="bkm-h3">{t("Finding")}</h3>
                                {item.source !== "arch" && <p className="rem-desc bidi-auto">{itemTitle(item)}</p>}
                                <div className="bkm-kv"><span>{t("Asset")}</span><b>{item.asset_name || "—"}{item.ip_address && <span className="bkm-mono rem-ip">{item.ip_address}</span>}</b></div>
                                <div className="bkm-kv"><span>{t("Source")}</span><b>{SOURCE[item.source]}{link && <> · <Link className="bkm-link" to={link.to}>{link.label}</Link></>}</b></div>
                                {item.source === "cve" && <>
                                    <div className="bkm-kv"><span>{t("Installed")}</span><b className="bkm-mono">{[d.product, d.installed].filter(Boolean).join(" ") || "—"}</b></div>
                                    <div className="bkm-kv"><span>{t("Fixed in")}</span>{d.fixed_in ? <b className="bkm-mono">{d.fixed_in}</b> : <b>{t("see the vendor advisory")}</b>}</div>
                                    {d.cvss != null && <div className="bkm-kv"><span>CVSS</span><b>{n(d.cvss)}</b></div>}
                                </>}
                                {item.source === "audit" && <>
                                    <div className="bkm-kv"><span>{t("Check")}</span><b className="bkm-mono">{d.check_number}{d.vdom ? ` · ${d.vdom}` : ""}</b></div>
                                    {d.evidence && <pre className="rem-evidence">{d.evidence}</pre>}
                                </>}
                                {item.source === "arch" && d.recommendation && (
                                    <div className="bkm-kv"><span>{t("Recommendation")}</span><b className="bidi-auto">{itemTitle({ ...item, title: d.recommendation })}</b></div>
                                )}
                                <div className="bkm-kv"><span>{t("First seen")}</span><b>{shortDate(item.first_seen_at)}{item.reopened ? ` · ${t("reopened {{count}} times", { count: item.reopened })}` : ""}</b></div>
                            </section>

                            <section className="rem-sec">
                                <h3 className="bkm-h3">{t("Follow-up")}</h3>
                                <div className="alr-grid-2">
                                    <label className="alr-lbl">{t("Owner")}
                                        <select className="bkm-select" value={item.owner_id ?? ""} disabled={!editable || busy}
                                                onChange={(e) => save({ owner_id: e.target.value ? Number(e.target.value) : null })}>
                                            <option value="">{t("Unassigned")}</option>
                                            {users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
                                        </select>
                                    </label>
                                    <label className="alr-lbl">{t("Deadline")}
                                        <input type="date" className="bkm-select" value={toDateInput(item.due_at)} disabled={!editable || busy}
                                               onChange={(e) => e.target.value && save({ due_date: e.target.value })} />
                                        <span className={`alr-hint ${dueClass(item)}`}>
                                            {shortDate(item.due_at)}{active ? ` · ${dueText(item)}` : ""}
                                            {item.due_custom && editable && <> · <button type="button" className="bkm-link" onClick={() => save({ due_date: null })}>{t("use the standard deadline")}</button></>}
                                        </span>
                                    </label>
                                </div>
                                {item.status === "accepted" && item.acceptance && (
                                    <div className="bkm-note rem-note-accepted">{t("Risk accepted until {{date}}. It does not count in the risk score until then.", { date: shortDate(item.acceptance.expires_at) })}</div>
                                )}
                                {item.status === "accepted" && !item.acceptance && (
                                    <div className="bkm-note">{t("Accepted on the Architecture Validation page.")}</div>
                                )}
                                {item.status === "resolved" && (
                                    <div className="bkm-note bkm-note-ok">{t("Closed on {{date}}.", { date: shortDate(item.resolved_at) })}</div>
                                )}
                                {editable && (
                                    <>
                                        <label className="alr-lbl rem-note-field">{t("Note")}
                                            <textarea className="bkm-select" rows={2} maxLength={2000} value={note}
                                                      onChange={(e) => setNote(e.target.value)} placeholder={t("What is being done, change request number…")} />
                                        </label>
                                        <div className="bkm-actions rem-actions">
                                            <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !note.trim()}
                                                    onClick={() => { save({ note: note.trim() }); setNote(""); }}>{t("Add note")}</button>
                                            {item.status !== "in_progress" && (
                                                <button type="button" className="bkm-btn" disabled={busy} onClick={() => save({ status: "in_progress" })}>{t("Start work")}</button>
                                            )}
                                            {item.status !== "pending_verification" && (
                                                <button type="button" className="bkm-btn" disabled={busy} onClick={() => save({ status: "pending_verification" })}>{t("Mark fixed")}</button>
                                            )}
                                            <button type="button" className="bkm-btn" disabled={busy} onClick={() => setAsking(true)}>{t("Request risk acceptance")}</button>
                                        </div>
                                        <p className="alr-hint">{t("\"Mark fixed\" waits for the next audit or CVE check: the finding closes only when its source no longer reports it.")}</p>
                                    </>
                                )}
                            </section>

                            {item.acceptances?.length > 0 && (
                                <section className="rem-sec">
                                    <h3 className="bkm-h3">{t("Risk acceptances")}</h3>
                                    {item.acceptances.map((a) => (
                                        <div key={a.id} className="rem-acc">
                                            <div className="bkm-row-between">
                                                <b>{a.scope === "ref" ? t("{{ref}} on every asset", { ref: a.ref }) : t("This finding only")}</b>
                                                <span className={`bkm-pill ${ACCEPTANCE_STATUS[a.status]?.pill}`}>{ACCEPTANCE_STATUS[a.status]?.label}</span>
                                            </div>
                                            <p className="bidi-auto">{a.justification}</p>
                                            <span className="bkm-sub">
                                                {t("Requested by {{user}} · until {{date}}", { user: a.requested_by || "—", date: shortDate(a.expires_at) })}
                                                {a.decided_by ? ` · ${t("decided by {{user}}", { user: a.decided_by })}` : ""}
                                            </span>
                                        </div>
                                    ))}
                                    <Link className="bkm-link" to="/remediation/acceptances">{t("All accepted risks")}</Link>
                                </section>
                            )}

                            <section className="rem-sec">
                                <h3 className="bkm-h3">{t("History")}</h3>
                                <ol className="rem-history">
                                    {[...(item.events || [])].reverse().map((e, i) => (
                                        <li key={i} className={`rem-ev-${e.kind}`}>
                                            <span className="bidi-auto">{e.user ? <b>{e.user}: </b> : null}{eventText(e)}</span>
                                            <time>{formatDateTime(e.at)}</time>
                                        </li>
                                    ))}
                                </ol>
                            </section>
                        </>
                    )}
                </div>
            </aside>
            {asking && item && (
                <AcceptanceModal item={item} onClose={() => setAsking(false)}
                                 onSent={() => { setAsking(false); api.get(`/api/remediation/items/${itemId}`).then(({ data }) => setItem(data)); onChanged(); }} />
            )}
        </div>
    );
}
