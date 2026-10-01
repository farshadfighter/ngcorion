import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import api from "../../config/api.js";
import { usePermission } from "../../hooks/usePermission";
import { formatWhen } from "../../utils/dates.js";
import { CHANNEL_LABEL, SEVERITY } from "../Alerts/alertFormat.js";
import { RuleEditor } from "./RuleEditor.jsx";
import { ChannelsTab } from "./ChannelsTab.jsx";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";

const TABS = [["rules", "Rules"], ["channels", "Channels"], ["log", "Delivery log"]];

function Switch({ on, onChange, label, disabled }) {
    return (
        <button type="button" role="switch" aria-checked={on} aria-label={label} disabled={disabled}
                className={`alr-switch ${on ? "is-on" : ""}`} onClick={() => onChange(!on)}>
            <i />
        </button>
    );
}

function RulesTab({ canWrite, channels }) {
    const [data, setData] = useState(null);
    const [events, setEvents] = useState([]);
    const [options, setOptions] = useState(null);
    const [error, setError] = useState(null);
    const [editing, setEditing] = useState(null);     // rule, or {} for a new one
    const [reload, setReload] = useState(0);

    useEffect(() => {
        let alive = true;
        Promise.all([api.get("/api/notifications/rules"), api.get("/api/notifications/events"),
            api.get("/api/notifications/options")])
            .then(([r, e, o]) => { if (alive) { setData(r.data); setEvents(e.data); setOptions(o.data); setError(null); } })
            .catch((e) => alive && setError(e.response?.data?.detail || "Could not load the rules"));
        return () => { alive = false; };
    }, [reload]);

    const toggle = (rule, enabled) => {
        if (!enabled && rule.open_alerts && !window.confirm(
            `Turn off "${rule.name}"? Its ${rule.open_alerts} open alert(s) will be closed.`)) return;
        api.patch(`/api/notifications/rules/${rule.id}/enabled`, { enabled })
            .then(() => setReload((n) => n + 1))
            .catch((e) => setError(e.response?.data?.detail || "Could not change the rule"));
    };

    return (
        <>
            <div className="bkm-row-between">
                <p className="bkm-muted alr-lead">Which events raise an alert, how urgent they are, and who hears about them where.</p>
                {canWrite && <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => setEditing({})}>+ New rule</button>}
            </div>
            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
            <section className="bkm-card bkm-flush">
                <div className="bkm-table-wrap">
                    <table className="bkm-table alr-rules">
                        <thead>
                            <tr>
                                <th style={{ width: 56 }}>On</th>
                                <th>Rule</th>
                                <th style={{ width: 100 }}>Severity</th>
                                <th style={{ width: 230 }}>Channels</th>
                                <th style={{ width: 190 }}>Who</th>
                                <th style={{ width: 130 }}>Last fired</th>
                            </tr>
                        </thead>
                        {(data?.groups || []).map((g) => (
                            <tbody key={g.module}>
                                <tr className="alr-group"><td colSpan={6}>{g.label}</td></tr>
                                {g.rules.map((r) => (
                                    <tr key={r.id} className={r.enabled ? "" : "alr-off"}>
                                        <td><Switch on={r.enabled} label={`${r.enabled ? "Turn off" : "Turn on"} ${r.name}`}
                                                    disabled={!canWrite} onChange={(v) => toggle(r, v)} /></td>
                                        <td>
                                            <button type="button" className="bkm-link alr-rule-name" onClick={() => setEditing(r)}>{r.name}</button>
                                            <span className="bkm-sub">
                                                {r.summary}
                                                {r.asset_scope !== "all" ? ` · ${r.asset_scope === "specific" ? "specific assets" : "matching assets"}` : ""}
                                                {r.open_alerts ? ` · ${r.open_alerts} open` : ""}
                                            </span>
                                        </td>
                                        <td><span className={`bkm-pill ${SEVERITY[r.severity]?.pill}`}>{SEVERITY[r.severity]?.label}</span></td>
                                        <td>
                                            <span className="alr-ch">In-app</span>
                                            {r.channel_labels.map((c) => <span key={c} className="alr-ch">{c}</span>)}
                                        </td>
                                        <td className="alr-who">{r.who}</td>
                                        <td className="bkm-muted">{r.last_fired_at ? formatWhen(r.last_fired_at) : "Never"}</td>
                                    </tr>
                                ))}
                            </tbody>
                        ))}
                    </table>
                </div>
            </section>
            {editing && (
                <RuleEditor rule={editing.id ? editing : null} events={events} options={options} channels={channels}
                            onClose={() => setEditing(null)}
                            onSaved={() => { setEditing(null); setReload((n) => n + 1); }}
                            onDeleted={() => { setEditing(null); setReload((n) => n + 1); }} />
            )}
        </>
    );
}

const LOG_PAGE = 50;
const STATUS_PILL = { sent: "bkm-pill-ok", failed: "bkm-pill-bad", pending: "bkm-pill-run", skipped: "bkm-pill-muted" };

function DeliveryLog() {
    const [channel, setChannel] = useState("");
    const [status, setStatus] = useState("");
    const [offset, setOffset] = useState(0);
    const [page, setPage] = useState(null);
    const [error, setError] = useState(null);

    useEffect(() => {
        let alive = true;
        const params = { limit: LOG_PAGE, offset };
        if (channel) params.channel = channel;
        if (status) params.status = status;
        api.get("/api/notifications/deliveries", { params })
            .then(({ data }) => { if (alive) { setPage(data); setError(null); } })
            .catch((e) => alive && setError(e.response?.data?.detail || "Could not load the delivery log"));
        return () => { alive = false; };
    }, [channel, status, offset]);

    const to = page ? Math.min(offset + LOG_PAGE, page.total) : 0;
    return (
        <>
            <div className="bkm-toolbar">
                <p className="bkm-muted alr-lead">Every message sent for an alert, with failures and retries. Kept for 90 days.</p>
                <div className="bkm-row-gap">
                    <select className="bkm-select" aria-label="Channel" value={channel} onChange={(e) => { setChannel(e.target.value); setOffset(0); }}>
                        <option value="">All channels</option>
                        {Object.entries(CHANNEL_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                    </select>
                    <select className="bkm-select" aria-label="Status" value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }}>
                        <option value="">Any result</option>
                        <option value="sent">Sent</option>
                        <option value="failed">Failed</option>
                        <option value="pending">Waiting to retry</option>
                        <option value="skipped">Skipped</option>
                    </select>
                </div>
            </div>
            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
            <section className="bkm-card bkm-flush">
                <div className="bkm-table-wrap">
                    <table className="bkm-table">
                        <thead>
                            <tr><th style={{ width: 150 }}>When</th><th>Message</th><th style={{ width: 120 }}>Channel</th>
                                <th style={{ width: 220 }}>To</th><th style={{ width: 230 }}>Result</th></tr>
                        </thead>
                        <tbody>
                            {(page?.items || []).map((d) => (
                                <tr key={d.id}>
                                    <td className="bkm-nowrap">{formatWhen(d.created_at)}</td>
                                    <td>
                                        <span className="bkm-strong">{d.subject}</span>
                                        <span className="bkm-sub">{d.rule_name || (d.kind === "test" ? "Test" : "")}
                                            {d.kind === "reminder" ? " · reminder" : d.kind === "resolved" ? " · resolved notice" : ""}</span>
                                    </td>
                                    <td>{CHANNEL_LABEL[d.channel] || d.channel}</td>
                                    <td><span className="bkm-mono alr-clip" title={d.recipient || ""}>{d.recipient || "—"}</span></td>
                                    <td>
                                        <span className={`bkm-pill ${STATUS_PILL[d.status]}`}>
                                            {d.status === "pending" ? (d.attempts ? "Retrying" : "Queued") : d.status[0].toUpperCase() + d.status.slice(1)}
                                        </span>
                                        {d.attempts > 1 && d.status === "sent" && <span className="bkm-sub">after {d.attempts} tries</span>}
                                        {d.error && d.status !== "sent" && <span className="bkm-sub alr-err" title={d.error}>{d.error}</span>}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                {page && page.items.length === 0 && (
                    <div className="bkm-empty"><b>No messages yet</b><span className="bkm-muted">Messages appear here once a rule with email, SMS, syslog or a webhook fires.</span></div>
                )}
                {page && page.total > LOG_PAGE && (
                    <div className="bkm-card-foot bkm-row-between">
                        <span>{offset + 1}–{to} of {page.total}</span>
                        <span className="bkm-actions">
                            <button type="button" className="bkm-btn bkm-btn-sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - LOG_PAGE))}>Previous</button>
                            <button type="button" className="bkm-btn bkm-btn-sm" disabled={to >= page.total} onClick={() => setOffset(offset + LOG_PAGE)}>Next</button>
                        </span>
                    </div>
                )}
            </section>
        </>
    );
}

/** System › Notifications: rules, channels and the delivery log. */
export function NotificationsPage() {
    const [params, setParams] = useSearchParams();
    const tab = TABS.some(([k]) => k === params.get("tab")) ? params.get("tab") : "rules";
    const canWrite = usePermission("system_config", "write");
    const [channels, setChannels] = useState(null);
    const [channelsError, setChannelsError] = useState(null);
    const [reload, setReload] = useState(0);
    const reloadChannels = useCallback(() => setReload((n) => n + 1), []);

    useEffect(() => {
        let alive = true;
        api.get("/api/notifications/channels")
            .then(({ data }) => { if (alive) { setChannels(data); setChannelsError(null); } })
            .catch((e) => alive && setChannelsError(e.response?.data?.detail || "Could not load the channels"));
        return () => { alive = false; };
    }, [reload]);

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <h1>Notifications</h1>
                    <p>Email, SMS and syslog use the servers set in <Link to="/settings/system">System Configuration</Link>. Alerts themselves are on the <Link to="/alerts">Alerts</Link> page.</p>
                </div>
            </div>
            <div className="alr-tabs" role="tablist" aria-label="Notifications">
                {TABS.map(([key, label]) => (
                    <button key={key} type="button" role="tab" aria-selected={tab === key}
                            className={`alr-tab ${tab === key ? "is-on" : ""}`}
                            onClick={() => setParams(key === "rules" ? {} : { tab: key })}>{label}</button>
                ))}
            </div>
            {tab === "rules" && <RulesTab canWrite={canWrite} channels={channels} />}
            {tab === "channels" && <ChannelsTab channels={channels} error={channelsError} canWrite={canWrite} onChanged={reloadChannels} />}
            {tab === "log" && <DeliveryLog />}
        </div>
    );
}
