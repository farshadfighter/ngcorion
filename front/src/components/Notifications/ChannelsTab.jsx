import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import api from "../../config/api.js";
import { formatWhen } from "../../utils/dates.js";

function Stats({ s }) {
    if (!s) return "—";
    return `${s.sent} · ${s.failed || 0} failed${s.pending ? ` · ${s.pending} retrying` : ""}`;
}

function Card({ tile, icon, title, sub, status, children, actions }) {
    return (
        <section className="bkm-card alr-chan">
            <div className="alr-chan-head">
                <span className="alr-tile" style={{ background: tile }} aria-hidden="true">{icon}</span>
                <div className="alr-chan-title"><h2>{title}</h2><p>{sub}</p></div>
                {status}
            </div>
            <div className="alr-chan-body">{children}</div>
            {actions && <div className="alr-chan-acts">{actions}</div>}
        </section>
    );
}

const Ready = () => <span className="bkm-pill bkm-pill-ok">Ready</span>;
const NotSet = () => <span className="bkm-pill bkm-pill-muted">Not set up</span>;

const ICONS = {
    bell: <path d="M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.9 1.9 0 0 0 3.4 0" />,
    mail: <path d="M3 6h18v12H3zM3 7l9 6 9-6" />,
    phone: <path d="M7 3h10a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1zM11 18h2" />,
    lines: <path d="M4 6h16M4 12h16M4 18h10" />,
    link: <path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" />,
};
const Icon = ({ name }) => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">{ICONS[name]}</svg>
);

function Kv({ k, children, warn }) {
    return <div className="bkm-kv"><span>{k}</span><b className={warn ? "bkm-orange" : ""}>{children}</b></div>;
}

function TestButton({ channel, needsTo, placeholder, disabled }) {
    const [open, setOpen] = useState(false);
    const [to, setTo] = useState("");
    const [result, setResult] = useState(null);
    const [busy, setBusy] = useState(false);
    const send = () => {
        setBusy(true);
        setResult(null);
        api.post("/api/notifications/channels/test", { channel, to: to || null })
            .then(({ data }) => setResult(data))
            .catch((e) => setResult({ success: false, message: e.response?.data?.detail || "Test failed" }))
            .finally(() => setBusy(false));
    };
    if (!needsTo) {
        return (
            <span className="alr-test">
                <button type="button" className="bkm-btn bkm-btn-sm" disabled={disabled || busy} onClick={send}>{busy ? "Sending…" : "Send test"}</button>
                {result && <span className={result.success ? "bkm-green" : "bkm-red"} role="status">{result.message}</span>}
            </span>
        );
    }
    return (
        <span className="alr-test">
            {open ? (
                <span className="alr-row-gap">
                    <input className="bkm-select alr-test-to" value={to} onChange={(e) => setTo(e.target.value)} placeholder={placeholder}
                           aria-label={placeholder} onKeyDown={(e) => e.key === "Enter" && send()} />
                    <button type="button" className="bkm-btn bkm-btn-sm bkm-btn-primary" disabled={busy} onClick={send}>{busy ? "Sending…" : "Send"}</button>
                </span>
            ) : (
                <button type="button" className="bkm-btn bkm-btn-sm" disabled={disabled} onClick={() => setOpen(true)}>Send test</button>
            )}
            {result && <span className={result.success ? "bkm-green" : "bkm-red"} role="status">{result.message}</span>}
        </span>
    );
}

function WebhookModal({ hook, onClose, onSaved }) {
    const [name, setName] = useState(hook?.name || "");
    const [url, setUrl] = useState(hook?.url || "");
    const [enabled, setEnabled] = useState(hook ? hook.enabled : true);
    const [rotate, setRotate] = useState(false);
    const [error, setError] = useState(null);
    const [secret, setSecret] = useState(null);
    const [busy, setBusy] = useState(false);
    const first = useRef(null);
    useEffect(() => { first.current?.focus(); }, []);

    const save = () => {
        setBusy(true);
        setError(null);
        const body = { name, url, enabled, rotate_secret: rotate };
        const req = hook ? api.put(`/api/notifications/webhooks/${hook.id}`, body) : api.post("/api/notifications/webhooks", body);
        req.then(({ data }) => {
            if (data.secret) setSecret(data.secret); else onSaved();
        }).catch((e) => {
            const d = e.response?.data?.detail;
            setError(Array.isArray(d) ? d.map((x) => x.msg).join("; ") : d || "Could not save the webhook");
        }).finally(() => setBusy(false));
    };

    return (
        <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="hook-title">
            <button type="button" className="bkm-scrim" aria-label="Close" onClick={secret ? onSaved : onClose} />
            <div className="alr-modal">
                <h2 id="hook-title">{secret ? "Signing secret" : hook ? "Edit webhook" : "Add a webhook"}</h2>
                {secret ? (
                    <>
                        <p className="bkm-muted">Copy it now; it is not shown again. The receiver uses it to check the
                            <code> X-NGCorion-Signature</code> header: HMAC-SHA256 of <code>timestamp.body</code>.</p>
                        <input className="bkm-select bkm-mono alr-secret" readOnly value={secret} onFocus={(e) => e.target.select()} aria-label="Signing secret" />
                        <div className="alr-modal-foot">
                            <button type="button" className="bkm-btn" onClick={() => navigator.clipboard?.writeText(secret)}>Copy</button>
                            <button type="button" className="bkm-btn bkm-btn-primary" onClick={onSaved}>Done</button>
                        </div>
                    </>
                ) : (
                    <>
                        <label className="alr-lbl">Name<input ref={first} className="bkm-select" value={name} maxLength={100}
                                                              onChange={(e) => setName(e.target.value)} placeholder="ops-chat" /></label>
                        <label className="alr-lbl">URL<input className="bkm-select bkm-mono" value={url} maxLength={500}
                                                             onChange={(e) => setUrl(e.target.value)} placeholder="https://chat.company.ir/hooks/…" /></label>
                        <p className="alr-hint">NGCorion sends a JSON POST for each message, signed with a secret it generates. Internal addresses are allowed; this server&apos;s own addresses are not.</p>
                        {hook && (
                            <>
                                <label className="alr-check"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Turned on</label>
                                <label className="alr-check"><input type="checkbox" checked={rotate} onChange={(e) => setRotate(e.target.checked)} /> Replace the signing secret</label>
                            </>
                        )}
                        {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                        <div className="alr-modal-foot">
                            <button type="button" className="bkm-btn" onClick={onClose}>Cancel</button>
                            <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !name.trim() || !url.trim()} onClick={save}>
                                {busy ? "Saving…" : hook ? "Save" : "Add webhook"}
                            </button>
                        </div>
                    </>
                )}
            </div>
        </div>
    );
}

/** Notifications › Channels. */
export function ChannelsTab({ channels: c, error, canWrite, onChanged }) {
    const [editing, setEditing] = useState(null);   // webhook, or {} for a new one

    if (error) return <div className="bkm-note bkm-note-error" role="alert">{error}</div>;
    if (!c) return <div className="page-loading" role="status">Loading…</div>;

    const removeHook = (h) => {
        if (!window.confirm(`Delete the webhook "${h.name}"? Rules stop sending to it.`)) return;
        api.delete(`/api/notifications/webhooks/${h.id}`).then(onChanged).catch(() => {});
    };
    const editLink = <Link className="bkm-btn bkm-btn-sm" to="/settings/system">Edit in System Configuration</Link>;

    return (
        <>
            <p className="bkm-muted alr-lead">Where alerts are delivered. Counts cover the last 24 hours.</p>
            <div className="alr-chan-grid">
                <Card tile="#1e3a5f" icon={<Icon name="bell" />} title="In-app" sub="The bell and the Alerts page"
                      status={<span className="bkm-pill bkm-pill-ok">Always on</span>}>
                    <Kv k="Alerts raised · 24 h">{c.in_app.raised_24h}</Kv>
                    <Kv k="Resolved alerts kept for">{c.in_app.retention_days} days</Kv>
                </Card>

                <Card tile="#1d4ed8" icon={<Icon name="mail" />} title="Email" sub="SMTP from System Configuration"
                      status={c.email.configured ? <Ready /> : <NotSet />}
                      actions={<>{canWrite && <TestButton channel="email" needsTo placeholder="Send to (your address by default)" disabled={!c.email.configured} />}{editLink}</>}>
                    {c.email.configured ? (
                        <>
                            <Kv k="Server"><span className="bkm-mono">{c.email.server} · {c.email.security}</span></Kv>
                            <Kv k="From">{c.email.from}</Kv>
                            <Kv k="Delivered · 24 h" warn={c.email.stats_24h.failed > 0}><Stats s={c.email.stats_24h} /></Kv>
                        </>
                    ) : <p className="alr-hint">Set the SMTP server in System Configuration to send alerts by email.</p>}
                </Card>

                <Card tile="#0e7490" icon={<Icon name="phone" />} title="SMS" sub="Provider from System Configuration"
                      status={c.sms.configured ? <Ready /> : <NotSet />}
                      actions={<>{canWrite && <TestButton channel="sms" needsTo placeholder="Mobile number" disabled={!c.sms.configured} />}{editLink}</>}>
                    {c.sms.configured ? (
                        <>
                            <Kv k="Provider">{c.sms.provider}</Kv>
                            <Kv k="Users with a mobile number" warn={!c.sms.users_with_phone}>{c.sms.users_with_phone}</Kv>
                            <Kv k="Delivered · 24 h" warn={c.sms.stats_24h.failed > 0}><Stats s={c.sms.stats_24h} /></Kv>
                        </>
                    ) : <p className="alr-hint">Set the SMS provider in System Configuration. Users&apos; mobile numbers are set in User Management.</p>}
                </Card>

                <Card tile="#334155" icon={<Icon name="lines" />} title="Syslog / SIEM" sub="Alerts as CEF syslog events"
                      status={c.syslog.configured ? <Ready /> : <NotSet />}
                      actions={<>{canWrite && <TestButton channel="syslog" disabled={!c.syslog.configured} />}{editLink}</>}>
                    {c.syslog.configured ? (
                        <>
                            <Kv k="Target"><span className="bkm-mono">{c.syslog.target} · {c.syslog.protocol}</span></Kv>
                            <Kv k="Format">CEF (ArcSight, QRadar, Splunk, Wazuh)</Kv>
                            <Kv k="Sent · 24 h" warn={c.syslog.stats_24h.failed > 0}><Stats s={c.syslog.stats_24h} /></Kv>
                        </>
                    ) : <p className="alr-hint">Uses the syslog server set in System Configuration.</p>}
                </Card>

                {c.webhooks.map((h) => (
                    <Card key={h.id} tile="#7c3aed" icon={<Icon name="link" />} title={`Webhook · ${h.name}`} sub="POST to a URL, signed"
                          status={!h.enabled ? <span className="bkm-pill bkm-pill-muted">Off</span>
                              : h.stats_24h.failed ? <span className="bkm-pill bkm-pill-orange">{h.stats_24h.failed} failed</span> : <Ready />}
                          actions={canWrite && <>
                              <WebhookTest hook={h} onDone={onChanged} />
                              <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => setEditing(h)}>Edit</button>
                              <button type="button" className="bkm-btn bkm-btn-sm alr-danger" onClick={() => removeHook(h)}>Delete</button>
                          </>}>
                        <Kv k="URL"><span className="bkm-mono alr-clip" title={h.url}>{h.url}</span></Kv>
                        <Kv k="Format">JSON · HMAC-SHA256 signature</Kv>
                        {h.last_error
                            ? <Kv k="Last error" warn>{h.last_error} · {formatWhen(h.last_error_at)}</Kv>
                            : <Kv k="Last delivered">{h.last_success_at ? formatWhen(h.last_success_at) : "Never"}</Kv>}
                    </Card>
                ))}

                {canWrite && (
                    <section className="bkm-card alr-chan alr-chan-add">
                        <b>Add a webhook</b>
                        <span className="bkm-muted">Ticketing, chat or automation - any system that accepts an HTTP POST.</span>
                        <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => setEditing({})}>+ Webhook</button>
                    </section>
                )}
            </div>
            {editing && (
                <WebhookModal hook={editing.id ? editing : null} onClose={() => setEditing(null)}
                              onSaved={() => { setEditing(null); onChanged(); }} />
            )}
        </>
    );
}

function WebhookTest({ hook, onDone }) {
    const [busy, setBusy] = useState(false);
    const [result, setResult] = useState(null);
    const run = () => {
        setBusy(true);
        api.post(`/api/notifications/webhooks/${hook.id}/test`)
            .then(({ data }) => setResult(data))
            .catch((e) => setResult({ success: false, message: e.response?.data?.detail || "Test failed" }))
            .finally(() => { setBusy(false); onDone(); });
    };
    return (
        <span className="alr-test">
            <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy} onClick={run}>{busy ? "Sending…" : "Send test"}</button>
            {result && <span className={result.success ? "bkm-green" : "bkm-red"} role="status">{result.message}</span>}
        </span>
    );
}
