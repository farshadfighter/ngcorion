import { useEffect, useMemo, useRef, useState } from "react";
import api from "../../config/api.js";
import { SEVERITY } from "../Alerts/alertFormat.js";
import { t as tr } from "../../i18n";
import { tb } from "../../i18n/backendText";

const REPEAT = [[0, tr("Off")], [15, tr("Every 15 minutes")], [30, tr("Every 30 minutes")], [60, tr("Every hour")],
    [240, tr("Every 4 hours")], [1440, tr("Once a day")]];
const GROUP = [[0, tr("Off - send each alert at once")], [1, tr("One message per minute")],
    [5, tr("One message per 5 minutes")], [15, tr("One message per 15 minutes")]];
const EMPTY_RECIPIENTS = { roles: [], user_ids: [], emails: [], phones: [], owner: false };

function blankRule(event) {
    return {
        name: tb(event?.name) || "", event_type: event?.code || "", enabled: true, severity: "warning",
        params: Object.fromEntries((event?.params || []).map((p) => [p.key, p.default])),
        asset_scope: "all", asset_filter: { type_ids: [], zone_ids: [], asset_ids: [] },
        recipients: { ...EMPTY_RECIPIENTS, roles: ["admin"], owner: !!event?.has_owner },
        channels: ["email"], repeat_minutes: 0, notify_resolved: true, quiet_start: null, quiet_end: null,
        group_minutes: 0,
    };
}

function Chip({ children, onRemove, label }) {
    return (
        <span className="alr-tag">
            {children}
            <button type="button" aria-label={tr("Remove {{label}}", { label })} onClick={onRemove}>×</button>
        </span>
    );
}

function Seg({ value, options, onChange, label }) {
    return (
        <div className="alr-seg" role="radiogroup" aria-label={label}>
            {options.map(([v, text]) => (
                <button key={v} type="button" role="radio" aria-checked={value === v}
                        className={value === v ? "is-on" : ""} onClick={() => onChange(v)}>{text}</button>
            ))}
        </div>
    );
}

/** Drawer to create or edit a notification rule. */
export function RuleEditor({ rule, events, options, channels, onClose, onSaved, onDeleted }) {
    const isNew = !rule?.id;
    const [eventCode, setEventCode] = useState(rule?.event_type || "");
    const event = events.find((e) => e.code === eventCode);
    const [form, setForm] = useState(() => (rule?.id ? {
        ...rule,
        asset_filter: { type_ids: [], zone_ids: [], asset_ids: [], ...(rule.asset_filter || {}) },
        recipients: { ...EMPTY_RECIPIENTS, ...(rule.recipients || {}) },
    } : blankRule(event)));
    const [contact, setContact] = useState("");
    const [error, setError] = useState(null);
    const [saving, setSaving] = useState(false);
    const [testResult, setTestResult] = useState(null);
    const [testing, setTesting] = useState(false);
    const firstField = useRef(null);

    useEffect(() => {
        firstField.current?.focus();
        const onKey = (e) => { if (e.key === "Escape") onClose(); };
        document.addEventListener("keydown", onKey);
        return () => document.removeEventListener("keydown", onKey);
    }, [onClose]);

    const set = (patch) => setForm((f) => ({ ...f, ...patch }));
    const setFilter = (patch) => setForm((f) => ({ ...f, asset_filter: { ...f.asset_filter, ...patch } }));
    const setWho = (patch) => setForm((f) => ({ ...f, recipients: { ...f.recipients, ...patch } }));
    const toggle = (list, value) => (list.includes(value) ? list.filter((x) => x !== value) : [...list, value]);

    const pickEvent = (code) => {
        setEventCode(code);
        const next = events.find((e) => e.code === code);
        setForm((f) => ({ ...blankRule(next), recipients: f.recipients, channels: f.channels }));
    };

    const byId = (list) => Object.fromEntries((list || []).map((x) => [x.id, x]));
    const types = useMemo(() => byId(options?.asset_types), [options]);
    const zones = useMemo(() => byId(options?.zones), [options]);
    const assets = useMemo(() => byId(options?.assets), [options]);
    const users = useMemo(() => byId(options?.users), [options]);
    const roleLabel = Object.fromEntries((options?.roles || []).map((r) => [r.key, tb(r.label)]));

    const addContact = () => {
        const v = contact.trim();
        if (!v) return;
        if (v.includes("@")) {
            if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) { setError(tr("That email address does not look right")); return; }
            setWho({ emails: [...new Set([...form.recipients.emails, v.toLowerCase()])] });
        } else {
            const phone = v.replace(/[\s\-()]/g, "");
            if (!/^\+?[0-9]{7,15}$/.test(phone)) { setError(tr("Enter an email address or a mobile number")); return; }
            setWho({ phones: [...new Set([...form.recipients.phones, phone])] });
        }
        setContact("");
        setError(null);
    };

    const quietOn = !!(form.quiet_start && form.quiet_end);
    const chOk = {
        email: channels?.email?.configured, sms: channels?.sms?.configured, syslog: channels?.syslog?.configured,
    };

    const save = () => {
        setSaving(true);
        setError(null);
        const body = {
            ...form, event_type: eventCode,
            params: Object.fromEntries(Object.entries(form.params || {}).map(([k, v]) => [k, Number(v)])),
        };
        const req = isNew ? api.post("/api/notifications/rules", body) : api.put(`/api/notifications/rules/${rule.id}`, body);
        req.then(({ data }) => onSaved(data))
            .catch((e) => {
                const d = e.response?.data?.detail;
                setError(Array.isArray(d) ? d.map((x) => x.msg).join("; ") : d || tr("Could not save the rule"));
            })
            .finally(() => setSaving(false));
    };

    const remove = () => {
        if (!window.confirm(tr("Delete the rule \"{{name}}\"? Its open alerts are closed.", { name: tb(rule.name) }))) return;
        api.delete(`/api/notifications/rules/${rule.id}`)
            .then(() => onDeleted(rule.id))
            .catch((e) => setError(e.response?.data?.detail || tr("Could not delete the rule")));
    };

    const sendTest = () => {
        setTesting(true);
        setTestResult(null);
        api.post(`/api/notifications/rules/${rule.id}/test`)
            .then(({ data }) => setTestResult(data.results))
            .catch((e) => setTestResult([{ success: false, channel: "", message: e.response?.data?.detail || tr("Test failed") }]))
            .finally(() => setTesting(false));
    };

    const moduleOrder = ["noc", "cve", "audit", "backup", "system"];

    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="rule-editor-title">
            <button type="button" className="bkm-scrim" aria-label={tr("Close")} onClick={onClose} />
            <aside className="bkm-drawer alr-editor">
                <header className="bkm-drawer-head">
                    <div>
                        <div className="bkm-muted bkm-small">{isNew ? tr("New rule") : tr("{{module}} rule", { module: tb(event?.module_label || "") })}</div>
                        <h2 id="rule-editor-title">{isNew ? tr("New notification rule") : tb(rule.name)}</h2>
                    </div>
                    <button type="button" className="bkm-icon-btn" aria-label={tr("Close")} onClick={onClose}>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M6 6l12 12M18 6 6 18" /></svg>
                    </button>
                </header>

                <div className="bkm-drawer-body alr-editor-body">
                    <section className="alr-sec">
                        <h3>{tr("When")}</h3>
                        {isNew ? (
                            <label className="alr-lbl">{tr("Event")}
                                <select ref={firstField} className="bkm-select" value={eventCode} onChange={(e) => pickEvent(e.target.value)}>
                                    <option value="">{tr("Choose what to watch…")}</option>
                                    {moduleOrder.map((m) => (
                                        <optgroup key={m} label={events.find((e) => e.module === m)?.module_label ? tb(events.find((e) => e.module === m).module_label) : m}>
                                            {events.filter((e) => e.module === m).map((e) => (
                                                <option key={e.code} value={e.code}>{tb(e.name)}</option>
                                            ))}
                                        </optgroup>
                                    ))}
                                </select>
                            </label>
                        ) : (
                            <div className="alr-event">{tb(event?.name) || rule.event_type}</div>
                        )}
                        {event && (
                            <>
                                {event.params.length > 0 && (
                                    <div className="alr-grid-2">
                                        {event.params.map((p) => (p.min === 0 && p.max === 1 ? (
                                            <label key={p.key} className="alr-check alr-span-2">
                                                <input type="checkbox" checked={Number(form.params[p.key]) === 1}
                                                       onChange={(e) => set({ params: { ...form.params, [p.key]: e.target.checked ? 1 : 0 } })} />
                                                {tb(p.label.replace(/ \(1 = yes.*\)$/, ""))}
                                            </label>
                                        ) : (
                                            <label key={p.key} className="alr-lbl">{tb(p.label)}
                                                <span className="alr-unit">
                                                    <input type="number" className="bkm-select" min={p.min} max={p.max}
                                                           value={form.params[p.key] ?? ""}
                                                           onChange={(e) => set({ params: { ...form.params, [p.key]: e.target.value } })} />
                                                    {p.unit && <span>{tb(p.unit)}</span>}
                                                </span>
                                            </label>
                                        )))}
                                    </div>
                                )}
                                <p className="alr-hint">
                                    {event.kind === "state"
                                        ? tr("The alert stays open while the condition holds and closes by itself when it clears.")
                                        : tr("Raised once for each occurrence; someone closes it with Resolve.")}
                                    {" "}{event.check_every_seconds >= 3600 ? tr("Checked every {{h}} h.", { h: event.check_every_seconds / 3600 })
                                        : event.check_every_seconds >= 60 ? tr("Checked every {{m}} min.", { m: event.check_every_seconds / 60 })
                                        : tr("Checked every {{s}} s.", { s: event.check_every_seconds })}
                                </p>
                                <label className="alr-lbl">{tr("Rule name")}
                                    <input className="bkm-select" value={form.name} maxLength={150}
                                           onChange={(e) => set({ name: e.target.value })} />
                                </label>
                            </>
                        )}
                        {event?.uses_assets && (
                            <div className="alr-lbl">{tr("Which assets")}
                                <Seg label={tr("Which assets")} value={form.asset_scope} onChange={(v) => set({ asset_scope: v })}
                                     options={[["all", tr("All")], ["matching", tr("Matching")], ["specific", tr("Specific")]]} />
                                {form.asset_scope === "matching" && (
                                    <div className="alr-tags">
                                        {form.asset_filter.type_ids.map((id) => (
                                            <Chip key={`t${id}`} label={types[id]?.name} onRemove={() => setFilter({ type_ids: toggle(form.asset_filter.type_ids, id) })}>
                                                {tr("Type:")}{" "} {types[id]?.name || id}
                                            </Chip>
                                        ))}
                                        {form.asset_filter.zone_ids.map((id) => (
                                            <Chip key={`z${id}`} label={zones[id]?.name} onRemove={() => setFilter({ zone_ids: toggle(form.asset_filter.zone_ids, id) })}>
                                                {tr("Zone:")}{" "} {zones[id]?.name || id}
                                            </Chip>
                                        ))}
                                        <select className="bkm-select alr-add" value="" aria-label={tr("Add an asset type or zone")}
                                                onChange={(e) => {
                                                    const [kind, id] = e.target.value.split(":");
                                                    if (kind === "t") setFilter({ type_ids: [...form.asset_filter.type_ids, Number(id)] });
                                                    if (kind === "z") setFilter({ zone_ids: [...form.asset_filter.zone_ids, Number(id)] });
                                                }}>
                                            <option value="">{tr("+ Add type or zone")}</option>
                                            <optgroup label={tr("Asset type")}>
                                                {(options?.asset_types || []).filter((t) => !form.asset_filter.type_ids.includes(t.id))
                                                    .map((t) => <option key={t.id} value={`t:${t.id}`}>{t.name}</option>)}
                                            </optgroup>
                                            <optgroup label={tr("Zone (Risk Intelligence)")}>
                                                {(options?.zones || []).filter((z) => !form.asset_filter.zone_ids.includes(z.id))
                                                    .map((z) => <option key={z.id} value={`z:${z.id}`}>{z.name}</option>)}
                                            </optgroup>
                                        </select>
                                    </div>
                                )}
                                {form.asset_scope === "specific" && (
                                    <div className="alr-tags">
                                        {form.asset_filter.asset_ids.map((id) => (
                                            <Chip key={id} label={assets[id]?.name} onRemove={() => setFilter({ asset_ids: toggle(form.asset_filter.asset_ids, id) })}>
                                                {assets[id]?.name || `#${id}`}
                                            </Chip>
                                        ))}
                                        <select className="bkm-select alr-add" value="" aria-label={tr("Add an asset")}
                                                onChange={(e) => e.target.value && setFilter({ asset_ids: [...form.asset_filter.asset_ids, Number(e.target.value)] })}>
                                            <option value="">{tr("+ Add asset")}</option>
                                            {(options?.assets || []).filter((a) => !form.asset_filter.asset_ids.includes(a.id))
                                                .map((a) => <option key={a.id} value={a.id}>{a.name}{a.ip ? ` · ${a.ip}` : ""}</option>)}
                                        </select>
                                    </div>
                                )}
                            </div>
                        )}
                    </section>

                    {event && (
                        <>
                            <section className="alr-sec">
                                <h3>{tr("How urgent")}</h3>
                                <Seg label={tr("Severity")} value={form.severity} onChange={(v) => set({ severity: v })}
                                     options={["info", "warning", "critical"].map((s) => [s, SEVERITY[s].label])} />
                            </section>

                            <section className="alr-sec">
                                <h3>{tr("Who hears about it")}</h3>
                                <div className="alr-tags">
                                    {form.recipients.roles.map((r) => (
                                        <Chip key={r} label={roleLabel[r]} onRemove={() => setWho({ roles: toggle(form.recipients.roles, r) })}>{tr("Role:")}{" "} {roleLabel[r] || r}</Chip>
                                    ))}
                                    {form.recipients.user_ids.map((id) => (
                                        <Chip key={id} label={users[id]?.username} onRemove={() => setWho({ user_ids: toggle(form.recipients.user_ids, id) })}>{users[id]?.username || tr("user #{{id}}", { id })}</Chip>
                                    ))}
                                    {form.recipients.emails.map((m) => (
                                        <Chip key={m} label={m} onRemove={() => setWho({ emails: toggle(form.recipients.emails, m) })}>{m}</Chip>
                                    ))}
                                    {form.recipients.phones.map((p) => (
                                        <Chip key={p} label={p} onRemove={() => setWho({ phones: toggle(form.recipients.phones, p) })}>{p}</Chip>
                                    ))}
                                    <select className="bkm-select alr-add" value="" aria-label={tr("Add a role or user")}
                                            onChange={(e) => {
                                                const [kind, id] = e.target.value.split(":");
                                                if (kind === "r") setWho({ roles: [...form.recipients.roles, id] });
                                                if (kind === "u") setWho({ user_ids: [...form.recipients.user_ids, Number(id)] });
                                            }}>
                                        <option value="">{tr("+ Add role or user")}</option>
                                        <optgroup label={tr("Role")}>
                                            {(options?.roles || []).filter((r) => !form.recipients.roles.includes(r.key))
                                                .map((r) => <option key={r.key} value={`r:${r.key}`}>{tb(r.label)}</option>)}
                                        </optgroup>
                                        <optgroup label={tr("User")}>
                                            {(options?.users || []).filter((u) => !form.recipients.user_ids.includes(u.id))
                                                .map((u) => <option key={u.id} value={`u:${u.id}`}>{u.username}{u.has_phone ? "" : tr(" (no mobile)")}</option>)}
                                        </optgroup>
                                    </select>
                                </div>
                                <div className="alr-contact">
                                    <input className="bkm-select" value={contact} onChange={(e) => setContact(e.target.value)}
                                           onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addContact(); } }}
                                           placeholder={tr("Another email address or mobile number")} aria-label={tr("Email address or mobile number")} />
                                    <button type="button" className="bkm-btn" onClick={addContact}>{tr("Add")}</button>
                                </div>
                                {event.has_owner && (
                                    <label className="alr-check">
                                        <input type="checkbox" checked={!!form.recipients.owner} onChange={(e) => setWho({ owner: e.target.checked })} />
                                        {tr("Also the person behind it (who ran the restore or created the job)")}
                                    </label>
                                )}
                                <p className="alr-hint">{tr("Users get email at their account address and SMS at the mobile number in User Management.")}</p>
                            </section>

                            <section className="alr-sec">
                                <h3>{tr("Where")}</h3>
                                <div className="alr-grid-2">
                                    <label className="alr-check alr-box is-fixed"><input type="checkbox" checked disabled /> {" "}{tr("In-app")}{" "} <span className="alr-hint alr-push">{tr("always")}</span></label>
                                    {[["email", tr("Email")], ["sms", "SMS"], ["syslog", tr("Syslog / SIEM")]].map(([c, label]) => (
                                        <label key={c} className="alr-check alr-box">
                                            <input type="checkbox" checked={form.channels.includes(c)} onChange={() => set({ channels: toggle(form.channels, c) })} />
                                            {label}
                                            {!chOk[c] && <span className="alr-hint alr-push alr-warn">{tr("not set up")}</span>}
                                            {c === "sms" && chOk.sms && <span className="alr-hint alr-push">{channels.sms.provider}</span>}
                                        </label>
                                    ))}
                                    {(options?.webhooks || []).map((h) => (
                                        <label key={h.id} className="alr-check alr-box">
                                            <input type="checkbox" checked={form.channels.includes(`webhook:${h.id}`)}
                                                   onChange={() => set({ channels: toggle(form.channels, `webhook:${h.id}`) })} />
                                            {tr("Webhook · {{name}}", { name: h.name })}
                                            {!h.enabled && <span className="alr-hint alr-push alr-warn">{tr("off")}</span>}
                                        </label>
                                    ))}
                                </div>
                            </section>

                            <section className="alr-sec">
                                <h3>{tr("Avoid noise")}</h3>
                                <div className="alr-grid-2">
                                    <label className="alr-lbl">{tr("Remind while not acknowledged")}
                                        <select className="bkm-select" value={form.repeat_minutes} onChange={(e) => set({ repeat_minutes: Number(e.target.value) })}>
                                            {REPEAT.map(([v, t]) => <option key={v} value={v}>{t}</option>)}
                                        </select>
                                    </label>
                                    <label className="alr-lbl">{tr("Group bursts")}
                                        <select className="bkm-select" value={form.group_minutes} onChange={(e) => set({ group_minutes: Number(e.target.value) })}>
                                            {GROUP.map(([v, t]) => <option key={v} value={v}>{t}</option>)}
                                        </select>
                                    </label>
                                    <label className="alr-check alr-span-2">
                                        <input type="checkbox" checked={form.notify_resolved} onChange={(e) => set({ notify_resolved: e.target.checked })} />
                                        {tr("Send a \"resolved\" notice when it recovers")}
                                    </label>
                                    <div className="alr-span-2 alr-quiet">
                                        <label className="alr-check">
                                            <input type="checkbox" checked={quietOn}
                                                   onChange={(e) => set(e.target.checked ? { quiet_start: "22:00", quiet_end: "07:00" } : { quiet_start: null, quiet_end: null })} />
                                            {tr("SMS quiet hours")}
                                        </label>
                                        {quietOn && (
                                            <span className="alr-row-gap">
                                                <input type="time" className="bkm-select" aria-label={tr("Quiet hours start")} value={form.quiet_start}
                                                       onChange={(e) => set({ quiet_start: e.target.value })} />
                                                <span>{tr("to")}</span>
                                                <input type="time" className="bkm-select" aria-label={tr("Quiet hours end")} value={form.quiet_end}
                                                       onChange={(e) => set({ quiet_end: e.target.value })} />
                                                <span className="alr-hint">{tr("Critical alerts are still sent.")}</span>
                                            </span>
                                        )}
                                    </div>
                                </div>
                            </section>
                        </>
                    )}

                    {testResult && (
                        <div className={`bkm-note ${testResult.every((r) => r.success) ? "bkm-note-ok" : "bkm-note-orange"}`} role="status">
                            {testResult.map((r, i) => (
                                <div key={i}>{r.success ? "✓" : "✗"} {r.channel}{r.recipient ? ` → ${r.recipient}` : ""}: {r.message}</div>
                            ))}
                        </div>
                    )}
                    {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                </div>

                <footer className="bkm-drawer-foot">
                    <span className="bkm-actions">
                        {!isNew && (
                            <button type="button" className="bkm-btn" onClick={sendTest} disabled={testing}
                                    title={tr("Sends a sample of this rule's alert as saved")}>
                                {testing ? tr("Sending…") : tr("Send a test")}
                            </button>
                        )}
                        {!isNew && !rule.builtin && (
                            <button type="button" className="bkm-btn alr-danger" onClick={remove}>{tr("Delete")}</button>
                        )}
                    </span>
                    <span className="bkm-actions">
                        <button type="button" className="bkm-btn" onClick={onClose}>{tr("Cancel")}</button>
                        <button type="button" className="bkm-btn bkm-btn-primary" onClick={save} disabled={saving || !event || !form.name?.trim()}>
                            {saving ? tr("Saving…") : tr("Save rule")}
                        </button>
                    </span>
                </footer>
            </aside>
        </div>
    );
}
