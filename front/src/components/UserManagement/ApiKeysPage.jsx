/**
 * API keys (Administration › Users › API keys; system administrators): keys other systems (SIEM, CMDB,
 * scripts) call the API with. Each key acts as its own service account with only the modules it is given,
 * read or read and write, until its end date; it can be limited to some addresses, renewed (new secret)
 * and revoked. The token is shown once, when the key is made or renewed (app/modules/api_keys).
 */
import { useEffect, useMemo, useState } from "react";

import api from "../../config/api.js";
import { n, t } from "../../i18n";
import { formatDate, formatWhen } from "../../utils/dates.js";
import { DateInput } from "../shared/DateInput.jsx";
import { errorText } from "../Software/softwareFormat.js";
import { PERMISSION_MODULES } from "./permissionModules.js";
import { UsersTabs } from "./UsersTabs.jsx";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/Lifecycle.css";
import "../../assets/ApiKeys.css";

const LABEL = Object.fromEntries(PERMISSION_MODULES.map((m) => [m.name, m.label]));
const STATUS = {
    active: { label: t("Active"), pill: "bkm-pill-ok" },
    expired: { label: t("Expired"), pill: "bkm-pill-bad" },
    revoked: { label: t("Revoked"), pill: "bkm-pill-muted" },
};
const Mono = ({ children }) => <bdi dir="ltr" className="bkm-mono">{children}</bdi>;

const isoDay = (d) => d.toISOString().slice(0, 10);
const inDays = (days) => isoDay(new Date(Date.now() + days * 86400000));

/** The scopes in one line: "Asset List (read), Remediation (read and write)". */
function scopesText(scopes) {
    return scopes.map((s) => `${LABEL[s.module] || s.module} (${s.write ? t("read and write") : t("read")})`).join(t(", "));
}

// ── the token, shown once ────────────────────────────────────────────────

function TokenDialog({ token, name, onClose }) {
    const [copied, setCopied] = useState(false);
    const copy = () => {
        navigator.clipboard?.writeText(token).then(() => setCopied(true)).catch(() => setCopied(false));
    };
    const origin = window.location.origin;
    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="ak-token-title">
            <div className="bkm-scrim" />
            <div className="ak-dialog">
                <h2 id="ak-token-title">{t("The token of {{name}}", { name })}</h2>
                <div className="bkm-note bkm-note-orange">{t("Copy it now and keep it in the other system's secret store: NGCorion keeps only a fingerprint of it and cannot show it again.")}</div>
                <div className="ak-token">
                    <code dir="ltr">{token}</code>
                    <button type="button" className="bkm-btn bkm-btn-sm" onClick={copy}>{copied ? t("Copied") : t("Copy")}</button>
                </div>
                <p className="bkm-small bkm-muted">{t("Use it as a bearer token, for example:")}</p>
                <pre className="ak-example" dir="ltr">{`NGC_TOKEN='${token}'\ncurl -H "Authorization: Bearer $NGC_TOKEN" ${origin}/api/assets/`}</pre>
                <div className="ak-dialog-foot">
                    <button type="button" className="bkm-btn bkm-btn-primary" onClick={onClose}>{t("I have stored it")}</button>
                </div>
            </div>
        </div>
    );
}

// ── making and changing a key ────────────────────────────────────────────

function KeyDrawer({ keyRow, modules, maxDays, defaultDays, onClose, onSaved, onToken }) {
    const editing = Boolean(keyRow);
    const active = !editing || keyRow.status !== "revoked";
    const [form, setForm] = useState(() => ({
        name: keyRow?.name || "",
        description: keyRow?.description || "",
        expires: keyRow ? keyRow.expires_at.slice(0, 10) : inDays(defaultDays),
        ips: (keyRow?.allowed_ips || []).join("\n"),
        scopes: Object.fromEntries((keyRow?.scopes || []).map((s) => [s.module, s.write ? "write" : "read"])),
    }));
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const [confirmRevoke, setConfirmRevoke] = useState(false);
    const chosen = Object.entries(form.scopes).filter(([, v]) => v !== "none");
    const ready = form.name.trim().length >= 2 && chosen.length > 0 && form.expires;
    const body = () => ({
        name: form.name.trim(), description: form.description.trim() || null,
        scopes: chosen.map(([module, v]) => ({ module, write: v === "write" })),
        allowed_ips: form.ips.split(/[\s,،]+/).map((x) => x.trim()).filter(Boolean),
        expires_at: `${form.expires}T23:59:59Z`,
    });
    const run = (req, after) => {
        setBusy(true);
        setError(null);
        req.then(({ data }) => after(data)).catch((e) => setError(errorText(e, t("Could not save")))).finally(() => setBusy(false));
    };
    const save = () => run(editing ? api.put(`/api/api-keys/${keyRow.id}`, body()) : api.post("/api/api-keys", body()),
        (data) => { onSaved(); if (data.token) onToken(data.token, data.key.name); else onClose(); });
    const renew = () => run(api.post(`/api/api-keys/${keyRow.id}/renew`), (data) => { onSaved(); onToken(data.token, data.key.name); });
    const revoke = () => run(api.post(`/api/api-keys/${keyRow.id}/revoke`), () => { onSaved(); onClose(); });
    const setScope = (m, v) => setForm((f) => ({ ...f, scopes: { ...f.scopes, [m]: v } }));
    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="ak-drawer-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer ak-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="ak-drawer-title">{editing ? keyRow.name : t("New API key")}</h2>
                        <span className="bkm-sub">{editing ? <><Mono>{keyRow.prefix}…</Mono> · <Mono>{keyRow.account}</Mono></>
                            : t("For another system (SIEM, CMDB, a script). It acts as its own account with only the access given here.")}</span>
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    {!active && <div className="bkm-note">{t("This key was revoked {{when}} and no longer works.", { when: formatWhen(keyRow.revoked_at) })}</div>}
                    <label className="alr-lbl">{t("Name")}
                        <input className="bkm-select" value={form.name} maxLength={100} dir="auto" disabled={!active}
                               placeholder={t("e.g. SIEM export")} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                    </label>
                    <label className="alr-lbl">{t("Description (optional)")}
                        <textarea className="bkm-select bp-reason" rows={2} value={form.description} maxLength={1000} dir="auto" disabled={!active}
                                  placeholder={t("Which system uses it, and who to ask about it")}
                                  onChange={(e) => setForm({ ...form, description: e.target.value })} />
                    </label>
                    <label className="alr-lbl">{t("Valid until")}
                        <DateInput className="bkm-select" value={form.expires} disabled={!active} min={inDays(0)} max={inDays(maxDays)}
                                   onChange={(v) => setForm({ ...form, expires: v })} />
                        <span className="bkm-small bkm-muted">{t("At most {{days}} days; renew it before then.", { days: n(maxDays) })}</span>
                    </label>
                    <fieldset className="ak-scopes" disabled={!active}>
                        <legend>{t("Access")}</legend>
                        <p className="bkm-small bkm-muted">{t("User management and credential profiles are never given to a key; hardening, device backups, system settings and logs only for reading. A key never deletes.")}</p>
                        {modules.read.map((m) => {
                            const value = form.scopes[m] || "none";
                            const canWrite = modules.write.includes(m);
                            return (
                                <div key={m} className="ak-scope">
                                    <span>{LABEL[m] || m}</span>
                                    <span className="ak-seg" role="radiogroup" aria-label={LABEL[m] || m}>
                                        {[["none", t("None")], ["read", t("Read")], ["write", t("Read and write")]].map(([v, label]) => (
                                            <button key={v} type="button" role="radio" aria-checked={value === v}
                                                    disabled={v === "write" && !canWrite} className={value === v ? "is-on" : ""}
                                                    onClick={() => setScope(m, v)}>{label}</button>
                                        ))}
                                    </span>
                                </div>
                            );
                        })}
                    </fieldset>
                    <label className="alr-lbl">{t("Allowed addresses (optional)")}
                        <textarea className="bkm-select bp-reason" rows={3} dir="ltr" value={form.ips} disabled={!active}
                                  placeholder={"10.20.30.40\n10.20.0.0/16"} onChange={(e) => setForm({ ...form, ips: e.target.value })} />
                        <span className="bkm-small bkm-muted">{t("One address or network per line. Empty: any address.")}</span>
                    </label>
                    {editing && (
                        <div className="ak-facts bkm-small">
                            <span>{t("Created {{when}} by {{who}}", { when: formatWhen(keyRow.created_at), who: keyRow.created_by || "—" })}</span>
                            {keyRow.renewed_at && <span>{t("Secret renewed {{when}}", { when: formatWhen(keyRow.renewed_at) })}</span>}
                            <span>{keyRow.last_used_at ? t("Last used {{when}} from {{ip}}", { when: formatWhen(keyRow.last_used_at), ip: keyRow.last_used_ip || "—" })
                                : t("Not used yet")}</span>
                        </div>
                    )}
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                </div>
                <footer className="bkm-drawer-foot">
                    {editing && active && (confirmRevoke
                        ? <button type="button" className="bkm-btn ak-danger" disabled={busy} onClick={revoke}>{t("Revoke for good")}</button>
                        : <button type="button" className="bkm-btn" disabled={busy} onClick={() => setConfirmRevoke(true)}>{t("Revoke")}</button>)}
                    {editing && active && <button type="button" className="bkm-btn" disabled={busy} onClick={renew}>{t("Renew the secret")}</button>}
                    {active && <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !ready} onClick={save}>
                        {editing ? t("Save") : t("Create the key")}</button>}
                </footer>
            </aside>
        </div>
    );
}

// ── page ─────────────────────────────────────────────────────────────────

export function ApiKeysPage() {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [open, setOpen] = useState(undefined);         // undefined: closed; null: new; a key: that key
    const [token, setToken] = useState(null);
    const [tick, setTick] = useState(0);
    useEffect(() => {
        api.get("/api/api-keys").then(({ data: d }) => setData(d)).catch((e) => setError(errorText(e, t("Could not load the API keys"))));
    }, [tick]);
    const refresh = () => setTick((x) => x + 1);
    const keys = useMemo(() => data?.keys || [], [data]);
    const current = open && keys.find((k) => k.id === open.id);

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <span className="bkm-crumb">{t("Administration")} › {t("Users")}</span>
                    <h1>{t("API keys")}</h1>
                    <p>{t("Keys other systems (SIEM, CMDB, scripts) call the NGCorion API with. Each acts as its own account with only the access it is given, until its end date; everything it does is in the audit trail under that account.")}</p>
                </div>
                <div className="bkm-actions">
                    <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => setOpen(null)} disabled={!data}>{t("New API key")}</button>
                </div>
            </div>
            <UsersTabs />
            {error && <div className="bkm-note bkm-note-error">{error}</div>}
            {data && (
                <section className="bkm-card bkm-flush">
                    {keys.length === 0 ? (
                        <div className="bkm-empty"><b>{t("No API key yet")}</b><span>{t("Make one for each system that calls the API, with only the modules it needs.")}</span></div>
                    ) : (
                        <div className="bkm-table-wrap">
                            <table className="bkm-table ak-table">
                                <thead><tr><th>{t("Key")}</th><th>{t("Access")}</th><th>{t("Valid until")}</th><th>{t("Last used")}</th><th>{t("Status")}</th></tr></thead>
                                <tbody>
                                    {keys.map((k) => (
                                        <tr key={k.id} className="ak-click" tabIndex={0} onClick={() => setOpen(k)} onKeyDown={(e) => e.key === "Enter" && setOpen(k)}>
                                            <td>
                                                <div className="ak-key">
                                                    <b dir="auto">{k.name}</b>
                                                    <span className="bkm-small bkm-muted"><Mono>{k.prefix}…</Mono> · <Mono>{k.account}</Mono></span>
                                                    {k.description && <span className="bkm-small bkm-muted ak-desc" dir="auto">{k.description}</span>}
                                                </div>
                                            </td>
                                            <td className="bkm-small ak-scope-cell">{scopesText(k.scopes)}
                                                {k.allowed_ips.length > 0 && <span className="bkm-muted ak-block">{t("Only from {{list}}", { list: k.allowed_ips.join(", ") })}</span>}</td>
                                            <td className="bkm-small">{formatDate(k.expires_at)}
                                                {k.status === "active" && <span className={`ak-block ${k.days_left <= 14 ? "ak-warn" : "bkm-muted"}`}>
                                                    {t("in {{count}} days", { count: k.days_left })}</span>}</td>
                                            <td className="bkm-small">{k.last_used_at ? <>{formatWhen(k.last_used_at)}<span className="ak-block bkm-muted"><Mono>{k.last_used_ip}</Mono></span></>
                                                : <span className="bkm-muted ak-nowrap">{t("Not used yet")}</span>}</td>
                                            <td><span className={`bkm-pill ${STATUS[k.status].pill}`}>{STATUS[k.status].label}</span></td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </section>
            )}
            {open !== undefined && data && (
                <KeyDrawer key={open?.id || "new"} keyRow={current || null} modules={data.modules} maxDays={data.max_days}
                           defaultDays={data.default_days} onClose={() => setOpen(undefined)} onSaved={refresh}
                           onToken={(tok, name) => { setOpen(undefined); setToken({ token: tok, name }); }} />
            )}
            {token && <TokenDialog token={token.token} name={token.name} onClose={() => setToken(null)} />}
        </div>
    );
}
