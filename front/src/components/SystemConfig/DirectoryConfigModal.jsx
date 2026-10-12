/**
 * Sign-in with Active Directory / LDAP (system administrators): the connection, a test of it and of
 * one user, the mapping of directory groups to roles and permissions, and the periodic account
 * check. Endpoints: /api/system/directory (app/modules/directory/router.py).
 */
import React, { useEffect, useState } from "react";

import api from "../../config/api.js";
import { n, t } from "../../i18n";
import { tb, tv } from "../../i18n/backendText";
import { formatDateTime } from "../../utils/dates";
import { PERMISSION_MODULES } from "../UserManagement/permissionModules";
import "../../assets/Directory.css";

const ROLES = ["admin", "manager", "user", "guest"];

const errorText = (err, fallback) => {
    const detail = err.response?.data?.detail;
    if (typeof detail === "string") return tb(detail);
    if (Array.isArray(detail)) return detail.map((d) => tb(String(d.msg || "").replace(/^Value error, /, ""))).join(" ");
    return fallback;
};

const groupName = (dn) => (/^cn=([^,]+)/i.exec(dn || "") || [])[1] || dn;

/** Module permissions of one mapping: the same grid as the user dialogs. */
const PermissionGrid = ({ value, onChange }) => {
    const get = (m) => value.find((p) => p.module === m) || { module: m, can_read: false, can_write: false, can_delete: false };
    const set = (m, key) => {
        const cur = get(m);
        const next = { ...cur, [key]: !cur[key] };
        onChange([...value.filter((p) => p.module !== m), next].filter((p) => p.can_read || p.can_write || p.can_delete));
    };
    return (
        <table className="sc-table dir-perms">
            <thead><tr><th>{t("Module")}</th><th>{t("Read")}</th><th>{t("Write")}</th><th>{t("Delete")}</th></tr></thead>
            <tbody>
                {PERMISSION_MODULES.map((m) => (
                    <tr key={m.name}>
                        <td>{m.label}</td>
                        {["can_read", "can_write", "can_delete"].map((k) => (
                            <td key={k}><input type="checkbox" checked={get(m.name)[k]} onChange={() => set(m.name, k)}
                                               aria-label={`${m.label} · ${k}`} /></td>
                        ))}
                    </tr>
                ))}
            </tbody>
        </table>
    );
};

export const DirectoryConfigModal = ({ onClose }) => {
    const [cfg, setCfg] = useState(null);
    const [status, setStatus] = useState(null);
    const [password, setPassword] = useState("");
    const [error, setError] = useState(null);
    const [saving, setSaving] = useState(false);
    const [conn, setConn] = useState(null);           // connection test result
    const [busy, setBusy] = useState("");
    const [groupText, setGroupText] = useState("");
    const [groups, setGroups] = useState(null);
    const [openPerms, setOpenPerms] = useState(null);  // index of the mapping whose grid is open
    const [probe, setProbe] = useState({ username: "", password: "" });
    const [probeResult, setProbeResult] = useState(null);
    const [advanced, setAdvanced] = useState(false);

    useEffect(() => {
        api.get("/api/system/directory")
            .then(({ data }) => { setCfg(data.config); setStatus(data.status); })
            .catch(() => setError(t("Could not load the directory settings")));
    }, []);

    const set = (patch) => setCfg((c) => ({ ...c, ...patch }));
    const body = () => ({ ...cfg, bind_password: password || null });
    const setMapping = (i, patch) => set({ mappings: cfg.mappings.map((m, j) => (j === i ? { ...m, ...patch } : m)) });

    const run = async (what, fn) => {
        setBusy(what);
        setError(null);
        try { await fn(); } catch (e) { setError(errorText(e, t("Something went wrong. Please try again."))); }
        finally { setBusy(""); }
    };

    const testConnection = () => run("conn", async () => {
        const { data } = await api.post("/api/system/directory/test", body());
        setConn(data);
    });
    const findGroups = () => run("groups", async () => {
        const { data } = await api.post("/api/system/directory/groups", { config: body(), text: groupText });
        setGroups(data);
    });
    const testUser = () => run("probe", async () => {
        const { data } = await api.post("/api/system/directory/test-user",
            { config: body(), username: probe.username, password: probe.password || null });
        setProbeResult(data);
    });
    const checkNow = () => run("check", async () => {
        const { data } = await api.post("/api/system/directory/check");
        setStatus(data);
    });
    const addGroup = (g) => {
        if (cfg.mappings.some((m) => m.group_dn.toLowerCase() === g.dn.toLowerCase())) return;
        set({ mappings: [...cfg.mappings, { group_dn: g.dn, role: "user", permissions: [] }] });
    };
    const loadCa = (file) => {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => set({ ca_pem: String(reader.result || "") });
        reader.readAsText(file);
    };

    const save = () => {
        setSaving(true);
        setError(null);
        api.put("/api/system/directory", body())
            .then(onClose)
            .catch((e) => setError(errorText(e, t("Could not save the directory settings"))))
            .finally(() => setSaving(false));
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="sc-modal dir-modal" role="dialog" aria-modal="true" aria-labelledby="dir-title"
                 onClick={(e) => e.stopPropagation()}>
                <div className="sc-modal-header">
                    <h3 id="dir-title">{t("Active Directory / LDAP")}</h3>
                    <button type="button" className="sc-modal-close" onClick={onClose} aria-label={t("Close")}>
                        <i className="fa-solid fa-xmark" />
                    </button>
                </div>
                <div className="sc-modal-body">
                    {!cfg ? <p className="sc-state">{error || t("Loading…")}</p> : (
                        <>
                            <label className="dir-switch">
                                <input type="checkbox" checked={cfg.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
                                <span>
                                    <b>{t("Sign in with the organization's directory")}</b>
                                    <small>{t("Users sign in with their directory name and password. Local accounts keep working, with their own passwords.")}</small>
                                </span>
                            </label>

                            <h4 className="dir-h">{t("Connection")}</h4>
                            <div className="dir-grid">
                                <label className="sc-field"><span>{t("Directory type")}</span>
                                    <select value={cfg.kind} onChange={(e) => set({ kind: e.target.value })}>
                                        <option value="ad">Active Directory</option>
                                        <option value="ldap">{t("Other LDAP directory (OpenLDAP, FreeIPA…)")}</option>
                                    </select></label>
                                <div className="sc-field"><span>{t("Encryption")}</span>
                                    <div className="dir-radio" role="radiogroup">
                                        {[["ldaps", "LDAPS (636)"], ["starttls", "StartTLS (389)"], ["plain", t("LDAP (389), not encrypted")]].map(([v, label]) => (
                                            <label key={v}><input type="radio" name="dir-sec" checked={cfg.security === v}
                                                                  onChange={() => set({ security: v })} /> {label}</label>
                                        ))}
                                    </div>
                                    <small className="dir-note">{t("StartTLS uses the same port 389 as plain LDAP, encrypted.")}</small>
                                </div>
                            </div>
                            {cfg.security === "plain" && (
                                <div className="dir-warn" role="alert">
                                    <i className="fa-solid fa-triangle-exclamation" aria-hidden="true" />
                                    <span>{t("Without encryption, the password of everyone who signs in, and the service account's, crosses the network readable by anyone who can see the traffic, and the server is not verified. Use it only on an isolated management network, and move to StartTLS (same port 389) or LDAPS as soon as the directory has a certificate. Active Directory with LDAP signing required refuses it.")}</span>
                                </div>
                            )}
                            <label className="sc-field"><span>{t("Servers, in order (one per line; host or host:port)")}</span>
                                <textarea dir="ltr" rows={2} value={cfg.servers.join("\n")} placeholder="dc1.corp.local&#10;dc2.corp.local"
                                          onChange={(e) => set({ servers: e.target.value.split(/\n/) })} /></label>
                            <label className="sc-field"><span>{t("Base DN")}</span>
                                <input dir="ltr" value={cfg.base_dn} placeholder="DC=corp,DC=local"
                                       onChange={(e) => set({ base_dn: e.target.value })} /></label>
                            <div className="dir-grid">
                                <label className="sc-field"><span>{t("Service account (read-only)")}</span>
                                    <input dir="ltr" value={cfg.bind_dn} placeholder="CN=svc-ngc-ldap,OU=Service,DC=corp,DC=local"
                                           onChange={(e) => set({ bind_dn: e.target.value })} /></label>
                                <label className="sc-field"><span>{t("Service account password")}</span>
                                    <input type="password" autoComplete="new-password" value={password} maxLength={256}
                                           placeholder={cfg.has_password ? t("Stored; type to replace") : ""}
                                           onChange={(e) => setPassword(e.target.value)} /></label>
                            </div>
                            {cfg.security !== "plain" && <div className="sc-field"><span>{t("CA certificate of the directory (PEM)")}</span>
                                <div className="dir-ca">
                                    <span className={cfg.ca_pem ? "dir-ok" : "dir-muted"}>
                                        {cfg.ca_pem ? t("Loaded") : t("None: the system's trusted CAs are used")}
                                    </span>
                                    <label className="sc-btn sc-btn-ghost dir-file">
                                        {t("Choose file…")}
                                        <input type="file" accept=".pem,.crt,.cer" onChange={(e) => loadCa(e.target.files?.[0])} />
                                    </label>
                                    {cfg.ca_pem && <button type="button" className="sc-btn sc-btn-ghost" onClick={() => set({ ca_pem: "" })}>{t("Remove")}</button>}
                                </div>
                            </div>}
                            <button type="button" className="dir-link" onClick={() => setAdvanced(!advanced)} aria-expanded={advanced}>
                                {advanced ? t("Hide advanced settings") : t("Advanced settings")}
                            </button>
                            {advanced && (
                                <div className="dir-grid">
                                    <label className="sc-field"><span>{t("User name attribute")}</span>
                                        <input dir="ltr" value={cfg.user_attr} placeholder={cfg.kind === "ad" ? "sAMAccountName" : "uid"}
                                               onChange={(e) => set({ user_attr: e.target.value })} /></label>
                                    <label className="sc-field"><span>{t("User filter")}</span>
                                        <input dir="ltr" value={cfg.user_filter}
                                               placeholder={cfg.kind === "ad" ? "(&(objectCategory=person)(objectClass=user))" : "(objectClass=inetOrgPerson)"}
                                               onChange={(e) => set({ user_filter: e.target.value })} /></label>
                                    <label className="sc-field"><span>{t("Group filter")}</span>
                                        <input dir="ltr" value={cfg.group_filter}
                                               placeholder={cfg.kind === "ad" ? "(objectClass=group)" : "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))"}
                                               onChange={(e) => set({ group_filter: e.target.value })} /></label>
                                </div>
                            )}
                            <div className="dir-row">
                                <button type="button" className="sc-btn sc-btn-ghost" onClick={testConnection} disabled={busy === "conn"}>
                                    <i className="fa-solid fa-plug" aria-hidden="true" /> {busy === "conn" ? t("Testing…") : t("Test the connection")}
                                </button>
                                {conn && (
                                    <span className={conn.ok ? "dir-ok" : "dir-bad"} role="status">
                                        {conn.ok ? `${tb(conn.message)} · ${conn.server}` : tb(conn.message)}
                                    </span>
                                )}
                            </div>

                            <h4 className="dir-h">{t("Directory groups → roles")}</h4>
                            <p className="sc-hint">{t("A user gets the highest role among their mapped groups and every permission those groups give. Nested groups count. A user in no mapped group cannot sign in.")}</p>
                            {cfg.mappings.length > 0 && (
                                <table className="sc-table dir-map">
                                    <thead><tr><th>{t("Directory group")}</th><th>{t("Role in NGCorion")}</th><th>{t("Permissions")}</th><th /></tr></thead>
                                    <tbody>
                                        {cfg.mappings.map((m, i) => (
                                            <React.Fragment key={m.group_dn}>
                                                <tr>
                                                    <td><b>{groupName(m.group_dn)}</b><small dir="ltr" className="dir-dn">{m.group_dn}</small></td>
                                                    <td>
                                                        <select value={m.role} onChange={(e) => setMapping(i, { role: e.target.value })}
                                                                aria-label={t("Role in NGCorion")}>
                                                            {ROLES.map((r) => <option key={r} value={r}>{tv(r)}</option>)}
                                                        </select>
                                                    </td>
                                                    <td>
                                                        {m.role === "admin" ? <span className="dir-muted">{t("Everything")}</span> : (
                                                            <button type="button" className="dir-link" onClick={() => setOpenPerms(openPerms === i ? null : i)}>
                                                                {t("Modules: {{value}}", { value: m.permissions.filter((p) => p.can_read || p.can_write || p.can_delete).length })}
                                                            </button>
                                                        )}
                                                    </td>
                                                    <td>
                                                        <button type="button" className="dir-icon" aria-label={t("Remove")}
                                                                onClick={() => { setOpenPerms(null); set({ mappings: cfg.mappings.filter((_, j) => j !== i) }); }}>
                                                            <i className="fa-solid fa-trash" />
                                                        </button>
                                                    </td>
                                                </tr>
                                                {openPerms === i && m.role !== "admin" && (
                                                    <tr><td colSpan={4}><PermissionGrid value={m.permissions} onChange={(p) => setMapping(i, { permissions: p })} /></td></tr>
                                                )}
                                            </React.Fragment>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                            <div className="dir-row">
                                <input className="dir-search" value={groupText} placeholder={t("Group name, e.g. NGC")}
                                       onChange={(e) => setGroupText(e.target.value)}
                                       onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); findGroups(); } }} />
                                <button type="button" className="sc-btn sc-btn-ghost" onClick={findGroups} disabled={busy === "groups"}>
                                    <i className="fa-solid fa-magnifying-glass" aria-hidden="true" /> {t("Find groups")}
                                </button>
                            </div>
                            {groups && (
                                <ul className="dir-groups">
                                    {groups.length === 0 && <li className="dir-muted">{t("No group found")}</li>}
                                    {groups.map((g) => {
                                        const added = cfg.mappings.some((m) => m.group_dn.toLowerCase() === g.dn.toLowerCase());
                                        return (
                                            <li key={g.dn}>
                                                <span><b>{g.name}</b><small dir="ltr" className="dir-dn">{g.dn}</small></span>
                                                <button type="button" className="sc-btn sc-btn-ghost" disabled={added} onClick={() => addGroup(g)}>
                                                    {added ? t("Added") : t("Add")}
                                                </button>
                                            </li>
                                        );
                                    })}
                                </ul>
                            )}

                            <h4 className="dir-h">{t("Test a user")}</h4>
                            <div className="dir-row">
                                <input className="dir-search" dir="ltr" value={probe.username} placeholder={t("User name")}
                                       onChange={(e) => setProbe({ ...probe, username: e.target.value })} />
                                <input className="dir-search" type="password" autoComplete="new-password" value={probe.password}
                                       placeholder={t("Password (optional)")} onChange={(e) => setProbe({ ...probe, password: e.target.value })} />
                                <button type="button" className="sc-btn sc-btn-ghost" onClick={testUser} disabled={!probe.username || busy === "probe"}>
                                    {t("Test")}
                                </button>
                            </div>
                            {probeResult && (
                                <div className="dir-probe" role="status">
                                    {!probeResult.found ? <span className="dir-bad">{t("No such user in the directory")}</span> : (
                                        <>
                                            <div><b>{probeResult.display_name || probeResult.username}</b> <small dir="ltr" className="dir-dn">{probeResult.dn}</small></div>
                                            {probeResult.disabled && <div className="dir-bad">{t("The account is disabled in the directory")}</div>}
                                            {probeResult.password_ok !== null && (
                                                <div className={probeResult.password_ok ? "dir-ok" : "dir-bad"}>
                                                    {probeResult.password_ok ? t("Password correct") : t("Password wrong")}
                                                </div>
                                            )}
                                            <div>{t("Groups ({{value}}):", { value: probeResult.groups.length })} {probeResult.groups.map(groupName).join("، ") || "—"}</div>
                                            <div className={probeResult.role ? "dir-ok" : "dir-bad"}>
                                                {probeResult.role
                                                    ? t("Would sign in as {{role}} (from {{groups}})", { role: tv(probeResult.role), groups: probeResult.mapped_groups.map(groupName).join("، ") })
                                                    : t("In no mapped group: would be refused")}
                                            </div>
                                        </>
                                    )}
                                </div>
                            )}

                            <h4 className="dir-h">{t("Account check")}</h4>
                            <p className="sc-hint">{t("Every 15 minutes NGCorion checks each directory account: disabled, deleted or out of every mapped group in the directory ends its access; a role change in the directory is applied.")}</p>
                            <div className="dir-row">
                                <span className={!status ? "dir-muted" : status.ok ? "dir-ok" : "dir-bad"}>
                                    {!status ? t("Not run yet")
                                        : status.skipped ? t("Last run {{date}}: directory sign-in is off", { date: formatDateTime(status.ran_at) })
                                        : status.ok ? t("Last run {{date}}: {{checked}} accounts checked, {{off}} turned off, {{updated}} updated",
                                            { date: formatDateTime(status.ran_at), checked: n(status.checked), off: n(status.turned_off || 0), updated: n(status.updated || 0) })
                                        : t("Last run {{date}}: the directory could not be reached ({{error}})", { date: formatDateTime(status.ran_at), error: status.error })}
                                </span>
                                <button type="button" className="sc-btn sc-btn-ghost" onClick={checkNow} disabled={!cfg.enabled || busy === "check"}>
                                    {busy === "check" ? t("Checking…") : t("Check now")}
                                </button>
                            </div>
                            <p className="sc-hint">{t("Local accounts always sign in with their own password, so a local administrator can still sign in when the directory is down; each such sign-in raises the \"Local administrator signed in\" alert. Two-step sign-in applies to directory accounts by their role, as to local ones.")}</p>
                            {error && <p className="sc-error" role="alert">{error}</p>}
                        </>
                    )}
                </div>
                <div className="sc-modal-footer">
                    <button type="button" className="sc-btn sc-btn-ghost" onClick={onClose} disabled={saving}>{t("Cancel")}</button>
                    <button type="button" className="sc-btn sc-btn-primary" onClick={save} disabled={saving || !cfg}>
                        {saving ? t("Saving…") : t("Save")}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default DirectoryConfigModal;
