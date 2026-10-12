/**
 * Credential profiles (system administrators): device sign-in details defined once and used by group
 * audits and scheduled group audits. Write-only: a stored password is never shown again, only that
 * it is set; leaving a password field empty keeps it. Each profile can be tried on one asset (a
 * sign-in only, nothing changes on the device). Endpoints: /api/credential-profiles.
 */
import React, { useEffect, useMemo, useState } from "react";

import api from "../../config/api.js";
import { n, t } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { formatDateTime } from "../../utils/dates";
import { ConfigModal } from "./ConfigModal";
import { KINDS, TECHS, errorText } from "../AssetGroups/groupFormat.js";
import "../../assets/AssetGroups.css";

const DEFAULT_PORT = { ssh: 22, winrm: 5985, mssql: 1433, sophos_api: 4444 };
const SECRETS = {
    ssh: [["password", t("Password")], ["sudo_password", t("Sudo password (optional)")],
          ["enable_secret", t("Enable secret, Cisco (optional)")], ["db_password", t("Database password: MySQL or MongoDB (optional)")]],
    winrm: [["password", t("Password")]],
    mssql: [["password", t("Password")]],
    sophos_api: [["password", t("Password")]],
};

const blank = (kind = "ssh") => ({ name: "", kind, username: "", description: "", rotation_days: 90,
                                   options: { port: DEFAULT_PORT[kind] }, secrets: {}, secrets_set: [] });

const TESTED = {
    ok: t("Signed in successfully."),
    auth: t("The device refused the sign-in."),
    unreachable: t("The device could not be reached."),
    error: t("The test failed."),
};

export const CredentialProfilesModal = ({ onClose }) => {
    const [profiles, setProfiles] = useState(null);
    const [techs, setTechs] = useState({});
    const [error, setError] = useState(null);
    const [editing, setEditing] = useState(null);

    const load = () => api.get("/api/credential-profiles").then(({ data }) => setProfiles(data))
        .catch((e) => setError(errorText(e, t("Could not load the credential profiles"))));
    useEffect(() => {
        load();
        api.get("/api/credential-profiles/technologies").then(({ data }) => setTechs(data)).catch(() => {});
    }, []);

    const usedBy = (kind) => Object.entries(techs).filter(([, k]) => k === kind).map(([tech]) => TECHS[tech] || tech).join("، ");

    if (editing) {
        return <ProfileEditor profile={editing} usedBy={usedBy} onBack={() => setEditing(null)}
                              onSaved={() => { setEditing(null); load(); }} onClose={onClose} />;
    }
    return (
        <ConfigModal title={t("Credential profiles")} onClose={onClose} onSave={() => setEditing(blank())}
                     saveLabel={t("New profile")} isLoading={!profiles && !error} error={error}>
            <p className="sc-hint">
                {t("Sign-in details for group audits and scheduled group audits, kept encrypted. Passwords can be replaced but are never shown again. Users need the \"Use credential profiles\" permission to audit with them; every use is written to the audit trail.")}
            </p>
            {profiles && (profiles.length === 0 ? <p className="sc-state">{t("No credential profiles yet.")}</p> : (
                <table className="sc-table">
                    <thead>
                        <tr><th>{t("Profile")}</th><th>{t("Kind")}</th><th>{t("Password age")}</th><th>{t("Last used")}</th><th /></tr>
                    </thead>
                    <tbody>
                        {profiles.map((p) => (
                            <tr key={p.id}>
                                <td><b dir="auto">{p.name}</b><div className="sc-hint" dir="ltr">{p.username}</div></td>
                                <td>{KINDS[p.kind] || p.kind}</td>
                                <td>
                                    {t("{{value}} days", { value: n(p.age_days ?? 0) })}
                                    {p.rotation_due && <div className="sc-warning cp-due">{t("Time to change it")}</div>}
                                </td>
                                <td className="sc-hint">{p.last_used_at ? formatDateTime(p.last_used_at) : "—"}</td>
                                <td><button type="button" className="sc-btn sc-btn-ghost" onClick={() => setEditing(p)}>{t("Edit")}</button></td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            ))}
        </ConfigModal>
    );
};

function ProfileEditor({ profile, usedBy, onBack, onSaved, onClose }) {
    const [p, setP] = useState({ ...profile, secrets: {}, options: { ...(profile.options || {}) } });
    const [error, setError] = useState(null);
    const [saving, setSaving] = useState(false);
    const [confirmDelete, setConfirmDelete] = useState(false);
    const [assets, setAssets] = useState([]);
    const [testAsset, setTestAsset] = useState("");
    const [test, setTest] = useState(null);
    const [testing, setTesting] = useState(false);
    const isNew = !profile.id;
    const set = (patch) => setP((cur) => ({ ...cur, ...patch }));
    const setOpt = (patch) => setP((cur) => ({ ...cur, options: { ...cur.options, ...patch } }));
    const setSecret = (k, v) => setP((cur) => ({ ...cur, secrets: { ...cur.secrets, [k]: v } }));

    useEffect(() => {
        if (!isNew) api.get("/api/assets/").then(({ data }) => setAssets(data || [])).catch(() => setAssets([]));
    }, [isNew]);
    const assetOptions = useMemo(() => assets.filter((a) => a.ip_address), [assets]);

    const save = () => {
        setSaving(true);
        setError(null);
        const body = { name: p.name, kind: p.kind, username: p.username, description: p.description || null,
                       rotation_days: Number(p.rotation_days) || 0, options: p.options, secrets: p.secrets };
        const req = isNew ? api.post("/api/credential-profiles", body) : api.put(`/api/credential-profiles/${p.id}`, body);
        req.then(onSaved).catch((e) => setError(errorText(e, t("Could not save the profile")))).finally(() => setSaving(false));
    };
    const remove = () => api.delete(`/api/credential-profiles/${p.id}`).then(onSaved)
        .catch((e) => { setConfirmDelete(false); setError(errorText(e, t("Could not delete the profile"))); });
    const runTest = () => {
        setTesting(true);
        setTest(null);
        api.post(`/api/credential-profiles/${p.id}/test`, { asset_id: Number(testAsset) })
            .then(({ data }) => setTest(data))
            .catch((e) => setTest({ result: "error", detail: errorText(e, "") }))
            .finally(() => setTesting(false));
    };

    const has = (k) => (profile.secrets_set || []).includes(k);
    return (
        <ConfigModal title={isNew ? t("New credential profile") : t("Credential profile: {{name}}", { name: profile.name })}
                     onClose={onClose} onSave={save} isSaving={saving} error={error}
                     saveDisabled={!p.name.trim() || !p.username.trim() || (isNew && !p.secrets.password)}>
            <button type="button" className="sc-btn sc-btn-ghost cp-back" onClick={onBack}>{t("‹ All profiles")}</button>
            <div className="cp-grid">
                <label className="sc-field"><span>{t("Name")}</span>
                    <input value={p.name} maxLength={120} dir="auto" onChange={(e) => set({ name: e.target.value })}
                           placeholder={t("e.g. Linux servers — audit account")} /></label>
                <label className="sc-field"><span>{t("Kind")}</span>
                    <select value={p.kind} disabled={!isNew}
                            onChange={(e) => set({ kind: e.target.value, options: { port: DEFAULT_PORT[e.target.value] }, secrets: {} })}>
                        {Object.entries(KINDS).map(([k, label]) => <option key={k} value={k}>{label}</option>)}
                    </select></label>
            </div>
            <p className="sc-hint">{t("Signs in to: {{list}}", { list: usedBy(p.kind) })}</p>
            <div className="cp-grid">
                <label className="sc-field"><span>{t("User name")}</span>
                    <input value={p.username} maxLength={256} dir="ltr" autoComplete="off" onChange={(e) => set({ username: e.target.value })} /></label>
                <label className="sc-field"><span>{t("Port")}</span>
                    <input type="number" min={1} max={65535} dir="ltr" value={p.options.port ?? ""} onChange={(e) => setOpt({ port: e.target.value })} /></label>
            </div>
            {SECRETS[p.kind].map(([k, label]) => (
                <label key={k} className="sc-field"><span>{label}</span>
                    <input type="password" autoComplete="new-password" maxLength={1024} value={p.secrets[k] || ""}
                           placeholder={has(k) ? t("Set — leave empty to keep it") : ""}
                           onChange={(e) => setSecret(k, e.target.value)} /></label>
            ))}
            {p.kind === "ssh" && (
                <div className="cp-grid">
                    <label className="sc-field"><span>{t("Database user (optional)")}</span>
                        <input dir="ltr" value={p.options.db_username || ""} onChange={(e) => setOpt({ db_username: e.target.value })} /></label>
                    <label className="sc-field"><span>{t("Database port (optional)")}</span>
                        <input type="number" dir="ltr" value={p.options.db_port || ""} onChange={(e) => setOpt({ db_port: e.target.value || null })} /></label>
                </div>
            )}
            {p.kind === "winrm" && (
                <div className="cp-grid">
                    <label className="sc-field"><span>{t("Transport")}</span>
                        <select value={p.options.transport || "ntlm"} onChange={(e) => setOpt({ transport: e.target.value })}>
                            {["ntlm", "kerberos", "credssp", "basic"].map((x) => <option key={x} value={x}>{x.toUpperCase()}</option>)}
                        </select></label>
                    <label className="sc-field"><span>{t("HTTPS certificate check")}</span>
                        <select value={p.options.verify_ssl === true ? "yes" : p.options.verify_ssl === false ? "no" : ""}
                                onChange={(e) => setOpt({ verify_ssl: e.target.value === "" ? null : e.target.value === "yes" })}>
                            <option value="">{t("System default")}</option>
                            <option value="yes">{t("Check")}</option>
                            <option value="no">{t("Do not check")}</option>
                        </select></label>
                </div>
            )}
            <div className="cp-grid">
                <label className="sc-field"><span>{t("Remind to change the password after (days)")}</span>
                    <input type="number" min={0} max={3650} value={p.rotation_days} onChange={(e) => set({ rotation_days: e.target.value })} /></label>
                <label className="sc-field"><span>{t("Description")}</span>
                    <input value={p.description || ""} maxLength={2000} dir="auto" onChange={(e) => set({ description: e.target.value })} /></label>
            </div>
            {!isNew && (
                <>
                    <p className="sc-hint">{t("Password set {{date}}; last used {{used}}.", {
                        date: formatDateTime(profile.secrets_changed_at), used: profile.last_used_at ? formatDateTime(profile.last_used_at) : t("never") })}</p>
                    <div className="sc-test">
                        <span className="sc-test-title">{t("Try the sign-in on one asset")}</span>
                        <div className="sc-test-row">
                            <select value={testAsset} onChange={(e) => setTestAsset(e.target.value)} aria-label={t("Asset")}>
                                <option value="">{t("Choose an asset…")}</option>
                                {assetOptions.map((a) => <option key={a.id} value={a.id}>{a.asset_name} · {a.ip_address}</option>)}
                            </select>
                            <button type="button" className="sc-btn sc-btn-ghost" disabled={!testAsset || testing} onClick={runTest}>
                                {testing ? t("Testing…") : t("Test")}</button>
                        </div>
                        <p className="sc-test-note">{t("Uses the saved details: save your changes first. Nothing is changed on the device.")}</p>
                        {test && (
                            <p className={test.result === "ok" ? "sc-test-ok" : "sc-test-fail"}>
                                {TESTED[test.result] || TESTED.error}{test.detail ? ` ${tb(test.detail)}` : ""}
                            </p>
                        )}
                    </div>
                    {confirmDelete ? (
                        <div className="sc-row">
                            <span className="sc-warning">{t("Delete this profile? Group audits that use it can no longer run.")}</span>
                            <button type="button" className="sc-btn sc-btn-danger" onClick={remove}>{t("Delete")}</button>
                            <button type="button" className="sc-btn sc-btn-ghost" onClick={() => setConfirmDelete(false)}>{t("Cancel")}</button>
                        </div>
                    ) : (
                        <button type="button" className="sc-btn sc-btn-danger-ghost" onClick={() => setConfirmDelete(true)}>{t("Delete profile")}</button>
                    )}
                </>
            )}
        </ConfigModal>
    );
}

export default CredentialProfilesModal;
