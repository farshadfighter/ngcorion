import { useCallback, useEffect, useState } from "react";
import api from "../../config/api.js";
import { formatWhen, num } from "./cveFormat.js";
import { Icon } from "./CveIcons.jsx";
import { tb } from "../../i18n/backendText";
import { t as tr } from "../../i18n";

const SOURCE = {
    online: tr("online"),
    osv_zip: tr("OSV file"),
    package: tr("signed package"),
};

/** The distributions' security advisories: which releases are loaded, for which assets, and keeping them current. */
export function CveAdvisories({ busy, onJob }) {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [working, setWorking] = useState(false);
    const [distro, setDistro] = useState("ubuntu");
    const [version, setVersion] = useState("");

    const load = useCallback(() => {
        api.get("/api/cve/advisories")
            .then(({ data: d }) => { setData(d); setError(null); })
            .catch((e) => setError(e.response?.data?.detail || tr("Could not load the advisories")));
    }, []);
    useEffect(() => { load(); }, [load, busy]);

    if (!data) return error ? <div className="cvx-note cvx-note-error">{error}</div> : null;
    const admin = data.is_admin;
    const running = busy || !!data.job;

    const act = async (fn) => {
        setWorking(true);
        setError(null);
        try {
            await fn();
        } catch (e) {
            setError(e.response?.data?.detail ? tb(e.response.data.detail) : tr("That did not work"));
        } finally {
            setWorking(false);
        }
    };
    const update = () => act(async () => { const { data: j } = await api.post("/api/cve/advisories/update"); onJob(j.id); });
    const importFile = (file) => act(async () => {
        const { data: j } = await api.post(`/api/cve/advisories/import?file_name=${encodeURIComponent(file.name)}`, file,
            { headers: { "Content-Type": "application/zip" }, timeout: 0 });
        onJob(j.id);
    });
    const save = (body) => act(async () => { const { data: d } = await api.put("/api/cve/advisories/settings", body); setData(d); });
    const addRelease = () => {
        const v = version.trim();
        if (!v) return;
        save({ releases: [...data.extra, `${distro}:${v}`] }).then(() => setVersion(""));
    };
    const remove = (release) => act(async () => { await api.delete(`/api/cve/advisories/releases/${encodeURIComponent(release)}`); load(); });

    return (
        <section className="cvx-card cvx-adv-card">
            <div className="cvx-card-head">
                <span className="cvx-tile cvx-tile-soft"><Icon name="shield" size={22} stroke="#1e3a5f" width={1.8} /></span>
                <div>
                    <h2>{tr("Linux distribution advisories")}</h2>
                    <p>{tr("Packages from a distribution's own repository are checked against that distribution's security advisories: Ubuntu USN, Debian DSA/DLA, Red Hat RHSA, Rocky RLSA and AlmaLinux ALSA, as published on OSV.dev. Only the releases your assets run are kept.")}</p>
                </div>
                {admin && (
                    <div className="cvx-adv-actions">
                        <button type="button" className="cvx-btn cvx-btn-primary" disabled={running || working} onClick={update}>{tr("Update online")}</button>
                        <label className={`cvx-btn cvx-file-btn ${running || working ? "is-disabled" : ""}`}>
                            <input type="file" accept=".zip" className="cvx-sr" disabled={running || working}
                                   onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ""; if (f) importFile(f); }} />
                            <Icon name="upload" size={16} /> {tr("Import OSV file…")}
                        </label>
                    </div>
                )}
            </div>
            {error && <div className="cvx-note cvx-note-error">{error}</div>}

            <div className="cvx-table-wrap">
                <table className="cvx-table">
                    <thead><tr>
                        <th>{tr("Release")}</th><th className="cvx-num">{tr("Assets")}</th><th className="cvx-num">{tr("Records")}</th>
                        <th>{tr("Updated")}</th><th>{tr("Status")}</th>{admin && <th><span className="cvx-sr">{tr("Actions")}</span></th>}
                    </tr></thead>
                    <tbody>
                        {data.releases.map((r) => (
                            <tr key={r.release}>
                                <td><b>{r.label}</b>{r.requested && !r.assets && <span className="cvx-sub">{tr("kept on request")}</span>}</td>
                                <td className="cvx-num">{num(r.assets)}</td>
                                <td className="cvx-num">{r.records ? num(r.records) : "—"}</td>
                                <td>
                                    {r.updated_at ? formatWhen(r.updated_at) : "—"}
                                    {r.source && <span className="cvx-sub">{SOURCE[r.source] || r.source}{r.last_changes != null && r.source === "online" ? ` · ${tr("{{num}} changed", { num: num(r.last_changes) })}` : ""}</span>}
                                </td>
                                <td>
                                    {r.state === "loaded"
                                        ? <span className="cvx-pill cvx-pill-ok">{tr("Up to date as of {{when}}", { when: formatWhen(r.watermark) })}</span>
                                        : <span className="cvx-pill cvx-pill-muted">{tr("Waiting for the first download")}</span>}
                                </td>
                                {admin && (
                                    <td>{!r.assets && <button type="button" className="cvx-link" disabled={running || working} onClick={() => remove(r.release)}>{tr("Remove")}</button>}</td>
                                )}
                            </tr>
                        ))}
                        {data.releases.length === 0 && (
                            <tr><td colSpan={admin ? 6 : 5} className="cvx-empty-row">
                                {tr("No asset with a supported Linux release has a software list yet. Releases appear here after the first Linux audit or “Collect now”.")}
                            </td></tr>
                        )}
                    </tbody>
                </table>
            </div>

            {data.uncovered.length > 0 && (
                <div className="cvx-note">
                    <b>{tr("Assets whose distribution packages are not checked ({{count}})", { count: data.uncovered.length })}</b>
                    <ul className="cvx-adv-uncovered">
                        {data.uncovered.slice(0, 12).map((u) => (
                            <li key={u.asset_id}>
                                <bdi>{u.asset_name}</bdi>{u.ip_address && <> (<span className="cvx-mono" dir="ltr">{u.ip_address}</span>)</>}:{" "}
                                {u.reason === "unsupported"
                                    ? tr("{{platform}}: no advisories available", { platform: u.platform || "—" })
                                    : tr("release not recorded yet; read at the next audit")}
                            </li>
                        ))}
                    </ul>
                    {data.uncovered.length > 12 && <span className="cvx-muted">{tr("+{{value}} more", { value: data.uncovered.length - 12 })}</span>}
                </div>
            )}

            {admin && (
                <div className="cvx-adv-settings">
                    <label className="cvx-check">
                        <input type="checkbox" checked={data.auto} disabled={working} onChange={(e) => save({ auto: e.target.checked })} />
                        <span>
                            <b>{tr("Update every day")}</b>
                            <small>{tr("At the CVE update time, only the records changed since the last update. A release used for the first time is downloaded within the hour.")}</small>
                        </span>
                    </label>
                    <div className="cvx-adv-add">
                        <span>{tr("Also keep a release no asset runs yet (to export it in a package for another site):")}</span>
                        <select className="cvx-select" value={distro} onChange={(e) => setDistro(e.target.value)} aria-label={tr("Distribution")}>
                            {data.supported.map((s) => <option key={s.distro} value={s.distro}>{s.label}</option>)}
                        </select>
                        <input className="cvx-input cvx-input-sm" dir="ltr" value={version} placeholder={distro === "ubuntu" ? "24.04" : "9"}
                               onChange={(e) => setVersion(e.target.value)} aria-label={tr("Version")} />
                        <button type="button" className="cvx-btn cvx-btn-sm" disabled={!version.trim() || working} onClick={addRelease}>{tr("Add")}</button>
                    </div>
                    <p className="cvx-muted cvx-small">
                        {tr("Without internet: a signed package exported from another NGCorion carries the advisories too. Or download all.zip of the distribution (Ubuntu, Debian, Red Hat, Rocky Linux, AlmaLinux) from osv-vulnerabilities.storage.googleapis.com and import it here; that file is not signed, so only administrators can import it and its SHA-256 is written to the audit log.")}
                    </p>
                </div>
            )}
            {!admin && <p className="cvx-muted cvx-small">{tr("Only administrators can update the advisories.")}</p>}
        </section>
    );
}
