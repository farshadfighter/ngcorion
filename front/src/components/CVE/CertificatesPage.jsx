/**
 * TLS certificates (Vulnerabilities › TLS certificates): what each TLS service of the assets presents, judged
 * for expiry, trust, name, key, signature and old protocol versions (app/modules/tls).
 *
 * Views: what needs attention, every service, those that did not answer, and the settings (ports, interval,
 * warning period, the organisation's trusted authorities). ?asset= shows one asset, ?service= opens one
 * service (alert links).
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useSelector } from "react-redux";

import api from "../../config/api.js";
import { n, t } from "../../i18n";
import { formatDate, formatDateTime, formatWhen } from "../../utils/dates.js";
import { usePermission } from "../../hooks/usePermission";
import { ReportShortcut } from "../Reports/ReportShortcut.jsx";
import { errorText } from "../Software/softwareFormat.js";
import { CveTabs } from "./CveTabs.jsx";
import { LEVEL, SCAN_STATUS, commonName, problemHelp, problemText, protocolName } from "./tlsFormat.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/Software.css";
import "../../assets/UnknownDevices.css";
import "../../assets/BenchmarkPolicy.css";
import "../../assets/Lifecycle.css";
import "../../assets/Certificates.css";

const VIEWS = [["attention", t("Needs attention")], ["all", t("All")], ["silent", t("No answer")], ["settings", t("Settings")]];
const Mono = ({ children }) => <bdi dir="ltr" className="bkm-mono">{children}</bdi>;
const DAY = 86400000;

function daysLeft(iso) {
    if (!iso) return null;
    return Math.floor((new Date(`${iso}Z`).getTime() - Date.now()) / DAY);
}

function useAssets() {
    const [assets, setAssets] = useState([]);
    useEffect(() => {
        api.get("/api/assets/").then(({ data }) => setAssets(Array.isArray(data) ? data : data.items || [])).catch(() => setAssets([]));
    }, []);
    return assets;
}

// ── one service ──────────────────────────────────────────────────────────

function Row({ label, children }) {
    return <div className="tls-row"><span className="tls-key">{label}</span><span className="tls-val">{children}</span></div>;
}

function ServiceDrawer({ id, canWrite, canDelete, onClose, onChanged }) {
    const [s, setS] = useState(null);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const [name, setName] = useState("");
    const load = useCallback(() => {
        api.get(`/api/tls/services/${id}`).then(({ data }) => { setS(data); setName(data.server_name || ""); })
            .catch((e) => setError(errorText(e, t("Could not load the service"))));
    }, [id]);
    useEffect(load, [load]);
    const act = (req) => {
        setBusy(true);
        setError(null);
        req.then(() => { load(); onChanged(); }).catch((e) => setError(errorText(e, t("Could not save")))).finally(() => setBusy(false));
    };
    const rescan = () => act(api.post("/api/tls/scan", { asset_id: s.asset_id }));
    const toggle = () => act(api.patch(`/api/tls/services/${id}`, { enabled: !s.enabled }));
    const saveName = () => act(api.patch(`/api/tls/services/${id}`, { server_name: name.trim() }));
    const remove = () => {
        setBusy(true);
        api.delete(`/api/tls/services/${id}`).then(() => { onChanged(); onClose(); })
            .catch((e) => setError(errorText(e, t("Could not save")))).finally(() => setBusy(false));
    };
    const left = s && daysLeft(s.not_after);
    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="tls-service-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer tls-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="tls-service-title"><Mono>{s?.where || "…"}</Mono></h2>
                        {s && <span className="bkm-sub"><Link to={`/assets/inventory/${s.asset_id}`}><bdi>{s.asset_name}</bdi></Link>
                            {s.source === "manual" && <> · {t("Added by hand")}</>}</span>}
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                    {!s ? <p className="bkm-muted">{t("Loading…")}</p> : (
                        <>
                            <div className="tls-pills">
                                {s.enabled ? <span className={`bkm-pill ${LEVEL[s.level].pill}`}>{LEVEL[s.level].label}</span>
                                    : <span className="bkm-pill bkm-pill-muted">{t("Turned off")}</span>}
                                {s.status !== "read" && <span className="bkm-pill bkm-pill-muted">{SCAN_STATUS[s.status]}</span>}
                            </div>
                            {s.status !== "read" && s.error && <p className="bkm-small bkm-muted"><bdi dir="ltr">{s.error}</bdi></p>}
                            {s.problems.length > 0 && (
                                <ul className="tls-problems">
                                    {s.problems.map((p) => (
                                        <li key={p.code} className={`tls-problem tls-${p.severity}`}>
                                            <b>{problemText(p)}</b>
                                            <span className="bkm-small">{problemHelp(p)}</span>
                                        </li>
                                    ))}
                                </ul>
                            )}
                            {s.fingerprint ? (
                                <section className="tls-section">
                                    <h3>{t("Certificate")}</h3>
                                    <Row label={t("Issued to")}><bdi dir="ltr">{s.subject}</bdi></Row>
                                    <Row label={t("Issuer")}><bdi dir="ltr">{s.issuer}</bdi>{s.trusted === true && <span className="bkm-small bkm-muted tls-block">{t("Trusted")}</span>}</Row>
                                    <Row label={t("Names")}>{s.names.length ? <Mono>{s.names.join(", ")}</Mono> : "—"}</Row>
                                    <Row label={t("Valid from")}>{formatDate(s.not_before)}</Row>
                                    <Row label={t("Valid until")}>{formatDate(s.not_after)}
                                        {left !== null && <span className="bkm-small bkm-muted tls-block">
                                            {left < 0 ? t("{{count}} days ago", { count: -left }) : t("in {{count}} days", { count: left })}</span>}</Row>
                                    <Row label={t("Key")}>{s.key_type ? <Mono>{`${s.key_type} ${s.key_bits || ""}`.trim()}</Mono> : "—"}</Row>
                                    <Row label={t("Signature")}>{s.signature ? <Mono>{s.signature.toUpperCase()}</Mono> : "—"}</Row>
                                    <Row label={t("Protocol")}>{s.protocol ? <Mono>{protocolName(s.protocol)}</Mono> : "—"}
                                        <span className="bkm-small bkm-muted tls-block">{s.old_protocols == null ? t("TLS 1.0 and 1.1 not checked")
                                            : s.old_protocols.length ? t("Also accepts {{protocols}}", { protocols: s.old_protocols.map(protocolName).join(t(", ")) })
                                                : t("Refuses TLS 1.0 and 1.1")}</span></Row>
                                    <Row label={t("SHA-256 fingerprint")}><Mono>{s.fingerprint.match(/.{1,2}/g).join(":")}</Mono></Row>
                                    <Row label={t("Serial number")}><Mono>{s.serial}</Mono></Row>
                                    {s.chain.length > 1 && (
                                        <Row label={t("Chain sent")}>
                                            <ol className="tls-chain">{s.chain.map((c, i) => <li key={i}><bdi dir="ltr">{commonName(c.subject)}</bdi></li>)}</ol>
                                        </Row>
                                    )}
                                    {s.cert_changed_at && <Row label={t("Certificate changed")}>{formatDateTime(s.cert_changed_at)}</Row>}
                                </section>
                            ) : <p className="bkm-muted">{t("No certificate has been read from this service yet.")}</p>}
                            <section className="tls-section">
                                <h3>{t("Scan")}</h3>
                                <Row label={t("Last scan")}>{s.last_scan_at ? formatWhen(s.last_scan_at) : t("Not yet")}</Row>
                                <Row label={t("Last answer")}>{s.last_ok_at ? formatWhen(s.last_ok_at) : "—"}</Row>
                                <label className="alr-lbl">{t("Server name (sent in the handshake and checked)")}
                                    <span className="eol-inline tls-name">
                                        <input className="bkm-select" dir="ltr" value={name} maxLength={253} disabled={!canWrite}
                                               placeholder={t("e.g. portal.example.com")} onChange={(e) => setName(e.target.value)} />
                                        {canWrite && <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy || name.trim() === (s.server_name || "")}
                                                             onClick={saveName}>{t("Save")}</button>}
                                    </span>
                                </label>
                            </section>
                        </>
                    )}
                </div>
                {s && (canWrite || canDelete) && (
                    <footer className="bkm-drawer-foot">
                        {canDelete && s.source === "manual" && <button type="button" className="bkm-btn" disabled={busy} onClick={remove}>{t("Remove")}</button>}
                        {canWrite && <button type="button" className="bkm-btn" disabled={busy} onClick={toggle}>{s.enabled ? t("Turn off") : t("Turn on")}</button>}
                        {canWrite && <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy} onClick={rescan}>{busy ? t("Scanning…") : t("Scan this asset again")}</button>}
                    </footer>
                )}
            </aside>
        </div>
    );
}

// ── added by hand ────────────────────────────────────────────────────────

function AddDrawer({ presetAsset, onClose, onDone }) {
    const assets = useAssets();
    const [q, setQ] = useState("");
    const [form, setForm] = useState({ asset_id: presetAsset || "", port: "443", host: "", server_name: "" });
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const shown = useMemo(() => {
        const needle = q.trim().toLowerCase();
        return assets.filter((a) => !needle || `${a.asset_name} ${a.ip_address || ""}`.toLowerCase().includes(needle)).slice(0, 200);
    }, [assets, q]);
    const port = Number(form.port);
    const ready = form.asset_id && port >= 1 && port <= 65535;
    const save = () => {
        setBusy(true);
        setError(null);
        api.post("/api/tls/services", { asset_id: Number(form.asset_id), port, host: form.host.trim() || null,
            server_name: form.server_name.trim() || null })
            .then(({ data }) => onDone(data.id)).catch((e) => setError(errorText(e, t("Could not save")))).finally(() => setBusy(false));
    };
    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="tls-add-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <aside className="bkm-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <h2 id="tls-add-title">{t("Add a TLS service")}</h2>
                        <span className="bkm-sub">{t("A service the automatic scan does not find: another port, or a name of its own. It is read at once.")}</span>
                    </div>
                    <button type="button" className="bkm-icon-btn" onClick={onClose} aria-label={t("Close")}>✕</button>
                </header>
                <div className="bkm-drawer-body">
                    <label className="alr-lbl">{t("Asset")}
                        <input className="bkm-select" type="search" value={q} placeholder={t("Search assets…")} onChange={(e) => setQ(e.target.value)} />
                        <select className="bkm-select eol-pick" size={6} value={form.asset_id} onChange={(e) => setForm({ ...form, asset_id: e.target.value })}>
                            {shown.map((a) => <option key={a.id} value={a.id}>{a.asset_name}{a.ip_address ? ` · ${a.ip_address}` : ""}</option>)}
                        </select>
                    </label>
                    <label className="alr-lbl">{t("Port")}
                        <input className="bkm-select tls-port" type="number" min={1} max={65535} dir="ltr" value={form.port}
                               onChange={(e) => setForm({ ...form, port: e.target.value })} />
                    </label>
                    <label className="alr-lbl">{t("Host (optional)")}
                        <input className="bkm-select" dir="ltr" value={form.host} maxLength={253} placeholder={t("The asset's address")}
                               onChange={(e) => setForm({ ...form, host: e.target.value })} />
                    </label>
                    <label className="alr-lbl">{t("Server name (optional)")}
                        <input className="bkm-select" dir="ltr" value={form.server_name} maxLength={253} placeholder={t("e.g. portal.example.com")}
                               onChange={(e) => setForm({ ...form, server_name: e.target.value })} />
                    </label>
                    <p className="bkm-small bkm-muted">{t("The server name is sent in the handshake (for servers with several sites) and checked against the certificate.")}</p>
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                </div>
                <footer className="bkm-drawer-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || !ready} onClick={save}>{busy ? t("Reading…") : t("Add and read")}</button>
                </footer>
            </aside>
        </div>
    );
}

// ── settings and trusted authorities ─────────────────────────────────────

function Settings({ isAdmin, onChanged }) {
    const [form, setForm] = useState(null);
    const [cas, setCas] = useState([]);
    const [ca, setCa] = useState({ name: "", pem: "" });
    const [notice, setNotice] = useState(null);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const loadCas = () => api.get("/api/tls/cas").then(({ data }) => setCas(data)).catch(() => setCas([]));
    useEffect(() => {
        api.get("/api/tls/settings").then(({ data }) => setForm({ ...data, ports: data.ports.join(", ") }))
            .catch((e) => setError(errorText(e, t("Could not load the settings"))));
        loadCas();
    }, []);
    const done = (msg) => { setNotice(msg); setError(null); onChanged(); };
    const fail = (e) => { setError(errorText(e, t("Could not save"))); setNotice(null); };
    const save = () => {
        setBusy(true);
        const ports = form.ports.split(/[\s,،]+/).map(Number).filter((p) => p >= 1 && p <= 65535);
        api.put("/api/tls/settings", { warn_days: Number(form.warn_days), auto_scan: form.auto_scan, interval_hours: Number(form.interval_hours),
            check_protocols: form.check_protocols, ports })
            .then(({ data }) => { setForm({ ...data, ports: data.ports.join(", ") }); done(t("Saved")); }).catch(fail).finally(() => setBusy(false));
    };
    const readFile = (file) => {
        if (!file) return;
        file.text().then((text) => setCa((c) => ({ name: c.name || file.name.replace(/\.(pem|crt|cer)$/i, ""), pem: text })));
    };
    const addCa = () => {
        setBusy(true);
        api.post("/api/tls/cas", { name: ca.name.trim(), pem: ca.pem })
            .then(() => { setCa({ name: "", pem: "" }); loadCas(); done(t("The authority is trusted from the next scan")); }).catch(fail).finally(() => setBusy(false));
    };
    const removeCa = (id) => api.delete(`/api/tls/cas/${id}`).then(() => { loadCas(); done(t("Removed")); }).catch(fail);
    if (!form) return error ? <div className="bkm-note bkm-note-error">{error}</div> : <p className="bkm-muted">{t("Loading…")}</p>;
    const dis = !isAdmin;
    return (
        <>
            {notice && <div className="bkm-note bkm-note-ok">{notice}</div>}
            {error && <div className="bkm-note bkm-note-error">{error}</div>}
            <section className="bkm-card">
                <div className="bkm-card-head tls-flush-head">
                    <div>
                        <h2>{t("Scan")}</h2>
                        <p>{t("NGCorion only opens a TLS handshake to each port: no password, nothing changes on the device. Ports discovery found open with a TLS service (https, ldaps, imaps …) are scanned too.")}</p>
                    </div>
                </div>
                <div className="tls-form">
                    <label className="tls-check"><input type="checkbox" checked={form.auto_scan} disabled={dis}
                                                         onChange={(e) => setForm({ ...form, auto_scan: e.target.checked })} />{t("Scan automatically")}</label>
                    <label className="alr-lbl">{t("Every")}
                        <span className="eol-inline"><input className="bkm-select tls-num" type="number" min={6} max={168} value={form.interval_hours} disabled={dis}
                                                            onChange={(e) => setForm({ ...form, interval_hours: e.target.value })} /><span>{t("hours")}</span></span>
                    </label>
                    <label className="alr-lbl">{t("Warn before expiry")}
                        <span className="eol-inline"><input className="bkm-select tls-num" type="number" min={7} max={180} value={form.warn_days} disabled={dis}
                                                            onChange={(e) => setForm({ ...form, warn_days: e.target.value })} /><span>{t("days")}</span></span>
                    </label>
                    <label className="tls-check"><input type="checkbox" checked={form.check_protocols} disabled={dis}
                                                         onChange={(e) => setForm({ ...form, check_protocols: e.target.checked })} />{t("Check whether TLS 1.0 and 1.1 are still accepted")}</label>
                    <label className="alr-lbl tls-wide">{t("Ports")}
                        <input className="bkm-select" dir="ltr" value={form.ports} disabled={dis} onChange={(e) => setForm({ ...form, ports: e.target.value })} />
                    </label>
                </div>
                {isAdmin && <div className="bkm-card-foot tls-foot"><button type="button" className="bkm-btn bkm-btn-primary" disabled={busy} onClick={save}>{t("Save")}</button></div>}
            </section>

            <section className="bkm-card bkm-flush">
                <div className="bkm-card-head">
                    <div>
                        <h2>{t("Trusted certificate authorities")}</h2>
                        <p>{t("Certificates issued by these authorities of the organisation count as trusted, besides the public authorities. Upload the CA certificate (PEM), not its key.")}</p>
                    </div>
                </div>
                {cas.length === 0 ? <div className="bkm-empty"><b>{t("Only the public authorities are trusted")}</b></div> : (
                    <div className="bkm-table-wrap">
                        <table className="bkm-table">
                            <thead><tr><th>{t("Name")}</th><th>{t("Subject")}</th><th>{t("Valid until")}</th><th /></tr></thead>
                            <tbody>
                                {cas.map((c) => (
                                    <tr key={c.id}>
                                        <td><bdi dir="auto">{c.name}</bdi></td>
                                        <td className="bkm-small"><bdi dir="ltr">{c.subject}</bdi></td>
                                        <td className="bkm-small">{formatDate(c.not_after)}</td>
                                        <td>{isAdmin && <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => removeCa(c.id)}>{t("Remove")}</button>}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
                {isAdmin && (
                    <div className="tls-form tls-ca-form">
                        <label className="alr-lbl">{t("Name")}
                            <input className="bkm-select" value={ca.name} maxLength={200} dir="auto" onChange={(e) => setCa({ ...ca, name: e.target.value })} />
                        </label>
                        <label className="alr-lbl tls-wide">{t("CA certificate (PEM)")}
                            <textarea className="bkm-select bp-reason tls-pem" rows={5} dir="ltr" value={ca.pem} placeholder="-----BEGIN CERTIFICATE-----"
                                      onChange={(e) => setCa({ ...ca, pem: e.target.value })} />
                        </label>
                        <div className="bkm-actions tls-wide">
                            <label className="bkm-btn eol-file">{t("Choose a file")}
                                <input type="file" accept=".pem,.crt,.cer" onChange={(e) => { readFile(e.target.files?.[0]); e.target.value = ""; }} />
                            </label>
                            <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy || ca.name.trim().length < 2 || ca.pem.length < 50} onClick={addCa}>{t("Trust this authority")}</button>
                        </div>
                    </div>
                )}
            </section>
        </>
    );
}

// ── page ─────────────────────────────────────────────────────────────────

export function CertificatesPage() {
    const canWrite = usePermission("cve", "write");
    const canDelete = usePermission("cve", "delete");
    const isAdmin = useSelector((s) => s.auth.role) === "admin";
    const [params, setParams] = useSearchParams();
    const assetFilter = Number(params.get("asset")) || null;
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [view, setView] = useState("attention");
    const [open, setOpen] = useState(Number(params.get("service")) || null);
    const [adding, setAdding] = useState(false);
    const [tick, setTick] = useState(0);
    const refresh = () => setTick((x) => x + 1);
    useEffect(() => {
        api.get("/api/tls/overview").then(({ data: d }) => setData(d)).catch((e) => setError(errorText(e, t("Could not load the TLS certificates"))));
    }, [tick]);
    const scanning = data?.scan.running || data?.scan.requested;
    useEffect(() => {
        if (!scanning) return undefined;
        const timer = setInterval(refresh, 5000);
        return () => clearInterval(timer);
    }, [scanning]);

    const services = useMemo(() => (data?.services || [])
        .filter((s) => !assetFilter || s.asset_id === assetFilter)
        .filter((s) => (view === "attention" ? s.enabled && (s.level === "critical" || s.level === "warning")
            : view === "silent" ? s.status === "unreachable" || s.status === "no_tls" : true)), [data, view, assetFilter]);
    const silent = (data?.services || []).filter((s) => s.status === "unreachable" || s.status === "no_tls").length;
    const sum = data?.summary;
    const filteredAsset = assetFilter && data?.services.find((s) => s.asset_id === assetFilter);
    const scanAll = () => api.post("/api/tls/scan", {}).then(refresh)
        .catch((e) => setError(errorText(e, t("Could not start the scan"))));

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <span className="bkm-crumb">{t("Security assessment")} › {t("Vulnerabilities (CVE)")}</span>
                    <h1>{t("TLS certificates")}</h1>
                    <p>{t("Certificates of the TLS services the assets run (web, LDAPS, mail, device management …): expired or about to, not trusted, for another name, weak, or still accepting TLS 1.0 and 1.1.")}</p>
                </div>
                <div className="bkm-actions">
                    <ReportShortcut template="tls_certificates" className="bkm-btn" />
                    {canWrite && <button type="button" className="bkm-btn" disabled={scanning} onClick={scanAll}>{scanning ? t("Scanning…") : t("Scan now")}</button>}
                    {canWrite && <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => setAdding(true)}>{t("Add a service")}</button>}
                </div>
            </div>
            <CveTabs />
            {error && <div className="bkm-note bkm-note-error">{error}</div>}

            {data && (
                <>
                    <div className="bkm-stats bkm-stats-4">
                        {[["critical", t("Expired"), sum.levels.critical], ["warning", t("With problems"), sum.levels.warning],
                          ["soon", t("Expire within 30 days"), sum.expiring_30], ["ok", t("No problem"), sum.levels.ok]].map(([k, label, value]) => (
                            <button key={k} type="button" className={`bkm-stat eol-stat tls-stat-${k}`} onClick={() => setView(k === "ok" ? "all" : "attention")}>
                                <b>{n(value || 0)}</b><span>{label}</span>
                            </button>
                        ))}
                    </div>
                    <p className="bkm-small bkm-muted tls-scan-line">
                        {data.scan.running ? t("Scanning…") : data.scan.requested ? t("The scan starts within a minute")
                            : data.scan.last_run ? t("Last scan {{when}}: {{services}} services on {{assets}} assets", {
                                when: formatWhen(data.scan.last_run), services: n(sum.services), assets: n(sum.assets) })
                                : t("Not scanned yet")}
                        {!data.auto_scan && <> · {t("Automatic scan off")}</>}
                    </p>
                </>
            )}
            {data && sum.services === 0 && !scanning && (
                <div className="bkm-note bkm-note-orange">{t("No TLS service is known yet. The scan reads the usual TLS ports of every asset with an address; start one with Scan now.")}</div>
            )}
            {filteredAsset && (
                <div className="bkm-note sl-banner">
                    <span className="sl-banner-text">{t("Only the asset {{name}}", { name: filteredAsset.asset_name })}</span>
                    <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => setParams({})}>{t("Show all")}</button>
                </div>
            )}

            <div className="bkm-chips" role="tablist" aria-label={t("View")}>
                {VIEWS.map(([k, label]) => (
                    <button key={k} type="button" role="tab" aria-selected={view === k}
                            className={`bkm-chip ${view === k ? "is-on" : ""}`} onClick={() => setView(k)}>
                        {label}{k === "silent" && silent ? <span className="ud-count">{n(silent)}</span> : null}
                    </button>
                ))}
            </div>

            {view !== "settings" && data && (
                <section className="bkm-card bkm-flush">
                    {services.length === 0 ? (
                        <div className="bkm-empty"><b>{view === "attention" ? t("Nothing needs attention") : t("Nothing here")}</b>
                            {view === "attention" && sum.services > 0 && <span>{t("No certificate is expired, about to expire or weak.")}</span>}</div>
                    ) : (
                        <div className="bkm-table-wrap">
                            <table className="bkm-table tls-table">
                                <thead><tr><th>{t("Service")}</th><th>{t("Certificate")}</th><th>{t("Status")}</th><th>{t("Valid until")}</th></tr></thead>
                                <tbody>
                                    {services.map((s) => {
                                        const left = daysLeft(s.not_after);
                                        return (
                                            <tr key={s.id} className="tls-click" tabIndex={0} onClick={() => setOpen(s.id)}
                                                onKeyDown={(e) => e.key === "Enter" && setOpen(s.id)}>
                                                <td>
                                                    <div className="ud-addr">
                                                        <b><Mono>{s.where}</Mono></b>
                                                        <span className="bkm-small bkm-muted"><bdi>{s.asset_name}</bdi>{s.source === "manual" && <> · {t("Added by hand")}</>}</span>
                                                    </div>
                                                </td>
                                                <td>
                                                    <div className="ud-addr">
                                                        <bdi dir="ltr">{commonName(s.subject)}</bdi>
                                                        {s.issuer && <span className="bkm-small bkm-muted">{t("by {{issuer}}", { issuer: commonName(s.issuer) })}</span>}
                                                    </div>
                                                </td>
                                                <td>
                                                    <div className="bp-stack">
                                                        <span className="tls-pills">
                                                            {s.enabled ? <span className={`bkm-pill ${LEVEL[s.level].pill}`}>{LEVEL[s.level].label}</span>
                                                                : <span className="bkm-pill bkm-pill-muted">{t("Turned off")}</span>}
                                                            {s.status !== "read" && <span className="bkm-pill bkm-pill-muted">{SCAN_STATUS[s.status]}</span>}
                                                        </span>
                                                        {s.problems.filter((p) => p.code !== "expired").map((p) => <span key={p.code} className="bkm-small">{problemText(p)}</span>)}
                                                    </div>
                                                </td>
                                                <td className="bkm-small">
                                                    {s.not_after ? <>{formatDate(s.not_after)}<span className={`tls-block ${left < 0 ? "tls-bad" : left <= (data.warn_days || 30) ? "tls-warn" : "bkm-muted"}`}>
                                                        {left < 0 ? t("{{count}} days ago", { count: -left }) : t("in {{count}} days", { count: left })}</span></> : "—"}
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    )}
                </section>
            )}

            {view === "settings" && <Settings isAdmin={isAdmin} onChanged={refresh} />}

            {open && <ServiceDrawer id={open} canWrite={canWrite} canDelete={canDelete} onChanged={refresh}
                                    onClose={() => { setOpen(null); if (params.get("service")) { params.delete("service"); setParams(params); } }} />}
            {adding && <AddDrawer presetAsset={assetFilter} onClose={() => setAdding(false)}
                                  onDone={(id) => { setAdding(false); refresh(); setOpen(id); }} />}
        </div>
    );
}
