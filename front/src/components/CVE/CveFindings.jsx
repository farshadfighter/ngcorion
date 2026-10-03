import { useEffect, useMemo, useRef, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { Link, useNavigate } from "react-router-dom";
import api from "../../config/api.js";
import { fetchCveDbStatus, fetchCveFindings } from "../../store/cveSlice.jsx";
import { usePermission } from "../../hooks/usePermission";
import { AssetIcon } from "../shared/AssetIcon.jsx";
import { PRIORITY, SEVERITY, ageDays, epssColor, epssLabel, formatWhen, num, versionCompare } from "./cveFormat.js";
import { Icon } from "./CveIcons.jsx";
import { CveJobModal } from "./CveJobModal.jsx";
import { CvePackageImport } from "./CvePackageImport.jsx";
import { CveDetail } from "./CveDetail.jsx";
import { ReportShortcut } from "../Reports/ReportShortcut.jsx";
import { CveAssetProducts } from "./CveAssetProducts.jsx";
import "../../assets/Cve.css";
import { t as tr, n } from "../../i18n";
import { tx } from "../../i18n/tx";

const TABS = [
    { key: "first", label: tr("Fix first") },
    { key: "all", label: tr("All findings") },
    { key: "updates", label: tr("By update") },
    { key: "assets", label: tr("By asset") },
    { key: "cves", label: tr("By CVE") },
];
const SOURCES = [
    { key: "", label: tr("Every source") },
    { key: "advisory", label: tr("Distribution advisories") },
    { key: "nvd", label: tr("NVD") },
];
const PAGE = 100;

const matchText = (q, ...values) => values.some((v) => v && String(v).toLowerCase().includes(q));

export function CveFindings() {
    const dispatch = useDispatch();
    const { summary, findings: allFindings, assets, databaseLoaded, advisoriesLoaded, isLoading, loadedOnce, error, status } = useSelector((s) => s.cve);
    const [source, setSource] = useState("");
    const findings = useMemo(() => (source ? allFindings.filter((f) => (f.source || "nvd") === source) : allFindings),
        [allFindings, source]);
    const canWrite = usePermission("cve", "write");
    const [tab, setTab] = useState("first");
    const [search, setSearch] = useState("");
    const [limit, setLimit] = useState(PAGE);
    const [detail, setDetail] = useState(null);
    const [jobId, setJobId] = useState(null);

    useEffect(() => {
        dispatch(fetchCveFindings());
        dispatch(fetchCveDbStatus());
    }, [dispatch]);

    // A load/update running in the background: refresh when it ends.
    const running = status?.active_job;
    useEffect(() => {
        if (!running || jobId) return undefined;
        const t = setInterval(() => dispatch(fetchCveDbStatus()), 4000);
        return () => clearInterval(t);
    }, [running, jobId, dispatch]);
    const wasRunning = useRef(false);
    useEffect(() => {
        if (wasRunning.current && !running) dispatch(fetchCveFindings());
        wasRunning.current = !!running;
    }, [running, dispatch]);

    const q = search.trim().toLowerCase();
    const rows = useMemo(() => {
        let r = tab === "first" ? findings.filter((f) => f.priority <= 2) : findings;
        if (q) r = r.filter((f) => matchText(q, f.cve_id, f.asset_name, f.product, f.ip_address, f.description));
        return r;
    }, [findings, tab, q]);

    const byCve = useMemo(() => {
        const map = new Map();
        for (const f of findings) {
            if (q && !matchText(q, f.cve_id, f.asset_name, f.product, f.description)) continue;
            const g = map.get(f.cve_id) || { ...f, assets: [] };
            g.assets.push({ id: f.asset_id, name: f.asset_name, icon: f.asset_icon });
            map.set(f.cve_id, g);
        }
        return [...map.values()];
    }, [findings, q]);

    // One line per fix to install: a package of a release, the version that fixes it, on every asset that needs it.
    const byUpdate = useMemo(() => {
        const map = new Map();
        for (const f of findings) {
            if (f.source !== "advisory") continue;
            if (q && !matchText(q, f.cve_id, f.asset_name, f.product, ...(f.advisories || []))) continue;
            const key = `${f.release}|${f.package}`;
            const g = map.get(key) || { key, package: f.package, vendor: f.vendor, release: f.release, fixed_in: f.fixed_in,
                advisories: new Set(), cves: new Map(), assets: new Map(), priority: f.priority, kev: false, cvss: null,
                epss: null, pro: true, reboot: 0 };
            (f.advisories || []).forEach((a) => g.advisories.add(a));
            g.cves.set(f.cve_id, f);
            g.assets.set(f.asset_id, { id: f.asset_id, name: f.asset_name, icon: f.asset_icon, reboot: f.reboot });
            g.priority = Math.min(g.priority, f.priority);
            g.kev = g.kev || f.kev;
            if (f.cvss != null && (g.cvss == null || f.cvss > g.cvss)) { g.cvss = f.cvss; g.severity = f.severity; }
            if (g.cvss == null && !g.severity) g.severity = f.severity;
            if (f.epss != null && (g.epss == null || f.epss > g.epss)) g.epss = f.epss;
            g.pro = g.pro && f.availability === "pro";
            if (versionCompare(f.fixed_in, g.fixed_in) > 0) g.fixed_in = f.fixed_in;
            map.set(key, g);
        }
        return [...map.values()].map((g) => ({ ...g, advisories: [...g.advisories].sort(), cves: [...g.cves.values()],
            assets: [...g.assets.values()] }))
            .sort((a, b) => a.priority - b.priority || b.kev - a.kev || b.assets.length - a.assets.length
                || b.cves.length - a.cves.length || a.package.localeCompare(b.package));
    }, [findings, q]);

    const closeJob = () => {
        setJobId(null);
        dispatch(fetchCveDbStatus());
        dispatch(fetchCveFindings());
    };

    const changeTab = (key) => { setTab(key); setLimit(PAGE); };

    const showFirstRun = loadedOnce && !databaseLoaded && !advisoriesLoaded;

    return (
        <div className="cvx-page">
            <div className="cvx-head">
                <div>
                    <h1>{tr("CVE Findings")}</h1>
                    <p>{tr("Known vulnerabilities in your assets, ordered by what to fix first.")}</p>
                </div>
                <div className="cvx-head-actions">
                    <ReportShortcut template="cve" className="cvx-btn cvx-btn-sm" />
                    <DbPill status={status} onOpenJob={setJobId} />
                </div>
            </div>

            {error && <div className="cvx-note cvx-note-error">{error}</div>}

            {showFirstRun ? (
                <FirstRun status={status} onStarted={setJobId} />
            ) : (
                <>
                    <div className="cvx-stats">
                        <button type="button" className={`cvx-stat cvx-stat-btn cvx-stat-hot ${tab === "first" ? "is-on" : ""}`} onClick={() => changeTab("first")}>
                            <b className="cvx-bad">{num(summary.fix_now)}</b><span>{tr("Fix now · exploited in the wild")}</span>
                        </button>
                        {["critical", "high", "medium", "low"].map((s) => (
                            <div key={s} className="cvx-stat"><b style={{ color: SEVERITY[s].fg }}>{num(summary[s])}</b><span>{SEVERITY[s].label}</span></div>
                        ))}
                        <button type="button" className={`cvx-stat cvx-stat-btn ${tab === "assets" ? "is-on" : ""}`} onClick={() => changeTab("assets")}>
                            <b className="cvx-navy">{num(summary.affected_assets)}</b><span>{tr("Affected assets")}</span>
                        </button>
                    </div>

                    <div className="cvx-toolbar">
                        <div role="tablist" aria-label={tr("Findings view")} className="cvx-tabs">
                            {TABS.map((t) => (
                                <button key={t.key} type="button" role="tab" aria-selected={tab === t.key}
                                        className={`cvx-tab ${tab === t.key ? "is-on" : ""}`} onClick={() => changeTab(t.key)}>
                                    {t.label}
                                    {t.key === "first" && <span className="cvx-count">{n(findings.filter((f) => f.priority <= 2).length)}</span>}
                                </button>
                            ))}
                        </div>
                        <div className="cvx-source" role="group" aria-label={tr("Source")}>
                            {SOURCES.map((s) => (
                                <button key={s.key} type="button" aria-pressed={source === s.key}
                                        className={`cvx-source-btn ${source === s.key ? "is-on" : ""}`}
                                        onClick={() => { setSource(s.key); setLimit(PAGE); }}>{s.label}</button>
                            ))}
                        </div>
                        <label className="cvx-search">
                            <Icon name="search" size={15} />
                            <input aria-label={tr("Search findings")} placeholder={tab === "assets" ? tr("Search asset or product") : tr("Search CVE, asset or product")}
                                   value={search} onChange={(e) => { setSearch(e.target.value); setLimit(PAGE); }} />
                        </label>
                    </div>

                    {isLoading && !findings.length ? (
                        <div className="cvx-card cvx-empty">{tr("Loading findings…")}</div>
                    ) : tab === "assets" ? (
                        <CveAssetProducts assets={assets} search={q} canWrite={canWrite}
                                          onChanged={() => dispatch(fetchCveFindings())} />
                    ) : tab === "cves" ? (
                        <CveTable groups={byCve.slice(0, limit)} onOpen={setDetail} />
                    ) : tab === "updates" ? (
                        <UpdatesTable groups={byUpdate.slice(0, limit)} onOpen={setDetail} />
                    ) : (
                        <FindingsTable rows={rows.slice(0, limit)} onOpen={setDetail} emptyText={
                            tab === "first"
                                ? (findings.length ? tr("Nothing urgent: no finding is exploited in the wild or critical. See All findings.") : null)
                                : null
                        } assetsWithoutProducts={assets.filter((a) => !a.products.length).length} onAssets={() => changeTab("assets")} />
                    )}

                    {tab !== "assets" && (tab === "cves" ? byCve.length : tab === "updates" ? byUpdate.length : rows.length) > limit && (
                        <div className="cvx-more">
                            <button type="button" className="cvx-btn" onClick={() => setLimit(limit + PAGE * 2)}>
                                {tr("Show more ({{num}} left)", { num: num((tab === "cves" ? byCve.length : tab === "updates" ? byUpdate.length : rows.length) - limit) })}
                            </button>
                        </div>
                    )}

                    <p className="cvx-footnote">
                        {tr("Packages from a Linux distribution's own repository are matched against that distribution's security advisories (Ubuntu USN, Debian DSA/DLA, Red Hat RHSA, Rocky RLSA, AlmaLinux ALSA); other software by vendor, product and version (CPE) against the local CVE database. Exploit likelihood from FIRST EPSS; \"Exploited in the wild\" from CISA KEV.")}
                    </p>
                </>
            )}

            {detail && <CveDetail cveId={detail.cve_id} finding={detail} onClose={() => setDetail(null)} />}
            {jobId && <CveJobModal jobId={jobId} isAdmin={!!status?.is_admin} onClose={closeJob} />}
        </div>
    );
}

function DbPill({ status, onOpenJob }) {
    if (!status) return null;
    const job = status.active_job;
    let dot = "#94a3b8";
    let text = <span>{tr("CVE database not loaded")}</span>;
    if (job) {
        dot = "#2563eb";
        text = <span><b>{tr("Updating the CVE database…")}</b></span>;
    } else if (status.loaded) {
        const age = ageDays(status.watermark);
        dot = age != null && age <= 7 ? "#16a34a" : "#d97706";
        text = <span>{tx("CVE database · {{cves}} · updated {{when}}", { cves: <b>{tr("{{num}} CVEs", { num: num(status.cves) })}</b>, when: formatWhen(status.watermark) })}</span>;
    }
    if (job) {
        return (
            <button type="button" className="cvx-pill-link" onClick={() => onOpenJob(job.id)}>
                <span className="cvx-spin cvx-spin-sm" />{text}<span className="cvx-pill-cta">{tr("View →")}</span>
            </button>
        );
    }
    return (
        <Link to="/cve/database" className="cvx-pill-link">
            <span className="cvx-dot" style={{ background: dot }} />{text}<span className="cvx-pill-cta">{tr("Manage →")}</span>
        </Link>
    );
}

function PriorityPill({ p }) {
    const s = PRIORITY[p] || PRIORITY[4];
    return <span className="cvx-pill" style={{ background: s.bg, color: s.fg }} title={s.hint}>{s.label}</span>;
}

function CvssPill({ score, severity }) {
    if (score == null) return <span className="cvx-muted">—</span>;
    const s = SEVERITY[severity] || SEVERITY.low;
    return <span className="cvx-pill" style={{ background: s.bg, color: s.fg }} title={s.label}>{n(Number(score).toFixed(1))}</span>;
}

export function Epss({ value }) {
    if (value == null) return <span className="cvx-muted">—</span>;
    return (
        <span className="cvx-epss" title={tr("{{epssLabel}} chance of exploitation in the next 30 days (FIRST EPSS)", { epssLabel: epssLabel(value) })}>
            <span className="cvx-epss-track"><span style={{ width: `${Math.max(3, Math.round(value * 100))}%`, background: epssColor(value) }} /></span>
            <span>{epssLabel(value)}</span>
        </span>
    );
}

function CveId({ f, onOpen }) {
    return (
        <>
            <div className="cvx-cve">
                <button type="button" className="cvx-cve-id" onClick={() => onOpen(f)}>{f.cve_id}</button>
                {f.kev && <span className="cvx-pill cvx-pill-kev"><Icon name="flame" size={12} width={2.2} /> {" "}{tr("Exploited in the wild")}</span>}
            </div>
            <div className="cvx-sub cvx-clip bidi-auto" title={f.description}>{f.description}</div>
        </>
    );
}

function FindingsTable({ rows, onOpen, emptyText, assetsWithoutProducts, onAssets }) {
    if (!rows.length) {
        return (
            <div className="cvx-card cvx-empty">
                <Icon name="shield" size={30} stroke="#16a34a" width={1.8} />
                <b>{emptyText || tr("No known vulnerabilities in your assets")}</b>
                {!emptyText && assetsWithoutProducts > 0 && (
                    <span>
                        {tr("{{count}} assets have no recognised product, so nothing could be matched.", { count: assetsWithoutProducts })}{" "}
                        <button type="button" className="cvx-link" onClick={onAssets}>{tr("Add their software")}</button>
                    </span>
                )}
            </div>
        );
    }
    return (
        <div className="cvx-card cvx-card-flush cvx-table-wrap">
            <table className="cvx-table">
                <thead>
                    <tr><th>{tr("Priority")}</th><th>{tr("CVE")}</th><th>{tr("Asset")}</th><th>{tr("Product")}</th><th>{tr("Installed")}</th><th>{tr("CVSS")}</th><th>{tr("Exploit likelihood")}</th></tr>
                </thead>
                <tbody>
                    {rows.map((f) => (
                        <tr key={`${f.asset_id}-${f.cve_id}`}>
                            <td><PriorityPill p={f.priority} /></td>
                            <td className="cvx-cve-cell"><CveId f={f} onOpen={onOpen} /></td>
                            <td className="cvx-tight">
                                <span className="cvx-asset">
                                    <AssetIcon icon={f.asset_icon} size={28} />
                                    <span><b>{f.asset_name}</b>{f.ip_address && <span className="cvx-sub cvx-mono">{f.ip_address}</span>}</span>
                                </span>
                            </td>
                            <td className="cvx-tight"><bdi>{f.product}</bdi>{f.identity_source === "manual" && <span className="cvx-sub">{tr("added by hand")}</span>}
                                {f.identity_source === "inventory" && <span className="cvx-sub cvx-from-inv">{tr("from the software inventory")}</span>}
                                {f.source === "advisory" && <AdvisoryLine f={f} />}</td>
                            <td className="cvx-tight">
                                <span className="cvx-mono">{f.installed || "?"}</span>
                                {f.fixed_in
                                    ? <span className="cvx-sub cvx-fixed">{tr("fixed in")}{" "} <span className="cvx-mono">{f.fixed_in}</span></span>
                                    : <span className="cvx-sub" title={tr("NVD lists no fixed version - see the advisory")}>{tr("fix: see advisory")}</span>}
                                {f.reboot && <span className="cvx-sub cvx-reboot">{tr("Installed; needs a reboot")}</span>}
                            </td>
                            <td><CvssPill score={f.cvss} severity={f.severity} /></td>
                            <td><Epss value={f.epss} /></td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function AdvisoryLine({ f }) {
    return (
        <span className="cvx-sub cvx-adv">
            <span className="cvx-adv-src">{f.vendor}</span>
            {(f.advisories || []).slice(0, 2).map((a) => <span key={a} className="cvx-mono cvx-adv-id">{a}</span>)}
            {(f.advisories || []).length > 2 && <span className="cvx-muted">{tr("+{{value}} more", { value: f.advisories.length - 2 })}</span>}
            {f.availability === "pro" && <span className="cvx-pill cvx-pill-pro">{tr("Ubuntu Pro only")}</span>}
        </span>
    );
}

function UpdatesTable({ groups, onOpen }) {
    if (!groups.length) {
        return <div className="cvx-card cvx-empty"><b>{tr("No security update is missing on assets with a Linux distribution")}</b></div>;
    }
    return (
        <div className="cvx-card cvx-card-flush cvx-table-wrap">
            <table className="cvx-table">
                <thead><tr><th>{tr("Priority")}</th><th>{tr("Update")}</th><th>{tr("Advisory")}</th><th>{tr("CVEs it closes")}</th><th>{tr("CVSS")}</th><th>{tr("Exploit likelihood")}</th><th>{tr("Assets")}</th></tr></thead>
                <tbody>
                    {groups.map((g) => (
                        <tr key={g.key}>
                            <td><PriorityPill p={g.priority} /></td>
                            <td className="cvx-tight">
                                <b><bdi>{g.package}</bdi></b>
                                {g.fixed_in && <span className="cvx-sub">{tr("to")}{" "}<span className="cvx-mono">{g.fixed_in}</span></span>}
                                <span className="cvx-sub">{g.vendor}{g.pro && <> · <span className="cvx-pill cvx-pill-pro">{tr("Ubuntu Pro only")}</span></>}</span>
                            </td>
                            <td className="cvx-tight">
                                {g.advisories.slice(0, 3).map((a) => <span key={a} className="cvx-mono cvx-adv-id cvx-block">{a}</span>)}
                                {g.advisories.length > 3 && <span className="cvx-muted cvx-small">{tr("+{{value}} more", { value: g.advisories.length - 3 })}</span>}
                                {!g.advisories.length && <span className="cvx-muted">—</span>}
                            </td>
                            <td>
                                <div className="cvx-cve-chips">
                                    {g.cves.slice(0, 3).map((c) => (
                                        <button key={c.cve_id} type="button" className={`cvx-cve-chip ${c.kev ? "is-kev" : ""}`} onClick={() => onOpen(c)}>{c.cve_id}</button>
                                    ))}
                                    {g.cves.length > 3 && <span className="cvx-muted cvx-small">{tr("+{{value}} more", { value: g.cves.length - 3 })}</span>}
                                </div>
                            </td>
                            <td><CvssPill score={g.cvss} severity={g.severity} /></td>
                            <td><Epss value={g.epss} /></td>
                            <td>
                                <div className="cvx-asset-stack">
                                    {g.assets.slice(0, 3).map((a) => (
                                        <span key={a.id} className="cvx-asset-chip" title={a.reboot ? tr("Installed; needs a reboot") : undefined}>
                                            <AssetIcon icon={a.icon} size={20} />{a.name}{a.reboot && " ⟳"}
                                        </span>
                                    ))}
                                    {g.assets.length > 3 && <span className="cvx-muted cvx-small">{tr("+{{value}} more", { value: g.assets.length - 3 })}</span>}
                                </div>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function CveTable({ groups, onOpen }) {
    if (!groups.length) return <div className="cvx-card cvx-empty"><b>{tr("No CVEs match")}</b></div>;
    return (
        <div className="cvx-card cvx-card-flush cvx-table-wrap">
            <table className="cvx-table">
                <thead><tr><th>{tr("Priority")}</th><th>{tr("CVE")}</th><th>{tr("CVSS")}</th><th>{tr("Exploit likelihood")}</th><th>{tr("Affected assets")}</th></tr></thead>
                <tbody>
                    {groups.map((g) => (
                        <tr key={g.cve_id}>
                            <td><PriorityPill p={g.priority} /></td>
                            <td className="cvx-cve-cell"><CveId f={g} onOpen={onOpen} /></td>
                            <td><CvssPill score={g.cvss} severity={g.severity} /></td>
                            <td><Epss value={g.epss} /></td>
                            <td>
                                <div className="cvx-asset-stack">
                                    {g.assets.slice(0, 4).map((a) => (
                                        <span key={a.id} className="cvx-asset-chip"><AssetIcon icon={a.icon} size={20} />{a.name}</span>
                                    ))}
                                    {g.assets.length > 4 && <span className="cvx-muted cvx-small">{tr("+{{value}} more", { value: g.assets.length - 4 })}</span>}
                                </div>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function FirstRun({ status, onStarted }) {
    const navigate = useNavigate();
    const [file, setFile] = useState(null);
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    if (!status) return null;
    const job = status.active_job;

    const run = async (url) => {
        setBusy(true);
        setError(null);
        try {
            const { data } = await api.post(url, {});
            onStarted(data.id);
        } catch (err) {
            setError(err.response?.data?.detail || tr("Could not start"));
        } finally {
            setBusy(false);
        }
    };

    return (
        <section className="cvx-card cvx-first">
            <div className="cvx-first-head">
                <span className="cvx-tile cvx-tile-soft"><Icon name="database" size={28} stroke="#1e3a5f" width={1.8} /></span>
                <div>
                    <h2>{job ? tr("Loading the CVE database…") : tr("Load the CVE database to start")}</h2>
                    <p>{tr("NGCorion matches your assets against a local copy of every published CVE. Nothing about your assets is sent outside your network.")}</p>
                </div>
            </div>
            {job ? (
                <div className="cvx-actions">
                    <span className="cvx-spin" />
                    <span>{tr("Findings appear here as soon as it finishes.")}</span>
                    <button type="button" className="cvx-btn" onClick={() => onStarted(job.id)}>{tr("View progress")}</button>
                </div>
            ) : !status.is_admin ? (
                <div className="cvx-note">{tr("An administrator needs to load the CVE database first (CVE › Database).")}</div>
            ) : (
                <>
                    <div className="cvx-grid-options">
                        {status.bundle_available && (
                            <div className="cvx-opt is-primary">
                                <h3>{tr("Use the database shipped with this release")}</h3>
                                <p>{tr("Works without internet. Afterwards, update it online or with a package.")}</p>
                                <button type="button" className="cvx-btn cvx-btn-primary" disabled={busy} onClick={() => run("/api/cve/db/bundle/load")}>{tr("Load bundled database")}</button>
                            </div>
                        )}
                        <div className={`cvx-opt ${status.bundle_available ? "" : "is-primary"}`}>
                            <h3>{tr("Download from the internet")}</h3>
                            <p>{tr("Every CVE from NVD, plus CISA KEV and EPSS. About 20 minutes without an NVD API key, a few with one.")}</p>
                            <div className="cvx-actions">
                                <button type="button" className={`cvx-btn ${status.bundle_available ? "" : "cvx-btn-primary"}`} disabled={busy} onClick={() => run("/api/cve/db/update")}>{tr("Download now")}</button>
                                <button type="button" className="cvx-link" onClick={() => navigate("/cve/database")}>{tr("Add an API key first")}</button>
                            </div>
                        </div>
                        <div className="cvx-opt">
                            <h3>{tr("Import a package")}</h3>
                            <p>{tr("For servers without internet: a signed full package exported from another NGCorion.")}</p>
                            <label className="cvx-btn cvx-file-btn">
                                <input type="file" accept=".ngcve" className="cvx-sr" onChange={(e) => { setFile(e.target.files?.[0] || null); e.target.value = ""; }} />
                                <Icon name="upload" size={16} /> {" "}{tr("Choose package")}
                            </label>
                        </div>
                    </div>
                    <p className="cvx-muted cvx-small">{tr("Loading runs in the background. This page shows findings as soon as it finishes.")}</p>
                </>
            )}
            {error && <div className="cvx-note cvx-note-error">{error}</div>}
            {file && (
                <CvePackageImport file={file} onClose={() => setFile(null)}
                                  onStarted={(j) => { setFile(null); onStarted(j.id); }} />
            )}
        </section>
    );
}

export default CveFindings;
