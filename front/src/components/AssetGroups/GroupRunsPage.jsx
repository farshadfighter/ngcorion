/**
 * Group audits (/audit/group-runs, /audit/group-runs/:runId) and group configuration backups
 * (/backup/runs, /backup/runs/:runId, kind="backup"): every asset of a group with one technology (or
 * device type), signing in with a credential profile, a few assets at a time. Each asset gets its
 * normal audit session or device backup; the run shows which ones failed and why, and can retry them.
 * Endpoints: /api/group-runs, /api/credential-profiles (app/modules/asset_groups/router.py).
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

import api from "../../config/api.js";
import { usePermission } from "../../hooks/usePermission";
import { n, t } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { BidiText } from "../../i18n/BidiText.jsx";
import { formatDateTime } from "../../utils/dates.js";
import { ITEM_STATUS, KINDS, REASONS, RUN_STATUS, TECHS, errorText } from "./groupFormat.js";
import { FAMILY_LABELS } from "../Backup/restoreConstants.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/AssetGroups.css";

const ACTIVE = ["queued", "running", "stopping"];
const BASE = { audit: "/audit/group-runs", backup: "/backup/runs" };
const techLabel = (kind, tech) => (kind === "backup" ? FAMILY_LABELS[tech] : TECHS[tech]) || tech;

function Progress({ run }) {
    const c = run.counts || {};
    const total = run.total || 1;
    const part = (k) => `${(100 * (c[k] || 0)) / total}%`;
    return (
        <div className="ag-progress" aria-label={t("{{done}} of {{total}} finished", { done: n(run.finished), total: n(run.total) })}>
            <div className="ag-bar">
                <i className="ag-bar-done" style={{ width: part("done") }} />
                <i className="ag-bar-failed" style={{ width: part("failed") }} />
                <i className="ag-bar-skipped" style={{ width: part("skipped") }} />
                <i className="ag-bar-running" style={{ width: part("running") }} />
            </div>
            <span className="bkm-small">{t("{{done}} of {{total}}", { done: n(run.finished), total: n(run.total) })}</span>
        </div>
    );
}

export function GroupRunsPage({ kind = "audit" }) {
    const { runId } = useParams();
    return runId ? <RunDetail runId={runId} kind={kind} /> : <RunList kind={kind} />;
}

function RunList({ kind }) {
    const isBackup = kind === "backup";
    const canWrite = usePermission(isBackup ? "backup" : "auditing", "write");
    const canUseProfiles = usePermission("credential_profiles", "read");
    const [params, setParams] = useSearchParams();
    const [runs, setRuns] = useState(null);
    const [error, setError] = useState(null);
    const starting = params.get("group") !== null || params.get("new") !== null;

    const load = useCallback(() => {
        api.get("/api/group-runs", { params: { kind } }).then(({ data }) => setRuns(data))
            .catch((e) => setError(errorText(e, t("Could not load the group runs"))));
    }, [kind]);
    useEffect(load, [load]);
    const anyActive = (runs || []).some((r) => ACTIVE.includes(r.status));
    useEffect(() => {
        if (!anyActive) return undefined;
        const timer = setInterval(load, 3000);
        return () => clearInterval(timer);
    }, [anyActive, load]);

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    {isBackup ? (
                        <>
                            <span className="bkm-crumb">{t("Device Backups")} › {t("Backup runs")}</span>
                            <h1>{t("Backup runs")}</h1>
                            <p>{t("Configuration backups of whole asset groups, from a schedule or started here. An unchanged configuration is not stored again; a changed one becomes a new version that can be compared with the previous one.")}</p>
                        </>
                    ) : (
                        <>
                            <span className="bkm-crumb">{t("Security assessment")} › {t("Group audits")}</span>
                            <h1>{t("Group audits")}</h1>
                            <p>{t("Audit every asset of a group in one go, signing in with a credential profile. Each asset gets its own audit session and score; assets that could not be audited are listed with the reason and can be tried again.")}</p>
                        </>
                    )}
                </div>
                <div className="bkm-actions">
                    {isBackup ? <Link className="bkm-btn" to="/backup/schedules">{t("Backup schedules")}</Link>
                        : <Link className="bkm-btn" to="/assets/groups">{t("Asset groups")}</Link>}
                    {canWrite && canUseProfiles && (
                        <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => setParams({ new: "1" })}>
                            {isBackup ? t("Back up a group now") : t("Start a group audit")}</button>
                    )}
                </div>
            </div>
            {canWrite && !canUseProfiles && (
                <div className="bkm-note bkm-note-orange">{isBackup
                    ? t("Backing up a group needs permission to use credential profiles. Ask an administrator.")
                    : t("Starting a group audit needs permission to use credential profiles. Ask an administrator.")}</div>
            )}
            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}

            <section className="bkm-card bkm-flush">
                <div className="bkm-table-wrap">
                    <table className="bkm-table">
                        <thead>
                            <tr>
                                <th>{t("Group")}</th>
                                <th>{isBackup ? t("Device type") : t("Technology")}</th>
                                <th>{t("Credential profile")}</th>
                                <th>{t("Status")}</th>
                                <th style={{ minWidth: 200 }}>{t("Progress")}</th>
                                <th>{t("Failed")}</th>
                                <th>{t("Started")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(runs || []).map((r) => (
                                <tr key={r.id} className="bkm-row-click">
                                    <td><Link className="bkm-link" to={`${BASE[kind]}/${r.id}`} dir="auto">{r.group_name}</Link>
                                        {r.trigger === "syslog"
                                            ? <div className="bkm-sub">{t("Device reported a change")}</div>
                                            : r.scheduled_job_id && <div className="bkm-sub">{t("Scheduled")}</div>}</td>
                                    <td>{techLabel(kind, r.technology)}</td>
                                    <td dir="auto">{r.credential_profile_name || "—"}</td>
                                    <td><span className={`bkm-pill ${RUN_STATUS[r.status]?.cls}`}>{RUN_STATUS[r.status]?.label || r.status}</span></td>
                                    <td><Progress run={r} /></td>
                                    <td>{r.counts.failed ? <b className="bkm-red">{n(r.counts.failed)}</b> : <span className="bkm-muted">—</span>}</td>
                                    <td className="bkm-small">{formatDateTime(r.created_at)}<div className="bkm-muted">{r.started_by_name || ""}</div></td>
                                </tr>
                            ))}
                            {runs && runs.length === 0 && (
                                <tr><td colSpan={7}><div className="bkm-empty">
                                    <b>{isBackup ? t("No backup runs yet") : t("No group audits yet")}</b>
                                    <span>{isBackup ? t("Schedule a nightly backup of an asset group, or back one up now.")
                                        : t("Make an asset group, ask an administrator for a credential profile, then start a group audit here.")}</span>
                                </div></td></tr>
                            )}
                            {!runs && !error && <tr><td colSpan={7} className="bkm-muted">{t("Loading…")}</td></tr>}
                        </tbody>
                    </table>
                </div>
            </section>
            {starting && <StartModal kind={kind} groupId={params.get("group")} onClose={() => setParams({})} />}
        </div>
    );
}

function StartModal({ kind, groupId, onClose }) {
    const isBackup = kind === "backup";
    const navigate = useNavigate();
    const [groups, setGroups] = useState([]);
    const [profiles, setProfiles] = useState([]);
    const [kinds, setKinds] = useState({});
    const [form, setForm] = useState({ group_id: groupId || "", technology: isBackup ? "cisco" : "linux", credential_profile_id: "",
                                       audit_profile: "L1", concurrency: 10 });
    const [error, setError] = useState(null);
    const [busy, setBusy] = useState(false);
    const set = (patch) => setForm((f) => ({ ...f, ...patch }));

    useEffect(() => {
        api.get("/api/asset-groups").then(({ data }) => setGroups(data)).catch(() => setGroups([]));
        api.get("/api/credential-profiles").then(({ data }) => setProfiles(data)).catch((e) => setError(errorText(e, t("Could not load the credential profiles"))));
        api.get("/api/credential-profiles/technologies").then(({ data }) => setKinds(data)).catch(() => setKinds({}));
    }, []);

    const needKind = isBackup ? "ssh" : kinds[form.technology];
    const fitting = useMemo(() => profiles.filter((p) => p.kind === needKind), [profiles, needKind]);
    // the chosen profile, or the first that fits the technology
    const profileId = fitting.some((p) => String(p.id) === String(form.credential_profile_id))
        ? form.credential_profile_id : (fitting[0]?.id ?? "");
    const group = groups.find((g) => String(g.id) === String(form.group_id));
    const profile = fitting.find((p) => String(p.id) === String(profileId));

    const start = () => {
        setBusy(true);
        setError(null);
        api.post("/api/group-runs", { ...form, kind, audit_profile: isBackup ? null : form.audit_profile,
                                      group_id: Number(form.group_id), credential_profile_id: Number(profileId),
                                      concurrency: Number(form.concurrency) })
            .then(({ data }) => navigate(`${BASE[kind]}/${data.id}`))
            .catch((e) => setError(errorText(e, isBackup ? t("Could not start the backup") : t("Could not start the group audit"))))
            .finally(() => setBusy(false));
    };

    return (
        <div className="alr-modal-wrap" role="dialog" aria-modal="true" aria-labelledby="ag-start-title">
            <button type="button" className="bkm-scrim" aria-label={t("Close")} onClick={onClose} />
            <div className="alr-modal ag-modal">
                <h2 id="ag-start-title">{isBackup ? t("Back up a group now") : t("Start a group audit")}</h2>
                <label className="alr-lbl">{t("Asset group")}
                    <select className="bkm-select" value={form.group_id} onChange={(e) => set({ group_id: e.target.value })}>
                        <option value="">{t("Choose…")}</option>
                        {groups.map((g) => <option key={g.id} value={g.id}>{g.name} ({n(g.asset_count)})</option>)}
                    </select>
                </label>
                {isBackup ? (
                    <label className="alr-lbl">{t("Device type")}
                        <select className="bkm-select" value={form.technology} onChange={(e) => set({ technology: e.target.value })}>
                            {Object.entries(FAMILY_LABELS).map(([k, label]) => <option key={k} value={k}>{label}</option>)}
                        </select>
                    </label>
                ) : (
                <div className="alr-grid-2">
                    <label className="alr-lbl">{t("Technology")}
                        <select className="bkm-select" value={form.technology} onChange={(e) => set({ technology: e.target.value })}>
                            {Object.keys(kinds).map((k) => <option key={k} value={k}>{TECHS[k] || k}</option>)}
                        </select>
                    </label>
                    <label className="alr-lbl">{t("Benchmark profile")}
                        <select className="bkm-select" value={form.audit_profile} onChange={(e) => set({ audit_profile: e.target.value })}>
                            <option value="L1">{t("Level 1")}</option>
                            <option value="FULL">{t("Full (Level 1 and 2)")}</option>
                        </select>
                    </label>
                </div>
                )}
                <label className="alr-lbl">{t("Credential profile")}
                    <select className="bkm-select" value={profileId} onChange={(e) => set({ credential_profile_id: e.target.value })}>
                        {fitting.length === 0 && <option value="">{t("No {{kind}} profile — ask an administrator", { kind: KINDS[needKind] || "" })}</option>}
                        {fitting.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.username}</option>)}
                    </select>
                </label>
                {profile?.rotation_due && <p className="bkm-note bkm-note-orange">{t("This profile's password is older than its change period.")}</p>}
                <label className="alr-lbl">{t("Assets audited at the same time")}
                    <input className="bkm-select" type="number" min={1} max={50} value={form.concurrency}
                           onChange={(e) => set({ concurrency: e.target.value })} />
                </label>
                {group && isBackup && (
                    <p className="alr-hint">{t("The configuration of {{value}} devices will be backed up. Devices without an IP address are skipped.", { value: n(group.asset_count) })}</p>
                )}
                {group && !isBackup && (
                    <p className="alr-hint">{t("{{value}} assets will be audited with {{technology}}. Assets the license does not cover, or without an IP address, are skipped.", { value: n(group.asset_count), technology: TECHS[form.technology] || form.technology })}</p>
                )}
                {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
                <div className="alr-modal-foot">
                    <button type="button" className="bkm-btn" onClick={onClose}>{t("Cancel")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" onClick={start}
                            disabled={busy || !form.group_id || !profileId}>{busy ? t("Starting…") : t("Start")}</button>
                </div>
            </div>
        </div>
    );
}

const FILTERS = [["all", t("All")], ["failed", t("Failed")], ["done", t("Done")], ["skipped", t("Skipped")], ["running", t("Running")], ["queued", t("Waiting")]];

function RunDetail({ runId, kind }) {
    const isBackup = kind === "backup";
    const canWrite = usePermission(isBackup ? "backup" : "auditing", "write");
    const [run, setRun] = useState(null);
    const [error, setError] = useState(null);
    const [filter, setFilter] = useState("all");
    const [busy, setBusy] = useState(false);

    const load = useCallback(() => {
        api.get(`/api/group-runs/${runId}`).then(({ data }) => setRun(data))
            .catch((e) => setError(errorText(e, t("Could not load the group run"))));
    }, [runId]);
    useEffect(load, [load]);
    const active = run && ACTIVE.includes(run.status);
    useEffect(() => {
        if (!active) return undefined;
        const timer = setInterval(load, 2500);
        return () => clearInterval(timer);
    }, [active, load]);

    const act = (what) => {
        setBusy(true);
        setError(null);
        api.post(`/api/group-runs/${runId}/${what}`).then(load)
            .catch((e) => setError(errorText(e, t("Something went wrong. Please try again."))))
            .finally(() => setBusy(false));
    };

    if (!run) return <div className="bkm-page">{error ? <div className="bkm-note bkm-note-error">{error}</div> : <p className="bkm-muted">{t("Loading…")}</p>}</div>;
    const c = run.counts;
    const items = run.items.filter((i) => filter === "all" || i.status === filter);
    const reasons = run.items.filter((i) => i.status === "failed")
        .reduce((acc, i) => ({ ...acc, [i.reason || "error"]: (acc[i.reason || "error"] || 0) + 1 }), {});
    const scores = run.items.filter((i) => i.compliance !== null && i.compliance !== undefined).map((i) => i.compliance);
    const avg = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null;
    const changedCount = run.items.filter((i) => i.outcome === "changed").length;
    const sameCount = run.items.filter((i) => i.outcome === "unchanged").length;

    return (
        <div className="bkm-page">
            <div className="bkm-head">
                <div>
                    <span className="bkm-crumb"><Link to={BASE[kind]}>{isBackup ? t("Backup runs") : t("Group audits")}</Link> › #{n(run.id)}</span>
                    <h1 dir="auto">{run.group_name} · {techLabel(kind, run.technology)}</h1>
                    <p>{t("Credential profile {{profile}} · {{concurrency}} at a time · started {{date}} by {{who}}", {
                        profile: run.credential_profile_name || "—", concurrency: n(run.concurrency),
                        date: formatDateTime(run.started_at || run.created_at), who: run.started_by_name || t("the scheduler") })}</p>
                </div>
                <div className="bkm-actions">
                    <span className={`bkm-pill ${RUN_STATUS[run.status]?.cls}`}>{RUN_STATUS[run.status]?.label}</span>
                    {canWrite && ["queued", "running"].includes(run.status) && (
                        <button type="button" className="bkm-btn" disabled={busy} onClick={() => act("stop")}>{t("Stop")}</button>
                    )}
                    {canWrite && !active && c.failed > 0 && (
                        <button type="button" className="bkm-btn bkm-btn-primary" disabled={busy} onClick={() => act("retry")}>
                            {t("Retry {{value}} failed", { value: n(c.failed) })}</button>
                    )}
                </div>
            </div>
            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}

            <div className="bkm-stats bkm-stats-4">
                <div className="bkm-stat"><b>{n(run.finished)} / {n(run.total)}</b><span>{t("Finished")}</span><Progress run={run} /></div>
                {isBackup ? (
                    <div className="bkm-stat"><b className="bkm-green">{n(c.done || 0)}</b>
                        <span>{t("Backed up · {{changed}} changed, {{same}} unchanged", { changed: n(changedCount), same: n(sameCount) })}</span></div>
                ) : (
                    <div className="bkm-stat"><b className="bkm-green">{n(c.done || 0)}</b><span>{t("Audited")}{avg !== null ? ` · ${t("average score {{value}}%", { value: n(avg) })}` : ""}</span></div>
                )}
                <div className={`bkm-stat ${c.failed ? "bkm-stat-warn" : ""}`}><b className={c.failed ? "bkm-red" : ""}>{n(c.failed || 0)}</b>
                    <span>{Object.keys(reasons).length ? Object.entries(reasons).map(([k, v]) => `${REASONS[k] || k}: ${n(v)}`).join(" · ") : t("Failed")}</span></div>
                <div className="bkm-stat"><b>{n(c.skipped || 0)}</b><span>{t("Skipped (license or no address)")}</span></div>
            </div>

            <div className="bkm-toolbar">
                <div className="bkm-chips" role="group" aria-label={t("Filter assets")}>
                    {FILTERS.map(([k, label]) => (
                        <button key={k} type="button" aria-pressed={filter === k} className={`bkm-chip ${filter === k ? "is-on" : ""}`}
                                onClick={() => setFilter(k)}>{label}<b>{n(k === "all" ? run.total : (c[k] || 0))}</b></button>
                    ))}
                </div>
            </div>

            <section className="bkm-card bkm-flush">
                <div className="bkm-table-wrap">
                    <table className="bkm-table">
                        <thead>
                            <tr>
                                <th>{t("Asset")}</th>
                                <th>{t("Status")}</th>
                                <th>{isBackup ? t("Result") : t("Compliance")}</th>
                                <th>{t("Reason")}</th>
                                <th>{t("Finished")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {items.map((i) => (
                                <tr key={i.id}>
                                    <td><span className="bkm-strong" dir="auto">{i.asset_name}</span>
                                        <div className="bkm-mono bkm-small" dir="ltr">{i.ip_address || "—"}</div></td>
                                    <td><span className={`bkm-pill ${ITEM_STATUS[i.status]?.cls}`}>{ITEM_STATUS[i.status]?.label}</span>
                                        {i.attempts > 1 && <div className="bkm-small bkm-muted">{t("attempt {{value}}", { value: n(i.attempts) })}</div>}</td>
                                    <td>{isBackup ? <BackupOutcome item={i} /> : i.compliance !== null && i.compliance !== undefined
                                        ? <Link className="bkm-link" to={`/audit/sessions/${i.session_id}`}>{n(Math.round(i.compliance))}%</Link>
                                        : i.session_id ? <Link className="bkm-link" to={`/audit/sessions/${i.session_id}`}>{t("Open session")}</Link> : "—"}</td>
                                    <td>{i.reason ? <><b>{REASONS[i.reason] || i.reason}</b>
                                        {i.detail && <div className="bkm-small bkm-muted ag-detail" dir="auto"><BidiText text={tb(i.detail)} /></div>}</> : <span className="bkm-muted">—</span>}</td>
                                    <td className="bkm-small">{i.finished_at ? formatDateTime(i.finished_at) : "—"}</td>
                                </tr>
                            ))}
                            {items.length === 0 && <tr><td colSpan={5} className="bkm-muted">{t("Nothing here")}</td></tr>}
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    );
}

/** What a backup run found on one device. */
function BackupOutcome({ item }) {
    if (!item.backup_id) return "—";
    const open = `/backup?asset=${item.asset_id}`;
    if (item.outcome === "unchanged") return <Link className="bkm-link" to={open}>{t("Unchanged")}</Link>;
    if (item.outcome === "first") return <Link className="bkm-link" to={open}>{t("First backup")}</Link>;
    return (
        <Link className="bkm-link" to={`${open}&compare=${item.backup_id}`}>
            <span className="ag-diff-count"><b className="ag-plus">+{n(item.added_lines ?? 0)}</b> <b className="ag-minus">−{n(item.removed_lines ?? 0)}</b></span>
            {" "}{item.change_origin === "ngcorion" ? t("by NGCorion") : t("outside NGCorion")}
        </Link>
    );
}

export default GroupRunsPage;
