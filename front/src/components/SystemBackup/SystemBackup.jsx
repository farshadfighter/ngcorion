import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import api from "../../config/api.js";
import { t, n } from "../../i18n";
import { tb } from "../../i18n/backendText";
import { duration, formatDate, formatDateTime, formatWhen } from "../../utils/dates.js";
import { BackupNowModal } from "./BackupNowModal.jsx";
import { DestinationModal } from "./DestinationModal.jsx";
import { PassphraseModal } from "./PassphraseModal.jsx";
import { RestoreWizard } from "./RestoreWizard.jsx";
import { BackupDrawer } from "./BackupDrawer.jsx";
import { DestChips, Health } from "./parts.jsx";
import {
    DEST_TYPE, KIND, PARTS, RESTORE_STEPS, TIER, WEEKDAYS, bytes, contentsText,
    destinationLabel, downloadBackup, errorText, weekday,
} from "./format.js";
import "../../assets/BackupModule.css";
import "../../assets/Alerts.css";
import "../../assets/Reports.css";
import "../../assets/SystemBackup.css";

const TABS = [
    ["backups", t("Backups")],
    ["schedule", t("Schedule and retention")],
    ["destinations", t("Destinations")],
    ["history", t("Restores and tests")],
];

/** Backups of NGCorion itself: its database and the files it keeps on disk. */
export function SystemBackup() {
    const [params, setParams] = useSearchParams();
    const tab = TABS.some(([k]) => k === params.get("tab")) ? params.get("tab") : "backups";
    const [overview, setOverview] = useState(null);
    const [backups, setBackups] = useState(null);
    const [dests, setDests] = useState([]);
    const [error, setError] = useState(null);
    const [reload, setReload] = useState(0);
    const [modal, setModal] = useState(null);          // {type, ...}
    const refresh = useCallback(() => setReload((x) => x + 1), []);

    useEffect(() => {
        let alive = true;
        Promise.all([
            api.get("/api/system-backup/overview"),
            api.get("/api/system-backup/backups"),
            api.get("/api/system-backup/destinations"),
        ]).then(([o, b, d]) => {
            if (!alive) return;
            setOverview(o.data);
            setBackups(b.data.items);
            setDests(d.data.items);
            setError(null);
        }).catch((e) => alive && setError(errorText(e, t("Could not load the backups"))));
        return () => { alive = false; };
    }, [reload]);

    const busy = (backups || []).some((b) => b.status === "queued" || b.status === "running" || b.step) || overview?.running;
    useEffect(() => {
        if (!busy) return undefined;
        const timer = setInterval(refresh, 3000);
        return () => clearInterval(timer);
    }, [busy, refresh]);

    const setTab = (k) => setParams(k === "backups" ? {} : { tab: k }, { replace: true });
    const close = (changed) => { setModal(null); if (changed) refresh(); };
    const needsPassphrase = overview && !overview.settings.passphrase_set;

    return (
        <div className="bkm-page">
            <div className="bkm-head rep-head">
                <div>
                    <div className="bkm-crumb">{t("System")} › {t("NGCorion backup")}</div>
                    <h1>{t("NGCorion backup")}</h1>
                    <p>{t("A complete, encrypted backup of this system's data and settings. Configuration backups of network devices are under “Backup & Restore”.")}</p>
                </div>
                <div className="bkm-row-gap">
                    <button type="button" className="bkm-btn" onClick={() => setModal({ type: "restore" })}>{t("Restore from a file…")}</button>
                    <button type="button" className="bkm-btn bkm-btn-primary" disabled={!overview || needsPassphrase}
                            onClick={() => setModal({ type: "now" })}>{t("Back up now")}</button>
                </div>
            </div>

            {error && <div className="bkm-note bkm-note-error" role="alert">{error}</div>}
            {overview && <Banner o={overview} onSetup={() => setModal({ type: "passphrase" })} />}
            {overview && <Kpis o={overview} dests={dests} />}

            <div className="sbk-tabs" role="tablist" aria-label={t("NGCorion backup")}>
                {TABS.map(([k, label]) => (
                    <button key={k} type="button" role="tab" aria-selected={tab === k} onClick={() => setTab(k)}>
                        {label}
                        {k === "destinations" && overview?.destinations.failing > 0 &&
                            <span className="sbk-count">{n(overview.destinations.failing)}</span>}
                    </button>
                ))}
            </div>

            {tab === "backups" && (
                <BackupsTab backups={backups} dests={dests}
                            onOpen={(b) => setModal({ type: "drawer", backup: b })}
                            onRestore={(b) => setModal({ type: "restore", backup: b })}
                            onError={setError} onChanged={refresh} />
            )}
            {tab === "schedule" && overview && (
                <ScheduleTab o={overview} onPassphrase={(mode) => setModal({ type: "passphrase", mode })} onSaved={refresh} />
            )}
            {tab === "destinations" && overview && (
                <DestinationsTab o={overview} dests={dests} onEdit={(d) => setModal({ type: "dest", dest: d })}
                                 onChanged={refresh} />
            )}
            {tab === "history" && <HistoryTab reload={reload} />}

            {modal?.type === "now" && <BackupNowModal overview={overview} dests={dests} onClose={close} />}
            {modal?.type === "restore" && <RestoreWizard backup={modal.backup} backups={backups || []} onClose={close} />}
            {modal?.type === "passphrase" && (
                <PassphraseModal mode={modal.mode || (overview?.settings.passphrase_set ? "change" : "set")} onClose={close} />
            )}
            {modal?.type === "dest" && <DestinationModal dest={modal.dest} onClose={close} />}
            {modal?.type === "drawer" && (
                <BackupDrawer backup={(backups || []).find((b) => b.id === modal.backup.id) || modal.backup} dests={dests}
                              onClose={close} onChanged={refresh}
                              onRestore={(b) => setModal({ type: "restore", backup: b })} />
            )}
        </div>
    );
}

function Banner({ o, onSetup }) {
    const s = o.settings;
    const last = o.last_success;
    const next = s.enabled && s.next_run_at ? formatWhen(s.next_run_at) : null;
    let title, sub, mark = "✓";
    if (o.health === "setup") {
        mark = "!";
        title = t("Set a backup passphrase to start");
        sub = t("Every backup is encrypted with this passphrase. Without it no backup can be opened, so keep it somewhere outside this server.");
    } else if (o.health === "failed") {
        mark = "✕";
        title = t("The last backup failed");
        sub = o.last_attempt?.error ? tb(o.last_attempt.error) : "";
    } else if (o.health === "stale") {
        mark = "!";
        title = last ? t("No successful backup in the last 2 days") : t("No backup yet");
        sub = last ? t("Last successful backup: {{when}}", { when: formatWhen(last.at) }) : t("The first backup runs at the scheduled time, or make one now.");
    } else {
        title = t("Last successful backup: {{when}}", { when: formatWhen(last.at) });
        const parts = [KIND[last.kind]?.label, bytes(last.size_bytes)];
        if (o.health === "warning") {
            parts.push(o.destinations.failing ? t("a destination is unreachable") : t("the last restore test failed"));
        }
        sub = parts.filter(Boolean).join(" · ");
    }
    return (
        <div className={`sbk-banner is-${o.health}`} role="status">
            <span className="sbk-mark" aria-hidden="true">{mark}</span>
            <div>
                <b>{title}</b>
                {sub && <small>{sub}</small>}
            </div>
            {o.health === "setup" ? (
                <button type="button" className="bkm-btn bkm-btn-primary" onClick={onSetup}>{t("Set the passphrase…")}</button>
            ) : (
                <div className="sbk-next">
                    <div>{t("Next backup")}</div>
                    <b>{next || t("Automatic backups are off")}</b>
                </div>
            )}
        </div>
    );
}

function Kpis({ o, dests }) {
    const s = o.settings;
    const enabled = dests.filter((d) => d.enabled);
    const reachable = enabled.filter((d) => d.last_status !== "failed").length;
    const disk = o.disk || {};
    const usedPct = disk.total ? Math.min(100, Math.round((o.total_bytes / disk.total) * 100)) : 0;
    const lowDisk = disk.total && disk.free / disk.total < 0.1;
    return (
        <div className="bkm-stats bkm-stats-4">
            <div className="bkm-stat">
                <b className="bkm-navy">{n(o.count)}</b>
                <span>{t("Backups kept")}</span>
                <small>{t("{{d}} daily, {{w}} weekly, {{m}} monthly", { d: n(s.keep_daily), w: n(s.keep_weekly), m: n(s.keep_monthly) })}</small>
            </div>
            <div className={`bkm-stat ${lowDisk ? "bkm-stat-warn" : ""}`}>
                <b>{bytes(o.total_bytes)}</b>
                <span>{t("Used on this server")}</span>
                <div className="bkm-meter" aria-hidden="true"><span style={{ width: `${Math.max(usedPct, 2)}%` }} /></div>
                <small className={lowDisk ? "bkm-orange" : ""}>
                    {disk.total ? t("{{free}} free of {{total}}", { free: bytes(disk.free), total: bytes(disk.total) }) : "—"}
                </small>
            </div>
            <div className={`bkm-stat ${enabled.length && reachable < enabled.length ? "bkm-stat-warn" : ""}`}>
                <b className={enabled.length && reachable < enabled.length ? "bkm-orange" : ""}>
                    {enabled.length ? t("{{a}} of {{b}}", { a: n(reachable), b: n(enabled.length) }) : n(0)}
                </b>
                <span>{t("Destinations reachable")}</span>
                <small>{enabled.length ? [...new Set(enabled.map((d) => DEST_TYPE[d.type]))].join(t(", ")) : t("Only on this server")}</small>
            </div>
            <div className={`bkm-stat ${o.last_test?.status === "failed" ? "bkm-stat-warn" : ""}`}>
                <b className={o.last_test?.status === "failed" ? "bkm-red" : ""}>{o.last_test ? formatDate(o.last_test.at) : "—"}</b>
                <span>{t("Last restore test")}</span>
                <small>{o.last_test ? (o.last_test.status === "succeeded" ? t("Passed") : o.last_test.status === "failed" ? t("Failed") : t("Running")) : (s.restore_test ? t("Runs weekly") : t("Off"))}</small>
            </div>
        </div>
    );
}

// ── backups ───────────────────────────────────────────────────────────────

/** How long writing took; nothing for a backup made in under a second. */
const took = (b) => {
    const a = Date.parse(b.started_at), z = Date.parse(b.finished_at);
    return a && z && z - a >= 1000 ? duration(b.started_at, b.finished_at) : null;
};

function BackupsTab({ backups, dests, onOpen, onRestore, onError, onChanged }) {
    const [busy, setBusy] = useState(null);
    const get = (b) => {
        setBusy(b.id);
        downloadBackup(b).catch(() => onError(t("Could not download the file"))).finally(() => setBusy(null));
    };
    const resend = (b) => {
        setBusy(b.id);
        api.post(`/api/system-backup/backups/${b.id}/resend`, {})
            .then(onChanged).catch((e) => onError(errorText(e, t("Could not send the backup")))).finally(() => setBusy(null));
    };
    if (!backups) return <div className="bkm-card bkm-empty">{t("Loading…")}</div>;
    return (
        <>
            <section className="bkm-card bkm-flush">
                {backups.length === 0 ? (
                    <div className="bkm-empty">{t("No backups yet.")}</div>
                ) : (
                    <div className="bkm-table-wrap">
                        <table className="bkm-table sbk-table">
                            <thead>
                                <tr>
                                    <th style={{ width: 140 }}>{t("Time")}</th>
                                    <th style={{ width: 120 }}>{t("Type")}</th>
                                    <th>{t("Contents")}</th>
                                    <th style={{ width: 80 }}>{t("Size")}</th>
                                    <th style={{ width: 190 }}>{t("Destinations")}</th>
                                    <th style={{ width: 140 }}>{t("Health")}</th>
                                    <th style={{ width: 150 }}><span className="sr-only">{t("Actions")}</span></th>
                                </tr>
                            </thead>
                            <tbody>
                                {backups.map((b) => (
                                    <tr key={b.id} className="bkm-row-click" onClick={() => onOpen(b)}>
                                        <td className="sbk-when">
                                            <b>{formatWhen(b.created_at)}</b>
                                            <span className="bkm-sub">
                                                {b.kind === "safety" ? t("Made before a restore")
                                                    : b.note ? <span className="bidi-auto">{tb(b.note)}</span>
                                                    : [took(b), b.app_version && t("version {{v}}", { v: b.app_version })].filter(Boolean).join(" · ")}
                                            </span>
                                            {b.created_by && <span className="bkm-sub">{b.created_by}</span>}
                                        </td>
                                        <td>
                                            <span className={`bkm-pill ${KIND[b.kind]?.pill}`}>{KIND[b.kind]?.label || b.kind}</span>
                                            {b.tier && <span className="bkm-sub">{TIER[b.tier]}</span>}
                                            {b.retention?.[0] === "expiring" && <span className="bkm-sub">{t("Removed by retention next time")}</span>}
                                        </td>
                                        <td>{b.status === "failed" ? "—" : contentsText(b.contents)}</td>
                                        <td className="bkm-nowrap">{b.size_bytes ? bytes(b.size_bytes) : "—"}</td>
                                        <td><DestChips b={b} dests={dests} /></td>
                                        <td><Health b={b} /></td>
                                        <td onClick={(e) => e.stopPropagation()}>
                                            {b.status === "ready" && (
                                                <div className="sbk-actions">
                                                    <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy === b.id} onClick={() => get(b)}>{t("Download")}</button>
                                                    {(b.destinations || []).some((d) => d.status === "failed") && (
                                                        <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy === b.id} onClick={() => resend(b)}>{t("Send again")}</button>
                                                    )}
                                                    <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => onRestore(b)}>{t("Restore…")}</button>
                                                </div>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>
            <p className="sbk-legend">
                {t("“Healthy” means the file opened, the hash of every part matched the list inside the file and its database version can be restored here. The weekly restore test fully restores the latest backup into a temporary database and then removes it.")}
            </p>
        </>
    );
}

// ── schedule and retention ────────────────────────────────────────────────

const INCLUDE = [["always", t("Every backup")], ["weekly", t("Weekly")], ["never", t("Never")]];

function Seg({ value, options, onChange, label }) {
    return (
        <div className="rep-seg" role="group" aria-label={label}>
            {options.map(([v, l]) => (
                <button key={v} type="button" aria-pressed={value === v} onClick={() => onChange(v)}>{l}</button>
            ))}
        </div>
    );
}

function Switch({ on, onChange, label }) {
    return (
        <button type="button" role="switch" aria-checked={on} aria-label={label} className={`alr-switch ${on ? "is-on" : ""}`}
                onClick={() => onChange(!on)}><i /></button>
    );
}

function ScheduleTab({ o, onPassphrase, onSaved }) {
    const [form, setForm] = useState(() => ({ ...o.settings }));
    const [state, setState] = useState(null);
    const set = (k) => (v) => setForm((f) => ({ ...f, [k]: v }));
    const dirty = useMemo(() => Object.keys(form).some((k) => form[k] !== o.settings[k]), [form, o.settings]);
    const save = () => {
        setState({ busy: true });
        const body = {};
        ["enabled", "frequency", "time", "include_reports", "include_cve", "include_noc", "weekly_day",
            "keep_daily", "keep_weekly", "keep_monthly", "restore_test"].forEach((k) => { body[k] = form[k]; });
        api.put("/api/system-backup/settings", body)
            .then(() => { setState({ ok: true }); onSaved(); })
            .catch((e) => setState({ error: errorText(e, t("Could not save the settings")) }));
    };
    const day = weekday(form.weekly_day);
    const s = o.settings;
    return (
        <div className="sbk-settings">
            <section className="bkm-card bkm-pad">
                <h2>{t("Schedule and retention")}</h2>
                <div className={`sbk-toggle ${form.enabled ? "is-on" : ""}`}>
                    <Switch on={form.enabled} onChange={set("enabled")} label={t("Automatic backup")} />
                    <div>
                        <b>{t("Automatic backup")}</b>
                        <small>{t("Made in the background while the system keeps working.")}</small>
                    </div>
                </div>
                <div className="sbk-row">
                    <label className="sbk-field">
                        <span>{t("Repeat")}</span>
                        <Seg value={form.frequency} onChange={set("frequency")} label={t("Repeat")}
                             options={[["daily", t("Daily")], ["weekly", t("Weekly")]]} />
                    </label>
                    <label className="sbk-field">
                        <span>{t("Time")}</span>
                        <input type="time" className="sbk-input" value={form.time} onChange={(e) => set("time")(e.target.value)} dir="ltr" />
                    </label>
                </div>
                <label className="sbk-field">
                    <span>{t("Weekly day")}</span>
                    <select className="bkm-select" value={form.weekly_day} onChange={(e) => set("weekly_day")(Number(e.target.value))}>
                        {WEEKDAYS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                    </select>
                    <small className="alr-hint">{t("Weekly backups, weekly parts and the restore test run on this day.")}</small>
                </label>

                <div className={`sbk-toggle ${form.include_reports ? "is-on" : ""}`}>
                    <Switch on={form.include_reports} onChange={set("include_reports")} label={PARTS.reports.label} />
                    <div><b>{PARTS.reports.label}</b><small>{PARTS.reports.hint}</small></div>
                </div>
                {[["include_cve", "cve"], ["include_noc", "noc_history"]].map(([key, part]) => (
                    <div key={key} className={`sbk-toggle ${form[key] !== "never" ? "is-on" : ""}`}>
                        <div>
                            <b>{PARTS[part].label}</b>
                            <small>{form[key] === "weekly" ? t("Only in the {{day}} backup", { day }) : PARTS[part].hint}</small>
                            <Seg value={form[key]} onChange={set(key)} options={INCLUDE} label={PARTS[part].label} />
                        </div>
                    </div>
                ))}

                <div className="sbk-field">
                    <span>{t("How many to keep")}</span>
                    <div className="sbk-keep">
                        {[["keep_daily", t("Daily")], ["keep_weekly", t("Weekly")], ["keep_monthly", t("Monthly")]].map(([k, l]) => (
                            <label key={k}>
                                <input type="number" min={k === "keep_daily" ? 1 : 0} max={60} value={form[k]}
                                       onChange={(e) => set(k)(Number(e.target.value))} />
                                {l}
                            </label>
                        ))}
                    </div>
                    <small className="alr-hint">{t("Older scheduled backups are deleted from the server and the destinations. Manual and safety backups stay until deleted by hand.")}</small>
                </div>

                <div className={`sbk-toggle ${form.restore_test ? "is-on" : ""}`}>
                    <Switch on={form.restore_test} onChange={set("restore_test")} label={t("Weekly restore test")} />
                    <div>
                        <b>{t("Weekly restore test")}</b>
                        <small>{t("Every {{day}} the latest backup is fully restored into a temporary database and then removed.", { day })}</small>
                    </div>
                </div>

                {state?.error && <div className="bkm-note bkm-note-error" role="alert">{state.error}</div>}
                {state?.ok && !dirty && <div className="bkm-note bkm-note-ok" role="status">{t("Settings saved.")}</div>}
                <div className="bkm-row-gap">
                    <button type="button" className="bkm-btn bkm-btn-primary" disabled={!dirty || state?.busy} onClick={save}>{t("Save")}</button>
                    {dirty && <button type="button" className="bkm-btn" onClick={() => { setForm({ ...o.settings }); setState(null); }}>{t("Discard changes")}</button>}
                </div>
            </section>

            <div className="rep-stack">
                <section className="bkm-card bkm-pad">
                    <h2>{t("Backup passphrase")}</h2>
                    {s.passphrase_set ? (
                        <div className="bkm-note bkm-note-ok">
                            {s.passphrase_set_by
                                ? t("Passphrase set · {{when}} by {{who}}", { when: formatDateTime(s.passphrase_set_at), who: s.passphrase_set_by })
                                : t("Passphrase set · {{when}}", { when: formatDateTime(s.passphrase_set_at) })}
                        </div>
                    ) : (
                        <div className="bkm-note bkm-note-orange">{t("No passphrase yet: no backup can be made until one is set.")}</div>
                    )}
                    <p className="alr-hint">{t("Every backup is encrypted with this passphrase. Without it no backup can be opened, not even by NGCorion support. Keep it somewhere outside this server.")}</p>
                    <div className="bkm-row-gap">
                        <button type="button" className="bkm-btn" onClick={() => onPassphrase(s.passphrase_set ? "change" : "set")}>
                            {s.passphrase_set ? t("Change passphrase…") : t("Set the passphrase…")}
                        </button>
                        {s.passphrase_set && <button type="button" className="bkm-btn" onClick={() => onPassphrase("check")}>{t("Test the passphrase…")}</button>}
                    </div>
                </section>
                <section className="bkm-card bkm-pad">
                    <h2>{t("What a backup holds")}</h2>
                    <div className="bkm-kv"><span>{t("Format")}</span><b dir="ltr">.ngbak · AES-256-GCM · scrypt</b></div>
                    <div className="bkm-kv"><span>{t("Program version")}</span><b dir="ltr">{o.app_version}</b></div>
                    <div className="bkm-kv"><span>{t("Database version")}</span><b className="bkm-mono" dir="ltr">{o.db_revision}</b></div>
                    <p className="alr-hint">{t("Not in a backup: device SSH passwords (never stored), the license files (bound to this server; activate again on a new server) and the program itself (install the same version).")}</p>
                    <p className="alr-hint">{t("Without the web interface, a backup file can also be restored from the command line:")}</p>
                    <code className="bkm-mono" dir="ltr" style={{ fontSize: 12, overflowWrap: "anywhere" }}>docker compose exec backend uv run python -m app.modules.sysbackup.cli restore FILE</code>
                </section>
            </div>
        </div>
    );
}

// ── destinations ──────────────────────────────────────────────────────────

function DestinationsTab({ o, dests, onEdit, onChanged }) {
    const [busy, setBusy] = useState(null);
    const [result, setResult] = useState({});
    const run = (d, fn) => {
        setBusy(d.id);
        fn().then((r) => { if (r?.data && "ok" in r.data) setResult((x) => ({ ...x, [d.id]: r.data })); onChanged(); })
            .catch((e) => setResult((x) => ({ ...x, [d.id]: { ok: false, error: errorText(e, t("The request failed")) } })))
            .finally(() => setBusy(null));
    };
    const toggle = (d) => run(d, () => api.put(`/api/system-backup/destinations/${d.id}`, { ...d, secret: null, enabled: !d.enabled }));
    const remove = (d) => {
        if (!window.confirm(t("Remove the destination “{{name}}”? Copies already sent stay on it.", { name: d.name }))) return;
        run(d, () => api.delete(`/api/system-backup/destinations/${d.id}`));
    };
    const disk = o.disk || {};
    return (
        <div className="sbk-settings">
            <section className="bkm-card bkm-pad">
                <h2>{t("Destinations")}</h2>
                <p className="alr-hint">{t("Every backup is made on this server first and then sent to the enabled destinations. Keeping a copy outside this server is essential: if its disk is lost, the backups on it are lost too.")}</p>
                <div className="sbk-destcard">
                    <div className="sbk-destcard-head">
                        <b>{t("On this server")}</b>
                        {disk.free != null && <span className="bkm-pill bkm-pill-ok">{t("{{size}} free", { size: bytes(disk.free) })}</span>}
                    </div>
                    <span className="bkm-mono" dir="ltr">{o.backup_dir}</span>
                    <small>{t("Always on · a Docker volume separate from the program's data")}</small>
                </div>
                {dests.map((d) => {
                    const r = result[d.id];
                    const failed = d.last_status === "failed";
                    return (
                        <div key={d.id} className={`sbk-destcard ${d.enabled ? "" : "is-off"}`}>
                            <div className="sbk-destcard-head">
                                <b><span dir="ltr">{DEST_TYPE[d.type]}</span> · <span className="bidi-auto">{d.name}</span></b>
                                {!d.enabled ? <span className="bkm-pill bkm-pill-muted">{t("Disabled")}</span>
                                    : failed ? <span className="bkm-pill bkm-pill-bad">{t("Unreachable")}</span>
                                        : d.last_status === "ok" ? <span className="bkm-pill bkm-pill-ok">{t("Reachable")}</span>
                                            : <span className="bkm-pill bkm-pill-muted">{t("Not tested")}</span>}
                            </div>
                            <span className="bkm-mono" dir="ltr">{destinationLabel(d)}{d.type === "sftp" && d.path ? ` : ${d.path}` : ""}</span>
                            <small>
                                {t("User")} <span className="bkm-mono" dir="ltr">{d.domain && d.type === "smb" ? `${d.domain}\\${d.username || ""}` : d.username || "—"}</span>
                                {d.type === "sftp" && ` · ${d.auth === "key" ? t("SSH key") : t("Password")}`}
                                {d.last_at && ` · ${t("last contact {{when}}", { when: formatWhen(d.last_at) })}`}
                            </small>
                            {d.host_key_fingerprint && <small>{t("Pinned host key:")} <span className="bkm-mono" dir="ltr">{d.host_key_fingerprint}</span></small>}
                            {failed && d.last_error && <small className="bkm-red">{tb(d.last_error)}</small>}
                            {r && (r.ok
                                ? <div className="bkm-note bkm-note-ok">{t("Connected and wrote a test file.")}{r.fingerprint ? ` ${t("Host key {{fp}} is pinned.", { fp: r.fingerprint })}` : ""}</div>
                                : <div className="bkm-note bkm-note-error">{tb(r.error || "")}</div>)}
                            <div className="bkm-row-gap">
                                <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy === d.id}
                                        onClick={() => run(d, () => api.post(`/api/system-backup/destinations/${d.id}/test`))}>
                                    {busy === d.id ? t("Testing…") : t("Test connection")}
                                </button>
                                <button type="button" className="bkm-btn bkm-btn-sm" onClick={() => onEdit(d)}>{t("Edit")}</button>
                                <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy === d.id} onClick={() => toggle(d)}>
                                    {d.enabled ? t("Disable") : t("Enable")}
                                </button>
                                {d.host_key_fingerprint && (
                                    <button type="button" className="bkm-btn bkm-btn-sm" disabled={busy === d.id}
                                            onClick={() => window.confirm(t("Clear the pinned host key? The key the server presents next will be trusted and pinned.")) &&
                                                run(d, () => api.post(`/api/system-backup/destinations/${d.id}/clear-host-key`))}>
                                        {t("Clear pinned key")}
                                    </button>
                                )}
                                <button type="button" className="bkm-btn bkm-btn-sm alr-danger" disabled={busy === d.id} onClick={() => remove(d)}>{t("Remove")}</button>
                            </div>
                        </div>
                    );
                })}
                <div><button type="button" className="bkm-btn" onClick={() => onEdit(null)}>{t("Add destination…")}</button></div>
            </section>
            <section className="bkm-card bkm-pad">
                <h2>{t("Alerts")}</h2>
                <p className="alr-hint">{t("These alerts go to system administrators; change who receives them and how on the notification rules page.")}</p>
                <ul className="sbk-legend">
                    <li><b>{t("NGCorion backup failed")}</b></li>
                    <li><b>{t("No recent NGCorion backup")}</b> · {t("no successful backup for 48 hours")}</li>
                    <li><b>{t("Backup destination unreachable")}</b></li>
                    <li><b>{t("Backup restore test failed")}</b></li>
                </ul>
                <div><Link className="bkm-btn" to="/settings/notifications">{t("Notification rules")}</Link></div>
            </section>
        </div>
    );
}

// ── restores and tests ────────────────────────────────────────────────────

function HistoryTab({ reload }) {
    const [items, setItems] = useState(null);
    const [open, setOpen] = useState(null);
    useEffect(() => {
        api.get("/api/system-backup/restores").then(({ data }) => setItems(data.items)).catch(() => setItems([]));
    }, [reload]);
    if (!items) return <div className="bkm-card bkm-empty">{t("Loading…")}</div>;
    return (
        <section className="bkm-card bkm-flush">
            {items.length === 0 ? <div className="bkm-empty">{t("No restore or restore test yet.")}</div> : (
                <div className="bkm-table-wrap">
                    <table className="bkm-table sbk-table">
                        <thead>
                            <tr>
                                <th style={{ width: 170 }}>{t("Time")}</th>
                                <th style={{ width: 140 }}>{t("Type")}</th>
                                <th>{t("Backup")}</th>
                                <th style={{ width: 130 }}>{t("By")}</th>
                                <th style={{ width: 260 }}>{t("Result")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {items.map((r) => (
                                <tr key={r.id} className="bkm-row-click" onClick={() => setOpen(open === r.id ? null : r.id)}>
                                    <td><b>{formatWhen(r.created_at)}</b><span className="bkm-sub">{duration(r.started_at, r.finished_at)}</span></td>
                                    <td>{r.kind === "test" ? t("Restore test") : t("Restore")}</td>
                                    <td><span className="bkm-mono" dir="ltr">{r.backup_label || "—"}</span></td>
                                    <td>{r.requested_by === "scheduler" ? t("Automatic") : r.requested_by || "—"}</td>
                                    <td>
                                        <span className={`bkm-pill ${r.status === "succeeded" ? "bkm-pill-ok" : r.status === "failed" ? "bkm-pill-bad" : "bkm-pill-run"}`}>
                                            {r.status === "succeeded" ? t("Succeeded") : r.status === "failed" ? t("Failed") : t("Running")}
                                        </span>
                                        {r.error && <span className="bkm-sub bkm-red">{tb(r.error)}</span>}
                                        {open === r.id && (
                                            <ul className="sbk-steps" style={{ marginTop: 8 }}>
                                                {(r.steps || []).filter((s) => s.status !== "pending").map((s) => (
                                                    <li key={s.key} className={s.status === "skipped" ? "" : s.status}>
                                                        {r.kind === "test" && s.key === "rekey" ? t("Checking that stored passwords open with this server's key")
                                                            : RESTORE_STEPS[s.key] || s.key}
                                                    </li>
                                                ))}
                                            </ul>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </section>
    );
}

