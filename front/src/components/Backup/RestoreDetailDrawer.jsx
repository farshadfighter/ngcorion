import { useEffect, useRef, useState } from "react";
import { useSelector } from "react-redux";
import api from "../../config/api.js";
import { usePermission } from "../../hooks/usePermission.js";
import { duration, formatWhen } from "../../utils/dates.js";
import BackupViewModal from "./BackupViewModal.jsx";
import RestoreWizard from "./RestoreWizard.jsx";

const ACTIVE = ["queued", "connecting", "backing_up", "applying", "verifying", "saving", "reverting"];
const RESULT = {
    succeeded: ["Succeeded", "bkm-pill-ok"],
    reverted: ["Reverted automatically", "bkm-pill-orange"],
    failed: ["Failed", "bkm-pill-bad"],
};
const STEP_TITLE = {
    connect: "Connect", backup: "Undo point", apply: "Apply changes", verify: "Verify",
    save: "Save on the device", revert: "Revert", error: "Stopped",
};
const FAMILY = { cisco: "Cisco", fortinet: "Fortinet", linux: "Linux", apache: "Apache", mongodb: "MongoDB" };

export function RestoreResult({ status, short = false }) {
    const [label, cls] = RESULT[status] || (ACTIVE.includes(status) ? ["In progress", "bkm-pill-run"] : [status, "bkm-pill-muted"]);
    const text = short && status === "reverted" ? "Reverted" : label;
    return <span className={`bkm-pill ${cls}`} title={text !== label ? label : undefined}>{text}</span>;
}

export function Changes({ diff }) {
    if (!diff) return <span className="bkm-muted">—</span>;
    return (
        <span className="bkm-nowrap">
            <span className="bkm-mono bkm-add">+{diff.added ?? 0}</span>{" "}
            <span className="bkm-mono bkm-del">−{diff.removed ?? 0}</span>
        </span>
    );
}

function EventDot({ status }) {
    const done = status === "done";
    const failed = status === "failed";
    return (
        <span className={`bkm-ev-dot ${done ? "is-done" : failed ? "is-failed" : "is-info"}`} aria-hidden="true">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                <path d={done ? "m5 12 5 5 9-10" : failed ? "M6 6l12 12M18 6 6 18" : "M12 8v5M12 17v.01"} />
            </svg>
        </span>
    );
}

const clock = (iso) => {
    if (!iso) return "";
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
};

/** One restore: why, what changed, step by step how it went; actions on its backups. */
export function RestoreDetailDrawer({ jobId, onClose, onChanged }) {
    const [job, setJob] = useState(null);
    const [error, setError] = useState(null);
    const [viewId, setViewId] = useState(null);
    const [again, setAgain] = useState(false);
    const timer = useRef(null);
    const role = useSelector((s) => s.auth.role);
    const canRestore = usePermission("backup", "write") && (role === "admin" || role === "manager");

    useEffect(() => {
        let alive = true;
        const load = () => api.get(`/api/backups/restores/${jobId}`)
            .then(({ data }) => {
                if (!alive) return;
                setJob(data);
                if (ACTIVE.includes(data.status)) timer.current = setTimeout(load, 3000);
            })
            .catch((e) => alive && setError(e.response?.data?.detail || "Could not load the restore"));
        load();
        return () => { alive = false; clearTimeout(timer.current); };
    }, [jobId]);

    useEffect(() => {
        if (viewId || again) return undefined;   // Escape belongs to the open dialog
        const onKey = (e) => e.key === "Escape" && onClose();
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [onClose, viewId, again]);

    const active = job && ACTIVE.includes(job.status);
    const took = job && duration(job.started_at || job.created_at, job.finished_at);
    const diff = job?.diff_summary;

    return (
        <div className="bkm-drawer-wrap" role="dialog" aria-modal="true" aria-labelledby="bkm-restore-title">
            <button type="button" className="bkm-scrim" aria-label="Close" onClick={onClose} />
            <aside className="bkm-drawer">
                <header className="bkm-drawer-head">
                    <div>
                        <div className="bkm-row-gap">
                            <h2 id="bkm-restore-title">Restore #{jobId}{job ? ` · ${job.asset_name || ""}` : ""}</h2>
                            {job && <RestoreResult status={job.status} />}
                        </div>
                        {job && (
                            <div className="bkm-sub">
                                {formatWhen(job.created_at)}{job.requested_by_username ? ` · by ${job.requested_by_username}` : ""}{took ? ` · took ${took}` : ""}
                            </div>
                        )}
                    </div>
                    <button type="button" className="bkm-icon-btn" aria-label="Close" onClick={onClose}>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18" /></svg>
                    </button>
                </header>

                <div className="bkm-drawer-body">
                    {error && <div className="bkm-note bkm-note-error">{error}</div>}
                    {!job && !error && <div className="bkm-muted">Loading…</div>}
                    {job && (
                        <>
                            {job.status === "succeeded" && (
                                <div className="bkm-note bkm-note-ok">The device now runs the configuration of backup #{job.backup_id ?? "?"}{job.events.some((e) => e.step === "save") ? ", saved on the device." : "."}</div>
                            )}
                            {job.status === "reverted" && (
                                <div className="bkm-note bkm-note-orange">
                                    <b>The device returned to its previous configuration.</b> {job.error}
                                </div>
                            )}
                            {job.status === "failed" && <div className="bkm-note bkm-note-error">{job.error || "The restore did not finish."}</div>}
                            {active && <div className="bkm-note">In progress - this panel updates by itself.</div>}

                            <div>
                                <h3 className="bkm-h3">Reason given</h3>
                                <div className="bkm-quote">{job.reason}</div>
                            </div>

                            <div className="bkm-two">
                                <div>
                                    <h3 className="bkm-h3">Backups</h3>
                                    <div className="bkm-kv"><span>Restored</span><b>{job.backup_id
                                        ? <button type="button" className="bkm-link" onClick={() => setViewId(job.backup_id)}>#{job.backup_id}</button>
                                        : "deleted"}</b></div>
                                    <div className="bkm-kv"><span>Undo point (before)</span><b>{job.pre_restore_backup_id
                                        ? <button type="button" className="bkm-link" onClick={() => setViewId(job.pre_restore_backup_id)}>#{job.pre_restore_backup_id}</button>
                                        : "—"}</b></div>
                                    <div className="bkm-kv"><span>Device</span><b className="bkm-mono">{job.device_ip || "—"} · {FAMILY[job.device_type] || job.device_type}</b></div>
                                </div>
                                <div>
                                    <h3 className="bkm-h3">Changes applied</h3>
                                    <div className="bkm-kv"><span>Lines</span><b><Changes diff={diff} /></b></div>
                                    <div className="bkm-kv"><span>Sections</span><b>{diff?.sections ?? "—"}</b></div>
                                    <div className="bkm-kv"><span>Auto-revert</span><b>{job.auto_revert === "armed" ? `Armed · ${job.revert_minutes} min` : "Not available"}</b></div>
                                </div>
                            </div>

                            <div>
                                <h3 className="bkm-h3">What happened</h3>
                                {job.events.length === 0 ? <div className="bkm-muted">Nothing recorded yet.</div> : (
                                    <ol className="bkm-events">
                                        {job.events.map((e, i) => (
                                            <li key={i}>
                                                <EventDot status={e.status} />
                                                <div><b>{STEP_TITLE[e.step] || e.step}</b><p>{e.message}</p></div>
                                                <span className="bkm-mono bkm-muted">{clock(e.at)}</span>
                                            </li>
                                        ))}
                                    </ol>
                                )}
                            </div>
                        </>
                    )}
                </div>

                {job && (
                    <footer className="bkm-drawer-foot">
                        <span className="bkm-muted bkm-small">Recorded in the audit log</span>
                        <div className="bkm-actions">
                            {job.pre_restore_backup_id && (
                                <button type="button" className="bkm-btn" onClick={() => setViewId(job.pre_restore_backup_id)}>Open undo point #{job.pre_restore_backup_id}</button>
                            )}
                            {canRestore && job.backup_id && !active && (
                                <button type="button" className="bkm-btn bkm-btn-primary" onClick={() => setAgain(true)}>Restore again…</button>
                            )}
                        </div>
                    </footer>
                )}
            </aside>

            {viewId && <BackupViewModal backupId={viewId} onClose={() => setViewId(null)} />}
            {again && (
                <RestoreWizard
                    backupId={job.backup_id}
                    onClose={() => setAgain(false)}
                    onChanged={onChanged}
                    onOpenBackup={(id) => setViewId(id)}
                />
            )}
        </div>
    );
}

export default RestoreDetailDrawer;
