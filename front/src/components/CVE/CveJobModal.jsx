import { useEffect, useRef, useState } from "react";
import api from "../../config/api.js";
import { ACTIVE, KIND_LABEL, STEP_LABEL, formatBytes, formatWhen, num } from "./cveFormat.js";
import { Icon } from "./CveIcons.jsx";

const POLL_MS = 1500;

const TITLES = {
    online: ["Updating the CVE database…", "CVE database updated", "Update failed", "Update cancelled"],
    full: ["Downloading the full CVE database…", "CVE database downloaded", "Download failed", "Download cancelled"],
    offline: ["Importing the package…", "Package imported", "Import failed", "Import cancelled"],
    bundle: ["Loading the bundled CVE database…", "CVE database loaded", "Loading failed", "Loading cancelled"],
    export: ["Creating the update package…", "Package ready", "Export failed", "Export cancelled"],
};

const SUBTITLES = {
    online: "Downloads only what changed since the last update, then applies it in one step.",
    full: "Downloads every published CVE again. Without an NVD API key this takes about 20 minutes.",
    bundle: "The snapshot of the CVE database shipped with this release.",
    export: "A signed package of this database, to carry to a server without internet access.",
};

function stepText(step, progress, job) {
    const { done, total } = progress || {};
    switch (step) {
        case "connect": return "services.nvd.nist.gov";
        case "download":
            if (done == null) return "Waiting for the first page";
            return total ? `${num(Math.min(done, total))} of ${num(total)} CVEs` : `${num(done)} CVEs`;
        case "kev": return "One small file";
        case "epss": return "Daily scores for every CVE";
        case "apply":
            if (done != null && total) return `${num(Math.min(done, total))} of ${num(total)} records`;
            return "Written in one step - the database changes only when all of it is applied";
        case "verify": return "Signature, integrity and fit with this database";
        case "export": return done != null && total ? `${num(done)} of ${num(total)} CVEs` : job.kind === "export" ? "CVEs, KEV list and EPSS scores" : "";
        default: return "";
    }
}

function Bar({ done, total }) {
    if (done == null || !total) return null;
    const pct = Math.max(2, Math.min(100, Math.round((done / total) * 100)));
    return <div className="cvx-bar"><span style={{ width: `${pct}%` }} /></div>;
}

export function CveJobModal({ jobId, isAdmin, onClose }) {
    const [job, setJob] = useState(null);
    const [error, setError] = useState(null);
    const [cancelling, setCancelling] = useState(false);
    const [downloading, setDownloading] = useState(false);
    const timer = useRef(null);

    useEffect(() => {
        let alive = true;
        const poll = async () => {
            try {
                const { data } = await api.get(`/api/cve/db/jobs/${jobId}`);
                if (!alive) return;
                setJob(data);
                if (ACTIVE.includes(data.status)) timer.current = setTimeout(poll, POLL_MS);
            } catch (err) {
                if (alive) setError(err.response?.data?.detail || "Could not read the job status");
            }
        };
        poll();
        return () => { alive = false; clearTimeout(timer.current); };
    }, [jobId]);

    const close = () => onClose(job);

    const cancel = async () => {
        setCancelling(true);
        try {
            await api.post(`/api/cve/db/jobs/${jobId}/cancel`);
        } catch (err) {
            setError(err.response?.data?.detail || "Could not cancel");
        }
    };

    const download = async () => {
        setDownloading(true);
        try {
            const res = await api.get(`/api/cve/db/export/${jobId}/file`, { responseType: "blob" });
            const url = URL.createObjectURL(res.data);
            const a = document.createElement("a");
            a.href = url;
            a.download = job.file_name || "ngcorion-cve.ngcve";
            a.click();
            URL.revokeObjectURL(url);
        } catch {
            setError("The package is no longer available - create it again.");
        } finally {
            setDownloading(false);
        }
    };

    const kind = job?.kind || "online";
    const titles = TITLES[kind] || TITLES.online;
    const active = !job || ACTIVE.includes(job.status);
    const title = active ? titles[0] : job.status === "succeeded" ? titles[1] : job.status === "cancelled" ? titles[3] : titles[2];
    const progress = job?.progress || {};
    const steps = progress.steps || [];
    const current = job?.status === "succeeded" ? steps.length : Math.max(0, steps.indexOf(progress.step));
    const stats = job?.stats || {};

    return (
        <div className="cvx-overlay" role="dialog" aria-modal="true" aria-labelledby="cvx-job-title">
            <section className="cvx-modal">
                <header className="cvx-modal-head">
                    <h2 id="cvx-job-title">{title}</h2>
                    <p>{kind === "offline" ? job?.file_name : SUBTITLES[kind]}</p>
                </header>

                <div className="cvx-modal-body">
                    {!job && !error && <div className="cvx-muted">Starting…</div>}
                    {job && (
                        <ol className="cvx-steps">
                            {steps.map((step, i) => {
                                const failed = !active && job.status !== "succeeded" && i === current;
                                const state = i < current ? "done" : i === current && active ? "active" : failed ? "failed" : "todo";
                                return (
                                    <li key={step} className={`cvx-step cvx-step-${state}`}>
                                        <span className="cvx-step-dot" aria-hidden="true">
                                            {state === "done" ? <Icon name="check" size={15} /> :
                                             state === "active" ? <span className="cvx-spin" /> :
                                             state === "failed" ? <Icon name="x" size={14} /> : i + 1}
                                        </span>
                                        <div>
                                            <h3>{STEP_LABEL[step] || step}</h3>
                                            <p>{state === "active" || state === "done" || state === "todo" ? stepText(step, state === "active" ? progress : null, job) : ""}</p>
                                            {state === "active" && <Bar done={progress.done} total={progress.total} />}
                                        </div>
                                    </li>
                                );
                            })}
                        </ol>
                    )}

                    {job?.status === "succeeded" && kind !== "export" && (
                        <div className="cvx-result cvx-result-ok">
                            <Icon name="check" size={18} />
                            <div>
                                <b>{num(stats.new || 0)} new · {num(stats.changed || 0)} updated{stats.removed ? ` · ${num(stats.removed)} removed` : ""}</b>
                                <span>
                                    {stats.kev != null && `${num(stats.kev)} known exploited · `}
                                    {stats.epss != null && `${num(stats.epss)} EPSS scores · `}
                                    finished {formatWhen(job.finished_at)}
                                    {stats.signer && ` · signed by ${stats.signer}`}
                                </span>
                            </div>
                        </div>
                    )}
                    {job?.status === "succeeded" && kind === "export" && (
                        <div className="cvx-result cvx-result-ok">
                            <Icon name="package" size={18} />
                            <div>
                                <b className="cvx-mono">{job.file_name}</b>
                                <span>{num(stats.cves)} CVEs · {formatBytes(stats.size)} · {stats.kind === "delta" ? `changes since ${formatWhen(stats.since)}` : "the whole database"}</span>
                            </div>
                        </div>
                    )}
                    {(stats.warnings || []).map((w) => (
                        <div key={w} className="cvx-note cvx-note-warn">{w}</div>
                    ))}
                    {job && ["failed", "cancelled"].includes(job.status) && (
                        <div className="cvx-note cvx-note-error">
                            {job.error || "The job did not finish."} {job.kind !== "export" && "The database was not changed."}
                        </div>
                    )}
                    {error && <div className="cvx-note cvx-note-error">{error}</div>}
                    {active && job && (
                        <div className="cvx-note">
                            You can leave this page - the job continues in the background. If it stops, nothing changes; running it again starts from the same point.
                        </div>
                    )}
                    {job?.started_at && active && (
                        <div className="cvx-muted cvx-small">Started {formatWhen(job.started_at)}{job.requested_by_name ? ` by ${job.requested_by_name}` : job.trigger === "automatic" ? " automatically" : ""}</div>
                    )}
                </div>

                <footer className="cvx-modal-foot">
                    <button type="button" className="cvx-btn" onClick={close}>{active ? "Run in background" : "Close"}</button>
                    {active && isAdmin && (
                        <button type="button" className="cvx-btn cvx-btn-danger" onClick={cancel} disabled={cancelling || !job}>
                            {cancelling ? "Cancelling…" : `Cancel ${(KIND_LABEL[kind] || "job").toLowerCase()}`}
                        </button>
                    )}
                    {job?.status === "succeeded" && kind === "export" && (
                        <button type="button" className="cvx-btn cvx-btn-primary" onClick={download} disabled={downloading}>
                            <Icon name="download" size={16} /> {downloading ? "Downloading…" : "Download package"}
                        </button>
                    )}
                </footer>
            </section>
        </div>
    );
}
