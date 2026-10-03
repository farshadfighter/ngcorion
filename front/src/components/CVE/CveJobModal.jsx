import { useEffect, useRef, useState } from "react";
import api from "../../config/api.js";
import { ACTIVE, ADV_STEP_LABEL, KIND_LABEL, STEP_LABEL, formatBytes, formatWhen, isAdvisoryJob, num, releaseLabel } from "./cveFormat.js";
import { Icon } from "./CveIcons.jsx";
import { tb } from "../../i18n/backendText";
import { currentLanguage, t, n } from "../../i18n";

const POLL_MS = 1500;

const TITLES = {
    online: [t("Updating the CVE database…"), "CVE database updated", t("Update failed"), t("Update cancelled")],
    full: [t("Downloading the full CVE database…"), "CVE database downloaded", t("Download failed"), t("Download cancelled")],
    offline: [t("Importing the package…"), t("Package imported"), t("Import failed"), t("Import cancelled")],
    bundle: [t("Loading the bundled CVE database…"), "CVE database loaded", t("Loading failed"), t("Loading cancelled")],
    export: [t("Creating the update package…"), t("Package ready"), t("Export failed"), t("Export cancelled")],
    advisories: [t("Updating the distribution advisories…"), t("Advisories updated"), t("Update failed"), t("Update cancelled")],
    adv_import: [t("Importing the advisories…"), t("Advisories imported"), t("Import failed"), t("Import cancelled")],
};

const SUBTITLES = {
    online: t("Downloads only what changed since the last update, then applies it in one step."),
    full: t("Downloads every published CVE again. Without an NVD API key this takes about 20 minutes."),
    bundle: t("The snapshot of the CVE database shipped with this release."),
    advisories: t("Downloads the security advisories of the Linux releases your assets run, from OSV.dev."),
    adv_import: t("An OSV archive downloaded from OSV.dev, for servers without internet access."),
    export: "A signed package of this database, to carry to a server without internet access.",
};

function advStepText(step, progress) {
    const { done, total, message } = progress || {};
    switch (step) {
        case "connect": return "osv-vulnerabilities.storage.googleapis.com";
        case "download":
            if (done == null) return message || t("The releases your assets run");
            return total ? `${message ? `${message} · ` : ""}${formatBytes(done)} / ${formatBytes(total)}` : t("{{num}} changed records", { num: num(done) });
        case "apply":
            if (done != null) return total ? `${num(Math.min(done, total))} / ${num(total)}` : t("{{num}} records read", { num: num(done) });
            return t("Written in one step - the database changes only when all of it is applied");
        case "verify": return done != null ? t("{{num}} records read", { num: num(done) }) : t("Which releases the file holds");
        default: return "";
    }
}

function stepText(step, progress, job) {
    if (isAdvisoryJob(job?.kind)) return advStepText(step, progress);
    const { done, total } = progress || {};
    switch (step) {
        case "connect": return "services.nvd.nist.gov";
        case "download":
            if (done == null) return t("Waiting for the first page");
            return total ? `${num(Math.min(done, total))} of ${num(total)} CVEs` : `${num(done)} CVEs`;
        case "kev": return t("One small file");
        case "epss": return t("Daily scores for every CVE");
        case "apply":
            if (done != null && total) return `${num(Math.min(done, total))} of ${num(total)} records`;
            return t("Written in one step - the database changes only when all of it is applied");
        case "verify": return t("Signature, integrity and fit with this database");
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
                if (alive) setError(err.response?.data?.detail || t("Could not read the job status"));
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
            setError(err.response?.data?.detail || t("Could not cancel"));
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
            setError(t("The package is no longer available - create it again."));
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
                    {!job && !error && <div className="cvx-muted">{t("Starting…")}</div>}
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
                                             state === "failed" ? <Icon name="x" size={14} /> : n(i + 1)}
                                        </span>
                                        <div>
                                            <h3>{(isAdvisoryJob(kind) ? ADV_STEP_LABEL[step] : STEP_LABEL[step]) || step}</h3>
                                            <p>{state === "active" || state === "done" || state === "todo" ? stepText(step, state === "active" ? progress : null, job) : ""}</p>
                                            {state === "active" && <Bar done={progress.done} total={progress.total} />}
                                        </div>
                                    </li>
                                );
                            })}
                        </ol>
                    )}

                    {job?.status === "succeeded" && isAdvisoryJob(kind) && (
                        <div className="cvx-result cvx-result-ok">
                            <Icon name="check" size={18} />
                            <div>
                                <b>{(stats.releases || []).length ? (stats.releases || []).map(releaseLabel).join(currentLanguage() === "fa" ? "، " : ", ") : t("No release to load")}</b>
                                <span>
                                    {stats.note ? t("No asset runs a supported Linux release yet - nothing to load.")
                                        : t("{{records}} records changed · {{rows}} rows written", { records: num(stats.records || 0), rows: num(stats.rows || 0) })}
                                    {" · "}{t("finished {{finished_at}}", { finished_at: formatWhen(job.finished_at) })}
                                </span>
                            </div>
                        </div>
                    )}
                    {job?.status === "succeeded" && kind !== "export" && !isAdvisoryJob(kind) && (
                        <div className="cvx-result cvx-result-ok">
                            <Icon name="check" size={18} />
                            <div>
                                <b>{t("{{num}} new · {{num2}} updated", { num: num(stats.new || 0), num2: num(stats.changed || 0) })}{stats.removed ? t(" · {{num}} removed", { num: num(stats.removed) }) : ""}</b>
                                <span>
                                    {stats.kev != null && t("{{num}} known exploited · ", { num: num(stats.kev) })}
                                    {stats.epss != null && t("{{num}} EPSS scores · ", { num: num(stats.epss) })}
                                    {t("finished {{finished_at}}", { finished_at: formatWhen(job.finished_at) })}
                                    {stats.signer && t(" · signed by {{signer}}", { signer: stats.signer })}
                                </span>
                            </div>
                        </div>
                    )}
                    {job?.status === "succeeded" && kind === "export" && (
                        <div className="cvx-result cvx-result-ok">
                            <Icon name="package" size={18} />
                            <div>
                                <b className="cvx-mono">{job.file_name}</b>
                                <span>{t("{{num}} CVEs · {{size}} ·", { num: num(stats.cves), size: formatBytes(stats.size) })}{" "} {stats.kind === "delta" ? t("changes since {{since}}", { since: formatWhen(stats.since) }) : t("the whole database")}</span>
                            </div>
                        </div>
                    )}
                    {(stats.warnings || []).map((w) => (
                        <div key={w} className="cvx-note cvx-note-warn">{w}</div>
                    ))}
                    {job && ["failed", "cancelled"].includes(job.status) && (
                        <div className="cvx-note cvx-note-error">
                            {job.error ? tb(job.error) : t("The job did not finish.")} {job.kind !== "export" && t("The database was not changed.")}
                        </div>
                    )}
                    {error && <div className="cvx-note cvx-note-error">{error}</div>}
                    {active && job && (
                        <div className="cvx-note">
                            {t("You can leave this page - the job continues in the background. If it stops, nothing changes; running it again starts from the same point.")}
                        </div>
                    )}
                    {job?.started_at && active && (
                        <div className="cvx-muted cvx-small">{t("Started {{started_at}}", { started_at: formatWhen(job.started_at) })}{job.requested_by_name ? ` by ${job.requested_by_name}` : job.trigger === "automatic" ? " automatically" : ""}</div>
                    )}
                </div>

                <footer className="cvx-modal-foot">
                    <button type="button" className="cvx-btn" onClick={close}>{active ? t("Run in background") : t("Close")}</button>
                    {active && isAdmin && (
                        <button type="button" className="cvx-btn cvx-btn-danger" onClick={cancel} disabled={cancelling || !job}>
                            {cancelling ? t("Cancelling…") : t("Cancel")}
                        </button>
                    )}
                    {job?.status === "succeeded" && kind === "export" && (
                        <button type="button" className="cvx-btn cvx-btn-primary" onClick={download} disabled={downloading}>
                            <Icon name="download" size={16} /> {downloading ? t("Downloading…") : t("Download package")}
                        </button>
                    )}
                </footer>
            </section>
        </div>
    );
}
