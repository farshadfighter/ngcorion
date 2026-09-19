import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useParams, useNavigate } from "react-router-dom";
import {
    fetchDeploymentJobDetail,
    startDeploymentJob,
    rollbackDeploymentJob,
    clearMessages,
} from "../../store/deploymentSlice.jsx";
import "../../assets/Deployment.css";

const STEPS = [
    { key: "precheck", label: "Precheck", outputKey: "precheck_output" },
    { key: "backup", label: "Backup", outputKey: null },
    { key: "applying", label: "Apply", outputKey: "apply_output" },
    { key: "verifying", label: "Verify", outputKey: "verify_output" },
];

const FAILURE_FOR_STEP = {
    precheck: "precheck_failed",
    backup: "backup_failed",
    applying: "apply_failed",
    verifying: "verify_failed",
};

const STEP_ORDER = ["queued", "precheck", "backup", "applying", "verifying", "success"];

function stepState(job, stepKey) {
    const failureStatus = FAILURE_FOR_STEP[stepKey];
    if (job.status === failureStatus) return "failed";
    const currentIdx = STEP_ORDER.indexOf(job.status);
    const stepIdx = STEP_ORDER.indexOf(stepKey);
    if (currentIdx > stepIdx || job.status === "success") return "done";
    if (currentIdx === stepIdx) return "active";
    return "pending";
}

export const DeploymentJobDetail = () => {
    const { jobId } = useParams();
    const navigate = useNavigate();
    const dispatch = useDispatch();
    const { currentJob, isLoading, isStarting, isRollingBack, error, successMessage } = useSelector((state) => state.deployment);
    const [showCreds, setShowCreds] = useState(null); // "start" | "rollback" | null
    const [creds, setCreds] = useState({ ssh_username: "", ssh_password: "", ssh_secret: "", ssh_port: 22 });

    useEffect(() => {
        dispatch(fetchDeploymentJobDetail(jobId));
    }, [dispatch, jobId]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 5000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    const buildCredentials = () => ({
        ssh_username: creds.ssh_username,
        ssh_password: creds.ssh_password,
        ssh_secret: creds.ssh_secret || undefined,
        ssh_port: Number(creds.ssh_port) || 22,
    });

    const handleConfirm = () => {
        if (showCreds === "start") {
            dispatch(startDeploymentJob({ jobId, credentials: buildCredentials() }));
        } else if (showCreds === "rollback") {
            dispatch(rollbackDeploymentJob({ jobId, credentials: buildCredentials() }));
        }
        setShowCreds(null);
        setCreds({ ssh_username: "", ssh_password: "", ssh_secret: "", ssh_port: 22 });
    };

    if (isLoading || !currentJob) {
        return <div className="dep-container"><div className="dep-empty">Loading…</div></div>;
    }

    const job = currentJob;
    const canStart = job.status === "queued";
    const canRollback = ["apply_failed", "verify_failed", "rollback_failed"].includes(job.status);

    return (
        <div className="dep-container">
            <div className="dep-toolbar">
                <div>
                    <h2 className="dep-page-title">{job.asset_name || "Deployment"}</h2>
                    <p className="dep-page-subtitle">{job.device_type} · status: {job.status.replace(/_/g, " ")}</p>
                </div>
                <div className="dep-toolbar-actions">
                    {canStart && (
                        <button className="dep-btn dep-btn-primary" onClick={() => setShowCreds("start")} disabled={isStarting}>
                            <i className="fa-solid fa-play" /> {isStarting ? "Running…" : "Start Deployment"}
                        </button>
                    )}
                    {canRollback && (
                        <button className="dep-btn dep-btn-danger" onClick={() => setShowCreds("rollback")} disabled={isRollingBack}>
                            <i className="fa-solid fa-rotate-left" /> {isRollingBack ? "Rolling back…" : "Rollback"}
                        </button>
                    )}
                    {job.status === "success" && (
                        <button className="dep-btn" onClick={() => navigate("/drift")} title="Periodically re-check this device's config against this deployment's backup to catch later manual changes">
                            <i className="fa-solid fa-magnifying-glass" /> Check for Drift
                        </button>
                    )}
                </div>
            </div>

            {(error || successMessage) && (
                <div className={`dep-toast ${error ? "dep-toast-error" : "dep-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="dep-steps">
                {STEPS.map((step) => {
                    const state = stepState(job, step.key);
                    const output = step.outputKey ? job[step.outputKey] : job.backup_id ? `Backup #${job.backup_id} saved` : null;
                    return (
                        <div key={step.key} className={`dep-step dep-step-${state}`}>
                            <div className="dep-step-marker">
                                {state === "done" && <i className="fa-solid fa-check" />}
                                {state === "failed" && <i className="fa-solid fa-xmark" />}
                                {state === "active" && <i className="fa-solid fa-spinner" />}
                            </div>
                            <div className="dep-step-body">
                                <div className="dep-step-label">{step.label}</div>
                                {output && <pre className="dep-step-output">{output}</pre>}
                            </div>
                        </div>
                    );
                })}
            </div>

            {job.error_message && <div className="dep-error-box">{job.error_message}</div>}

            {job.rollback_output && (
                <div className="dep-object-output">
                    <strong>Rollback result:</strong>
                    <pre className="dep-step-output">{job.rollback_output}</pre>
                </div>
            )}

            {showCreds && (
                <div className="dep-modal-backdrop" onClick={() => setShowCreds(null)}>
                    <div className="dep-modal" onClick={(e) => e.stopPropagation()}>
                        <h3>{showCreds === "start" ? "Start deployment" : "Roll back"}</h3>
                        <p className="dep-modal-hint">
                            Credentials are used once for this action and are never stored.
                        </p>
                        <div className="dep-field">
                            <label>Username</label>
                            <input value={creds.ssh_username} onChange={(e) => setCreds({ ...creds, ssh_username: e.target.value })} />
                        </div>
                        <div className="dep-field">
                            <label>Password</label>
                            <input type="password" value={creds.ssh_password} onChange={(e) => setCreds({ ...creds, ssh_password: e.target.value })} />
                        </div>
                        <div className="dep-field">
                            <label>Enable secret (Cisco, optional)</label>
                            <input type="password" value={creds.ssh_secret} onChange={(e) => setCreds({ ...creds, ssh_secret: e.target.value })} />
                        </div>
                        <div className="dep-field">
                            <label>Port</label>
                            <input type="number" value={creds.ssh_port} onChange={(e) => setCreds({ ...creds, ssh_port: e.target.value })} />
                        </div>
                        <div className="dep-modal-actions">
                            <button className="dep-btn" onClick={() => setShowCreds(null)}>Cancel</button>
                            <button
                                className="dep-btn dep-btn-primary"
                                onClick={handleConfirm}
                                disabled={!creds.ssh_username || !creds.ssh_password}
                            >
                                Confirm
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default DeploymentJobDetail;
