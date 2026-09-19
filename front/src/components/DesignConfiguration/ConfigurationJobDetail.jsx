import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate, useParams } from "react-router-dom";
import { fetchConfigurationJobDetail, applyConfigurationObject, clearMessages } from "../../store/configurationSlice.jsx";
import { createDeploymentJob } from "../../store/deploymentSlice.jsx";
import "../../assets/DesignConfiguration.css";

const STATUS_CLASS = { pending: "dc-status-draft", success: "dc-status-published", failed: "dc-status-failed" };

export const ConfigurationJobDetail = () => {
    const { jobId } = useParams();
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { currentJob, isLoading, isApplying, error, successMessage } = useSelector((state) => state.configuration);
    const { role } = useSelector((state) => state.auth);
    const canDeploy = role === "admin" || role === "manager";
    const [applyingObject, setApplyingObject] = useState(null);
    const [expandedObject, setExpandedObject] = useState(null);
    const [creds, setCreds] = useState({ ssh_username: "", ssh_password: "", ssh_secret: "", ssh_port: 22 });

    useEffect(() => {
        dispatch(fetchConfigurationJobDetail(jobId));
    }, [dispatch, jobId]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 4000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    const handleApply = () => {
        dispatch(
            applyConfigurationObject({
                objectId: applyingObject.id,
                credentials: {
                    ssh_username: creds.ssh_username,
                    ssh_password: creds.ssh_password,
                    ssh_secret: creds.ssh_secret || undefined,
                    ssh_port: Number(creds.ssh_port) || 22,
                },
            })
        ).then(() => {
            setApplyingObject(null);
            setCreds({ ssh_username: "", ssh_password: "", ssh_secret: "", ssh_port: 22 });
        });
    };

    if (isLoading || !currentJob) {
        return <div className="dc-container"><div className="dc-empty">Loading…</div></div>;
    }

    const { job, objects } = currentJob;

    return (
        <div className="dc-container">
            <div className="dc-toolbar">
                <div>
                    <h2 className="dc-page-title">{job.name}</h2>
                    <p className="dc-page-subtitle">
                        <span className={`dc-status ${STATUS_CLASS[job.status] || ""}`}>{job.status}</span> · {objects.length} object(s)
                    </p>
                </div>
            </div>

            {(error || successMessage) && (
                <div className={`dc-toast ${error ? "dc-toast-error" : "dc-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="dc-object-list">
                {objects.length === 0 ? (
                    <div className="dc-empty">
                        No configuration objects in this job (no components in the source version were mapped to a
                        real asset).
                    </div>
                ) : (
                    objects.map((obj) => (
                        <div key={obj.id} className="dc-object-card">
                            <div className="dc-object-header">
                                <div>
                                    <span className="dc-cell-strong">{obj.asset_name || "Unmapped"}</span>
                                    <span className="dc-object-devtype">{obj.device_type || "unknown"}</span>
                                </div>
                                <div className="dc-object-header-actions">
                                    <span className={`dc-status ${STATUS_CLASS[obj.apply_status] || ""}`}>{obj.apply_status}</span>
                                    <button
                                        className="dc-link-btn"
                                        onClick={() => setExpandedObject(expandedObject === obj.id ? null : obj.id)}
                                    >
                                        {expandedObject === obj.id ? "Hide" : "View"} config
                                    </button>
                                    <button
                                        className="dc-btn dc-btn-primary dc-btn-small"
                                        onClick={() => setApplyingObject(obj)}
                                        disabled={!["cisco", "fortinet"].includes(obj.device_type)}
                                    >
                                        Apply
                                    </button>
                                    {canDeploy && (
                                        <button
                                            className="dc-btn dc-btn-small"
                                            onClick={() =>
                                                dispatch(createDeploymentJob(obj.id)).then((action) => {
                                                    if (action.payload?.id) navigate(`/deployment/jobs/${action.payload.id}`);
                                                })
                                            }
                                            disabled={!["cisco", "fortinet"].includes(obj.device_type)}
                                            title="Push with a precheck, pre-change backup and post-change verification"
                                        >
                                            Deploy Safely
                                        </button>
                                    )}
                                </div>
                            </div>
                            {expandedObject === obj.id && <pre className="dc-config-pre">{obj.generated_config}</pre>}
                            {obj.apply_output && (
                                <div className="dc-object-output">
                                    <strong>Last result:</strong>
                                    <pre className="dc-config-pre">{obj.apply_output}</pre>
                                </div>
                            )}
                        </div>
                    ))
                )}
            </div>

            {applyingObject && (
                <div className="dc-modal-backdrop" onClick={() => setApplyingObject(null)}>
                    <div className="dc-modal" onClick={(e) => e.stopPropagation()}>
                        <h3>Apply configuration to {applyingObject.asset_name}</h3>
                        <p className="dc-modal-hint">
                            Credentials are used once to push this configuration and are never stored.
                        </p>
                        <div className="dc-field">
                            <label>Username</label>
                            <input value={creds.ssh_username} onChange={(e) => setCreds({ ...creds, ssh_username: e.target.value })} />
                        </div>
                        <div className="dc-field">
                            <label>Password</label>
                            <input type="password" value={creds.ssh_password} onChange={(e) => setCreds({ ...creds, ssh_password: e.target.value })} />
                        </div>
                        <div className="dc-field">
                            <label>Enable secret (Cisco, optional)</label>
                            <input type="password" value={creds.ssh_secret} onChange={(e) => setCreds({ ...creds, ssh_secret: e.target.value })} />
                        </div>
                        <div className="dc-field">
                            <label>Port</label>
                            <input type="number" value={creds.ssh_port} onChange={(e) => setCreds({ ...creds, ssh_port: e.target.value })} />
                        </div>
                        <div className="dc-modal-actions">
                            <button className="dc-btn" onClick={() => setApplyingObject(null)}>Cancel</button>
                            <button
                                className="dc-btn dc-btn-primary"
                                onClick={handleApply}
                                disabled={isApplying || !creds.ssh_username || !creds.ssh_password}
                            >
                                {isApplying ? "Applying…" : "Apply"}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ConfigurationJobDetail;
