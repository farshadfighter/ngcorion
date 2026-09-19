import { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { fetchDeploymentJobs, clearMessages } from "../../store/deploymentSlice.jsx";
import "../../assets/Deployment.css";

const STATUS_CLASS = {
    queued: "dep-status-neutral",
    precheck: "dep-status-progress",
    backup: "dep-status-progress",
    applying: "dep-status-progress",
    verifying: "dep-status-progress",
    success: "dep-status-success",
    rolled_back: "dep-status-neutral",
    precheck_failed: "dep-status-failed",
    backup_failed: "dep-status-failed",
    apply_failed: "dep-status-failed",
    verify_failed: "dep-status-failed",
    rollback_failed: "dep-status-failed",
};

export const DeploymentJobList = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { jobs, isLoading, error, successMessage } = useSelector((state) => state.deployment);

    useEffect(() => {
        dispatch(fetchDeploymentJobs());
    }, [dispatch]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 4000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    return (
        <div className="dep-container">
            <div className="dep-toolbar">
                <div className="dep-toolbar-info">{jobs.length} deployment job(s)</div>
            </div>

            {(error || successMessage) && (
                <div className={`dep-toast ${error ? "dep-toast-error" : "dep-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="dep-table-container">
                {isLoading ? (
                    <div className="dep-empty">Loading deployment jobs…</div>
                ) : jobs.length === 0 ? (
                    <div className="dep-empty">
                        No deployment jobs yet. Start one from a Configuration Job's object list ("Deploy Safely").
                    </div>
                ) : (
                    <table className="dep-table">
                        <thead>
                            <tr>
                                <th>Asset</th>
                                <th>Device type</th>
                                <th>Status</th>
                                <th>Created</th>
                                <th>Completed</th>
                            </tr>
                        </thead>
                        <tbody>
                            {jobs.map((j) => (
                                <tr key={j.id} onClick={() => navigate(`/deployment/jobs/${j.id}`)}>
                                    <td className="dep-cell-strong">{j.asset_name || "—"}</td>
                                    <td>{j.device_type || "—"}</td>
                                    <td>
                                        <span className={`dep-status ${STATUS_CLASS[j.status] || ""}`}>
                                            {j.status.replace(/_/g, " ")}
                                        </span>
                                    </td>
                                    <td>{j.created_at ? new Date(j.created_at).toLocaleString() : "—"}</td>
                                    <td>{j.completed_at ? new Date(j.completed_at).toLocaleString() : "—"}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
};

export default DeploymentJobList;
