import { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { fetchConfigurationJobs, clearMessages } from "../../store/configurationSlice.jsx";
import "../../assets/DesignConfiguration.css";

const STATUS_CLASS = { generated: "dc-status-draft", applied: "dc-status-published", partially_applied: "dc-status-partial" };

export const ConfigurationJobList = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { jobs, isLoading, error, successMessage } = useSelector((state) => state.configuration);

    useEffect(() => {
        dispatch(fetchConfigurationJobs());
    }, [dispatch]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 4000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    return (
        <div className="dc-container">
            <div className="dc-toolbar">
                <div className="dc-toolbar-info">{jobs.length} job(s)</div>
            </div>

            {(error || successMessage) && (
                <div className={`dc-toast ${error ? "dc-toast-error" : "dc-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="dc-table-container">
                {isLoading ? (
                    <div className="dc-empty">Loading configuration jobs…</div>
                ) : jobs.length === 0 ? (
                    <div className="dc-empty">
                        No configuration jobs yet. Generate one from a design version's canvas.
                    </div>
                ) : (
                    <table className="dc-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Status</th>
                                <th>Objects</th>
                                <th>Created</th>
                            </tr>
                        </thead>
                        <tbody>
                            {jobs.map((j) => (
                                <tr key={j.id} onClick={() => navigate(`/design-configuration/jobs/${j.id}`)}>
                                    <td className="dc-cell-strong">{j.name}</td>
                                    <td>
                                        <span className={`dc-status ${STATUS_CLASS[j.status] || ""}`}>{j.status}</span>
                                    </td>
                                    <td>{j.object_count}</td>
                                    <td>{j.created_at ? new Date(j.created_at).toLocaleString() : "—"}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
};

export default ConfigurationJobList;
