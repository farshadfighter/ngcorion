import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
    fetchFindings,
    runAnalysis,
    acceptFinding,
    ignoreFinding,
    clearMessages,
} from "../../store/architectureValidationSlice.jsx";
import "../../assets/ArchitectureValidation.css";

const STATUS_TABS = [
    { key: "open", label: "Open" },
    { key: "accepted", label: "Accepted" },
    { key: "ignored", label: "Ignored" },
    { key: "", label: "All" },
];

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };
const SEVERITY_CLASS = { low: "av-badge-low", medium: "av-badge-medium", high: "av-badge-high" };

export const ArchitectureValidationDashboard = () => {
    const dispatch = useDispatch();
    const { findings, isLoading, isAnalyzing, error, successMessage, lastRun } = useSelector(
        (state) => state.architectureValidation
    );
    const [statusFilter, setStatusFilter] = useState("open");
    const [ignoringId, setIgnoringId] = useState(null);
    const [ignoreReason, setIgnoreReason] = useState("");

    useEffect(() => {
        dispatch(fetchFindings({ status: statusFilter || undefined }));
    }, [dispatch, statusFilter]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 4000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    const handleAnalyze = () => {
        dispatch(runAnalysis()).then(() => dispatch(fetchFindings({ status: statusFilter || undefined })));
    };

    const handleAccept = (id) => dispatch(acceptFinding(id));

    const handleIgnoreConfirm = () => {
        dispatch(ignoreFinding({ findingId: ignoringId, reason: ignoreReason || undefined }));
        setIgnoringId(null);
        setIgnoreReason("");
    };

    const sortedFindings = [...findings].sort(
        (a, b) => (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3)
    );

    return (
        <div className="av-container">
            <div className="av-toolbar">
                <div className="av-tabs">
                    {STATUS_TABS.map((tab) => (
                        <button
                            key={tab.key}
                            className={`av-tab ${statusFilter === tab.key ? "active" : ""}`}
                            onClick={() => setStatusFilter(tab.key)}
                        >
                            {tab.label}
                        </button>
                    ))}
                </div>
                <div className="av-toolbar-actions">
                    {lastRun && (
                        <span className="av-last-run">
                            Last run: {lastRun.findingCount} finding(s) / {lastRun.assetCount} asset(s)
                        </span>
                    )}
                    <button className="av-btn av-btn-primary" onClick={handleAnalyze} disabled={isAnalyzing}>
                        <i className="fa-solid fa-clipboard-check" /> {isAnalyzing ? "Analyzing…" : "Run Analysis"}
                    </button>
                </div>
            </div>

            {(error || successMessage) && (
                <div className={`av-toast ${error ? "av-toast-error" : "av-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="av-table-container">
                {isLoading ? (
                    <div className="av-empty">Loading findings…</div>
                ) : sortedFindings.length === 0 ? (
                    <div className="av-empty">
                        No {statusFilter || ""} findings. Click "Run Analysis" to check every asset against the
                        architecture rule set.
                    </div>
                ) : (
                    <table className="av-table">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Rule</th>
                                <th>Asset</th>
                                <th>Category</th>
                                <th>Recommendation</th>
                                {statusFilter === "open" && <th>Actions</th>}
                            </tr>
                        </thead>
                        <tbody>
                            {sortedFindings.map((f) => (
                                <tr key={f.id}>
                                    <td>
                                        <span className={`av-badge ${SEVERITY_CLASS[f.severity] || ""}`}>
                                            {f.severity}
                                        </span>
                                    </td>
                                    <td>
                                        <div className="av-rule-code">{f.rule_code}</div>
                                        <div className="av-rule-title">{f.title}</div>
                                    </td>
                                    <td>{f.asset_name || "—"}</td>
                                    <td>{f.category || "—"}</td>
                                    <td className="av-recommendation">{f.recommendation || "—"}</td>
                                    {statusFilter === "open" && (
                                        <td>
                                            <div className="av-row-actions">
                                                <button className="av-link-btn" onClick={() => handleAccept(f.id)}>
                                                    Accept
                                                </button>
                                                <button
                                                    className="av-link-btn av-link-btn-muted"
                                                    onClick={() => setIgnoringId(f.id)}
                                                >
                                                    Ignore
                                                </button>
                                            </div>
                                        </td>
                                    )}
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {ignoringId !== null && (
                <div className="av-modal-backdrop" onClick={() => setIgnoringId(null)}>
                    <div className="av-modal" onClick={(e) => e.stopPropagation()}>
                        <h3>Ignore finding</h3>
                        <p className="av-modal-hint">Optionally explain why this finding doesn't apply.</p>
                        <textarea
                            className="av-modal-textarea"
                            rows={3}
                            value={ignoreReason}
                            onChange={(e) => setIgnoreReason(e.target.value)}
                            placeholder="Reason (optional)"
                        />
                        <div className="av-modal-actions">
                            <button className="av-btn" onClick={() => setIgnoringId(null)}>
                                Cancel
                            </button>
                            <button className="av-btn av-btn-primary" onClick={handleIgnoreConfirm}>
                                Ignore finding
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ArchitectureValidationDashboard;
