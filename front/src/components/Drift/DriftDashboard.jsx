import { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
    fetchDriftResults,
    fetchDriftResultDetail,
    runDriftAnalysis,
    acceptDriftResult,
    ignoreDriftResult,
    clearMessages,
} from "../../store/driftSlice.jsx";
import { fetchAssets } from "../../store/assetSlice.jsx";
import "../../assets/Drift.css";

const STATUS_TABS = [
    { key: "open", label: "Open" },
    { key: "accepted", label: "Accepted" },
    { key: "ignored", label: "Ignored" },
    { key: "", label: "All" },
];

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };
const SEVERITY_CLASS = { low: "drift-badge-low", medium: "drift-badge-medium", high: "drift-badge-high" };

export const DriftDashboard = () => {
    const dispatch = useDispatch();
    const { results, currentResult, isLoading, isAnalyzing, error, successMessage, lastRun } = useSelector(
        (state) => state.drift
    );
    const { assets } = useSelector((state) => state.assets);

    const [statusFilter, setStatusFilter] = useState("open");
    const [showAnalyze, setShowAnalyze] = useState(false);
    const [ignoringId, setIgnoringId] = useState(null);
    const [ignoreReason, setIgnoreReason] = useState("");
    const [viewingId, setViewingId] = useState(null);
    const [form, setForm] = useState({ asset_id: "", ssh_username: "", ssh_password: "", ssh_secret: "", ssh_port: 22 });

    useEffect(() => {
        dispatch(fetchDriftResults({ status: statusFilter || undefined }));
        dispatch(fetchAssets());
    }, [dispatch, statusFilter]);

    useEffect(() => {
        if (!error && !successMessage) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 5000);
        return () => clearTimeout(timer);
    }, [error, successMessage, dispatch]);

    const handleAnalyze = () => {
        dispatch(
            runDriftAnalysis({
                assetId: Number(form.asset_id),
                credentials: {
                    ssh_username: form.ssh_username,
                    ssh_password: form.ssh_password,
                    ssh_secret: form.ssh_secret || undefined,
                    ssh_port: Number(form.ssh_port) || 22,
                },
            })
        ).then(() => dispatch(fetchDriftResults({ status: statusFilter || undefined })));
        setShowAnalyze(false);
        setForm({ asset_id: "", ssh_username: "", ssh_password: "", ssh_secret: "", ssh_port: 22 });
    };

    const handleAccept = (id) => dispatch(acceptDriftResult(id));

    const handleIgnoreConfirm = () => {
        dispatch(ignoreDriftResult({ resultId: ignoringId, reason: ignoreReason || undefined }));
        setIgnoringId(null);
        setIgnoreReason("");
    };

    const handleView = (id) => {
        setViewingId(id);
        dispatch(fetchDriftResultDetail(id));
    };

    const sortedResults = [...results].sort(
        (a, b) => (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3)
    );

    return (
        <div className="drift-container">
            <div className="drift-toolbar">
                <div className="drift-tabs">
                    {STATUS_TABS.map((tab) => (
                        <button
                            key={tab.key}
                            className={`drift-tab ${statusFilter === tab.key ? "active" : ""}`}
                            onClick={() => setStatusFilter(tab.key)}
                        >
                            {tab.label}
                        </button>
                    ))}
                </div>
                <div className="drift-toolbar-actions">
                    {lastRun && (
                        <span className="drift-last-run">
                            Last run: {lastRun.status === "completed" ? `${lastRun.drift_found_count} drift found` : lastRun.status}
                        </span>
                    )}
                    <button className="drift-btn drift-btn-primary" onClick={() => setShowAnalyze(true)} disabled={isAnalyzing}>
                        <i className="fa-solid fa-magnifying-glass" /> {isAnalyzing ? "Analyzing…" : "Run Analysis"}
                    </button>
                </div>
            </div>

            {(error || successMessage) && (
                <div className={`drift-toast ${error ? "drift-toast-error" : "drift-toast-success"}`}>
                    {error || successMessage}
                </div>
            )}

            <div className="drift-table-container">
                {isLoading ? (
                    <div className="drift-empty">Loading drift results…</div>
                ) : sortedResults.length === 0 ? (
                    <div className="drift-empty">
                        No {statusFilter || ""} drift results. Click "Run Analysis" to compare a device's live
                        config against its last backup.
                    </div>
                ) : (
                    <table className="drift-table">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Asset</th>
                                <th>Technology</th>
                                <th>Lines changed</th>
                                <th>Found</th>
                                {statusFilter === "open" && <th>Actions</th>}
                            </tr>
                        </thead>
                        <tbody>
                            {sortedResults.map((r) => (
                                <tr key={r.id}>
                                    <td>
                                        <span className={`drift-badge ${SEVERITY_CLASS[r.severity] || ""}`}>{r.severity}</span>
                                    </td>
                                    <td className="drift-cell-strong">{r.asset_name || "—"}</td>
                                    <td>{r.technology || "—"}</td>
                                    <td>{r.lines_changed}</td>
                                    <td>{r.created_at ? new Date(r.created_at).toLocaleString() : "—"}</td>
                                    <td>
                                        <div className="drift-row-actions">
                                            <button className="drift-link-btn" onClick={() => handleView(r.id)}>
                                                View diff
                                            </button>
                                            {statusFilter === "open" && (
                                                <>
                                                    <button className="drift-link-btn" onClick={() => handleAccept(r.id)}>
                                                        Accept
                                                    </button>
                                                    <button
                                                        className="drift-link-btn drift-link-btn-muted"
                                                        onClick={() => setIgnoringId(r.id)}
                                                    >
                                                        Ignore
                                                    </button>
                                                </>
                                            )}
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {showAnalyze && (
                <div className="drift-modal-backdrop" onClick={() => setShowAnalyze(false)}>
                    <div className="drift-modal" onClick={(e) => e.stopPropagation()}>
                        <h3>Run drift analysis</h3>
                        <p className="drift-modal-hint">
                            Compares the device's live config against its most recent backup. Requires a backup to
                            already exist for the asset. Credentials are used once and never stored.
                        </p>
                        <div className="drift-field">
                            <label>Asset</label>
                            <select value={form.asset_id} onChange={(e) => setForm({ ...form, asset_id: e.target.value })}>
                                <option value="">— Select an asset —</option>
                                {assets.map((a) => (
                                    <option key={a.id} value={a.id}>{a.asset_name}</option>
                                ))}
                            </select>
                        </div>
                        <div className="drift-field">
                            <label>Username</label>
                            <input value={form.ssh_username} onChange={(e) => setForm({ ...form, ssh_username: e.target.value })} />
                        </div>
                        <div className="drift-field">
                            <label>Password</label>
                            <input type="password" value={form.ssh_password} onChange={(e) => setForm({ ...form, ssh_password: e.target.value })} />
                        </div>
                        <div className="drift-field">
                            <label>Enable secret (Cisco, optional)</label>
                            <input type="password" value={form.ssh_secret} onChange={(e) => setForm({ ...form, ssh_secret: e.target.value })} />
                        </div>
                        <div className="drift-field">
                            <label>Port</label>
                            <input type="number" value={form.ssh_port} onChange={(e) => setForm({ ...form, ssh_port: e.target.value })} />
                        </div>
                        <div className="drift-modal-actions">
                            <button className="drift-btn" onClick={() => setShowAnalyze(false)}>Cancel</button>
                            <button
                                className="drift-btn drift-btn-primary"
                                onClick={handleAnalyze}
                                disabled={!form.asset_id || !form.ssh_username || !form.ssh_password}
                            >
                                Analyze
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {ignoringId !== null && (
                <div className="drift-modal-backdrop" onClick={() => setIgnoringId(null)}>
                    <div className="drift-modal" onClick={(e) => e.stopPropagation()}>
                        <h3>Ignore drift result</h3>
                        <p className="drift-modal-hint">Optionally explain why this drift is expected/acceptable.</p>
                        <textarea
                            className="drift-modal-textarea"
                            rows={3}
                            value={ignoreReason}
                            onChange={(e) => setIgnoreReason(e.target.value)}
                            placeholder="Reason (optional)"
                        />
                        <div className="drift-modal-actions">
                            <button className="drift-btn" onClick={() => setIgnoringId(null)}>Cancel</button>
                            <button className="drift-btn drift-btn-primary" onClick={handleIgnoreConfirm}>
                                Ignore
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {viewingId !== null && (
                <div className="drift-modal-backdrop" onClick={() => setViewingId(null)}>
                    <div className="drift-modal drift-modal-wide" onClick={(e) => e.stopPropagation()}>
                        <h3>Configuration diff</h3>
                        {currentResult && currentResult.id === viewingId ? (
                            <pre className="drift-diff-pre">{currentResult.diff}</pre>
                        ) : (
                            <div className="drift-empty">Loading…</div>
                        )}
                        <div className="drift-modal-actions">
                            <button className="drift-btn" onClick={() => setViewingId(null)}>Close</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default DriftDashboard;
