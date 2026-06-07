import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAuditSessions, getDeviceName } from "../../store/hardeningSlice";

// ─── Component ────────────────────────────────────────────────────────────────

export const FixUnsuccessfulConnectionForm = ({ onSubmit, onCancel, preselectedSessionId, preselectedDeviceType }) => {
    const dispatch = useDispatch();
    const { auditSessions, isLoading } = useSelector((state) => state.hardening);

    const [formData, setFormData] = useState({ session_id: "" });

    const [selectedSession, setSelectedSession] = useState(null);
    const [deviceType, setDeviceType]           = useState(null);
    const [errors, setErrors]                   = useState({});

    useEffect(() => {
        dispatch(fetchAuditSessions());
    }, [dispatch]);

    // Auto-select session when opened from audit results
    useEffect(() => {
        if (!preselectedSessionId || !auditSessions?.length) return;
        const session = auditSessions.find(s => s.session_id === preselectedSessionId);
        if (!session) return;
        setFormData(prev => ({ ...prev, session_id: String(preselectedSessionId) }));
        setSelectedSession(session);
        setDeviceType(preselectedDeviceType || session.sub_device_type || session.device_type || null);
    }, [auditSessions, preselectedSessionId, preselectedDeviceType]);

    // Only sessions that are completed AND have failed checks
    const failedAuditSessions = (auditSessions || []).filter(
        (session) =>
            session.status === "completed" &&
            (
                (session.compliance?.failed_checks > 0) ||
                (session.compliance?.failed > 0)
            )
    );

    const getFailedCount = (session) =>
        session?.compliance?.failed_checks ||
        session?.compliance?.failed ||
        0;

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));

        if (name === "session_id") {
            if (value) {
                const session = failedAuditSessions.find(
                    (s) => s.session_id === parseInt(value)
                );
                setSelectedSession(session || null);
                setDeviceType(session?.sub_device_type || session?.device_type || null);
            } else {
                setSelectedSession(null);
                setDeviceType(null);
            }
        }

        if (errors[name]) {
            setErrors((prev) => { const n = { ...prev }; delete n[name]; return n; });
        }
    };

    const validate = () => {
        const errs = {};
        if (!formData.session_id) errs.session_id = "Please select an audit job";
        setErrors(errs);
        return Object.keys(errs).length === 0;
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!validate()) return;

        const sessionId = parseInt(formData.session_id);
        if (isNaN(sessionId) || !selectedSession) {
            setErrors({ session_id: "Please select a valid audit job" });
            return;
        }

        onSubmit({
            session_id: sessionId,
            session: { ...selectedSession, device_type: deviceType },
            device_type: deviceType,
        });
    };

    return (
        <div className="auditing-form-container">
            <form onSubmit={handleSubmit} className="auditing-form">
                <div className="form-grid-two-column">

                    {/* ── Audit Job Dropdown ───────────────────────────────── */}
                    <div className="form-group form-group-full">
                        <label htmlFor="session_id">
                            Audit Job Name
                            <span className="required" style={{ color: "#ef4444" }}>*</span>
                        </label>

                        {isLoading ? (
                            <div style={{
                                padding: "10px 14px",
                                background: "#f8f9fa",
                                border: "1px solid #d1d5db",
                                borderRadius: "6px",
                                fontSize: "13px",
                                color: "#6b7280",
                            }}>
                                Loading sessions…
                            </div>
                        ) : (
                            <select
                                id="session_id"
                                name="session_id"
                                value={formData.session_id}
                                onChange={handleChange}
                                className={errors.session_id ? "error" : ""}
                            >
                                <option value="">Select an audit job</option>
                                {failedAuditSessions.map((session) => (
                                    <option key={session.session_id} value={session.session_id}>
                                        {session.job_name || session.asset_name} | {session.target_ip} —{" "}
                                        {session.completed_at
                                            ? new Date(session.completed_at).toLocaleDateString()
                                            : session.started_at
                                                ? new Date(session.started_at).toLocaleDateString()
                                                : "N/A"
                                        }{" "}
                                        ({getFailedCount(session)} Failed)
                                    </option>
                                ))}
                            </select>
                        )}

                        {errors.session_id && (
                            <span className="error-message">{errors.session_id}</span>
                        )}

                        {!isLoading && failedAuditSessions.length === 0 && (
                            <div style={{
                                marginTop: "10px",
                                padding: "14px 16px",
                                background: "#fef3c7",
                                border: "1px solid #f59e0b",
                                borderRadius: "8px",
                            }}>
                                <p style={{ margin: "0 0 4px 0", fontWeight: "600", fontSize: "13px", color: "#92400e" }}>
                                    ⚠️ No failed audit sessions found
                                </p>
                                <p style={{ margin: 0, fontSize: "12px", color: "#78350f" }}>
                                    Please run an audit first. Only completed audits with failed checks appear here.
                                </p>
                            </div>
                        )}
                    </div>

                    {/* ── Session Info Box ─────────────────────────────────── */}
                    {selectedSession && (
                        <div className="form-group form-group-full" style={{
                            background: "#eff6ff",
                            borderLeft: "4px solid #3b82f6",
                            padding: "12px 16px",
                            borderRadius: "6px",
                        }}>
                            <p style={{ margin: "4px 0", fontSize: "13px", color: "#1f2937" }}>
                                <strong>Asset:</strong> {selectedSession.asset_name || "N/A"}
                            </p>
                            <p style={{ margin: "4px 0", fontSize: "13px", color: "#1f2937" }}>
                                <strong>IP Address:</strong> {selectedSession.target_ip || "N/A"}
                            </p>
                            <p style={{ margin: "4px 0", fontSize: "13px", color: "#1f2937" }}>
                                <strong>Device Type:</strong> {getDeviceName(deviceType)}
                            </p>
                            <p style={{ margin: "4px 0", fontSize: "13px", color: "#1f2937" }}>
                                <strong>Status:</strong> {selectedSession.status}
                            </p>
                            {selectedSession.compliance && (
                                <>
                                    <p style={{ margin: "4px 0", fontSize: "13px", color: "#1f2937" }}>
                                        <strong>Total Checks:</strong>{" "}
                                        {selectedSession.compliance.total_checks || selectedSession.compliance.total || 0}
                                    </p>
                                    <p style={{ margin: "4px 0", fontSize: "13px", color: "#dc2626" }}>
                                        <strong>Failed Checks:</strong> {getFailedCount(selectedSession)}
                                    </p>
                                    <p style={{ margin: "4px 0", fontSize: "13px", color: "#059669" }}>
                                        <strong>Passed Checks:</strong>{" "}
                                        {selectedSession.compliance.passed_checks || selectedSession.compliance.passed || 0}
                                    </p>
                                </>
                            )}
                        </div>
                    )}

                </div>

                {/* Actions */}
                <div className="form-actions">
                    <button
                        type="button"
                        onClick={onCancel}
                        className="btn-cancel"
                        disabled={isLoading}
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        className="btn-see-result"
                        disabled={isLoading || failedAuditSessions.length === 0}
                    >
                        Next
                    </button>
                </div>
            </form>
        </div>
    );
};

export default FixUnsuccessfulConnectionForm;
