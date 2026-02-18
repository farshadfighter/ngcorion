import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAuditSessions } from "../../store/hardeningSlice";

export const FixUnsuccessfulConnectionForm = ({ onSubmit, onCancel }) => {
    const dispatch = useDispatch();
    const { auditSessions, isLoading } = useSelector((state) => state.hardening);

    const [formData, setFormData] = useState({
        session_id: "",
        ssh_username: "",
        ssh_password: "",
        ssh_secret: "",      // Cisco only
        vdom: "",            // Fortinet only
        sudo_password: "",   // Linux/Apache only
    });

    const [selectedSession, setSelectedSession] = useState(null);
    const [deviceType, setDeviceType] = useState(null);
    const [errors, setErrors] = useState({});

    useEffect(() => {
        dispatch(fetchAuditSessions());
    }, [dispatch]);

    // ✅ فقط session هایی که completed هستن و failed checks دارن
    const failedAuditSessions = auditSessions?.filter(session =>
        session.status === 'completed' &&
        (
            (session.compliance?.failed_checks > 0) ||
            (session.compliance?.failed > 0)
        )
    ) || [];

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));

        // اگه session انتخاب شد، اطلاعاتش رو استخراج کن
        if (name === "session_id" && value) {
            const session = failedAuditSessions.find(
                (s) => s.session_id === parseInt(value)
            );
            setSelectedSession(session || null);

            if (session?.device_type) {
                setDeviceType(session.device_type);
            } else {
                setDeviceType(null);
            }
        }

        // اگه session پاک شد، اطلاعات انتخابی رو هم پاک کن
        if (name === "session_id" && !value) {
            setSelectedSession(null);
            setDeviceType(null);
        }

        // پاک کردن error مربوطه
        if (errors[name]) {
            setErrors((prev) => {
                const newErrors = { ...prev };
                delete newErrors[name];
                return newErrors;
            });
        }
    };

    const validate = () => {
        const newErrors = {};

        if (!formData.session_id) {
            newErrors.session_id = "Please select an audit job";
        }
        if (!formData.ssh_username || formData.ssh_username.trim().length < 1) {
            newErrors.ssh_username = "Username is required";
        }
        if (!formData.ssh_password || formData.ssh_password.trim().length < 1) {
            newErrors.ssh_password = "Password is required";
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = (e) => {
        e.preventDefault();

        if (!validate()) return;

        const sessionId = parseInt(formData.session_id);
        if (isNaN(sessionId) || !selectedSession) {
            setErrors({ session_id: "Please select a valid audit job" });
            return;
        }

        // آماده‌سازی credentials
        const credentials = {
            ssh_username: formData.ssh_username,
            ssh_password: formData.ssh_password,
        };

        // اضافه کردن credentials مخصوص device type
        if (deviceType === "cisco" && formData.ssh_secret) {
            credentials.ssh_secret = formData.ssh_secret;
        }
        if (deviceType === "fortinet" && formData.vdom) {
            credentials.vdom = formData.vdom;
        }
        if ((deviceType?.startsWith("linux-") || deviceType === "apache") && formData.sudo_password) {
            credentials.sudo_password = formData.sudo_password;
        }

        // ارسال داده به والد
        onSubmit({
            session_id: sessionId,
            session: {
                ...selectedSession,
                device_type: deviceType,
            },
            device_type: deviceType,
            credentials,
        });
    };

    // تبدیل device type به نام قابل خواندن
    const getDeviceName = (type) => {
        const names = {
            'cisco': 'Cisco Router/Switch',
            'fortinet': 'FortiGate Firewall',
            'linux-ubuntu-22.04': 'Ubuntu 22.04 LTS',
            'linux-ubuntu-24.04': 'Ubuntu 24.04 LTS',
            'linux-rocky-8': 'Rocky Linux 8',
            'apache': 'Apache Web Server',
        };
        return names[type] || type || 'Unknown';
    };

    // تعداد failed checks
    const getFailedCount = (session) => {
        return session?.compliance?.failed_checks ||
            session?.compliance?.failed ||
            0;
    };

    return (
        <div className="auditing-form-container">
            <form onSubmit={handleSubmit} className="auditing-form">
                <div className="form-grid-two-column">

                    {/* ── Audit Job Dropdown ── */}
                    <div className="form-group form-group-full">
                        <label htmlFor="session_id">
                            Audit Job Name
                            <span className="required" style={{ color: '#ef4444' }}>*</span>
                        </label>

                        {isLoading ? (
                            <div style={{
                                padding: '10px 14px',
                                background: '#f8f9fa',
                                border: '1px solid #d1d5db',
                                borderRadius: '6px',
                                fontSize: '13px',
                                color: '#6b7280'
                            }}>
                                Loading sessions...
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
                                    <option
                                        key={session.session_id}
                                        value={session.session_id}
                                    >
                                        {session.job_name || session.asset_name} | {session.target_ip} —{" "}
                                        {session.completed_at
                                            ? new Date(session.completed_at).toLocaleDateString()
                                            : session.started_at
                                                ? new Date(session.started_at).toLocaleDateString()
                                                : 'N/A'
                                        } ({getFailedCount(session)} Failed)
                                    </option>
                                ))}
                            </select>
                        )}

                        {errors.session_id && (
                            <span className="error-message">{errors.session_id}</span>
                        )}

                        {/* ✅ Empty State - هیچ session ناموفقی وجود ندارد */}
                        {!isLoading && failedAuditSessions.length === 0 && (
                            <div style={{
                                marginTop: '10px',
                                padding: '14px 16px',
                                background: '#fef3c7',
                                border: '1px solid #f59e0b',
                                borderRadius: '8px',
                            }}>
                                <p style={{
                                    margin: '0 0 4px 0',
                                    fontWeight: '600',
                                    fontSize: '13px',
                                    color: '#92400e'
                                }}>
                                    ⚠️ No failed audit sessions found
                                </p>
                                <p style={{
                                    margin: 0,
                                    fontSize: '12px',
                                    color: '#78350f'
                                }}>
                                    Please run an audit first. Only completed audits with failed checks appear here.
                                </p>
                            </div>
                        )}
                    </div>

                    {/* ── Session Info Box ── */}
                    {selectedSession && (
                        <div className="form-group form-group-full" style={{
                            background: '#eff6ff',
                            borderLeft: '4px solid #3b82f6',
                            padding: '12px 16px',
                            borderRadius: '6px',
                        }}>
                            <p style={{ margin: '4px 0', fontSize: '13px', color: '#1f2937' }}>
                                <strong>Asset:</strong> {selectedSession.asset_name || 'N/A'}
                            </p>
                            <p style={{ margin: '4px 0', fontSize: '13px', color: '#1f2937' }}>
                                <strong>IP Address:</strong> {selectedSession.target_ip || 'N/A'}
                            </p>
                            <p style={{ margin: '4px 0', fontSize: '13px', color: '#1f2937' }}>
                                <strong>Device Type:</strong> {getDeviceName(deviceType)}
                            </p>
                            <p style={{ margin: '4px 0', fontSize: '13px', color: '#1f2937' }}>
                                <strong>Status:</strong> {selectedSession.status}
                            </p>
                            {selectedSession.compliance && (
                                <>
                                    <p style={{ margin: '4px 0', fontSize: '13px', color: '#1f2937' }}>
                                        <strong>Total Checks:</strong> {selectedSession.compliance.total_checks || selectedSession.compliance.total || 0}
                                    </p>
                                    <p style={{ margin: '4px 0', fontSize: '13px', color: '#dc2626' }}>
                                        <strong>Failed Checks:</strong> {getFailedCount(selectedSession)}
                                    </p>
                                    <p style={{ margin: '4px 0', fontSize: '13px', color: '#059669' }}>
                                        <strong>Passed Checks:</strong> {selectedSession.compliance.passed_checks || selectedSession.compliance.passed || 0}
                                    </p>
                                </>
                            )}
                        </div>
                    )}

                    {/* ── SSH Username ── */}
                    <div className="form-group">
                        <label htmlFor="ssh_username">
                            Username
                            <span className="required" style={{ color: '#ef4444' }}>*</span>
                        </label>
                        <input
                            id="ssh_username"
                            type="text"
                            name="ssh_username"
                            value={formData.ssh_username}
                            onChange={handleChange}
                            placeholder="Enter SSH username"
                            className={errors.ssh_username ? "error" : ""}
                            autoComplete="username"
                        />
                        {errors.ssh_username && (
                            <span className="error-message">{errors.ssh_username}</span>
                        )}
                    </div>

                    {/* ── CISCO ONLY: Enable Password ── */}
                    {deviceType === "cisco" && (
                        <div className="form-group">
                            <label htmlFor="ssh_secret">Enable Password</label>
                            <input
                                id="ssh_secret"
                                type="password"
                                name="ssh_secret"
                                value={formData.ssh_secret}
                                onChange={handleChange}
                                placeholder="Enter enable secret (optional)"
                                autoComplete="off"
                            />
                            <span style={{
                                fontSize: '12px',
                                color: '#6b7280',
                                display: 'block',
                                marginTop: '4px'
                            }}>
                                Required for privileged commands
                            </span>
                        </div>
                    )}

                    {/* ── FORTINET ONLY: VDOM ── */}
                    {deviceType === "fortinet" && (
                        <div className="form-group">
                            <label htmlFor="vdom">VDOM</label>
                            <input
                                id="vdom"
                                type="text"
                                name="vdom"
                                value={formData.vdom}
                                onChange={handleChange}
                                placeholder="Virtual Domain (optional, default: root)"
                                autoComplete="off"
                            />
                            <span style={{
                                fontSize: '12px',
                                color: '#6b7280',
                                display: 'block',
                                marginTop: '4px'
                            }}>
                                Leave empty for default VDOM
                            </span>
                        </div>
                    )}

                    {/* ── LINUX ALL VARIANTS: Sudo Password ── */}
                    {deviceType?.startsWith("linux-") && (
                        <div className="form-group">
                            <label htmlFor="sudo_password">Sudo Password</label>
                            <input
                                id="sudo_password"
                                type="password"
                                name="sudo_password"
                                value={formData.sudo_password}
                                onChange={handleChange}
                                placeholder="Sudo password (optional)"
                                autoComplete="off"
                            />
                            <span style={{
                                fontSize: '12px',
                                color: '#6b7280',
                                display: 'block',
                                marginTop: '4px'
                            }}>
                                Required for root access (defaults to SSH password)
                            </span>
                        </div>
                    )}

                    {/* ── APACHE: Sudo Password ── */}
                    {deviceType === "apache" && (
                        <div className="form-group">
                            <label htmlFor="sudo_password">Sudo Password</label>
                            <input
                                id="sudo_password"
                                type="password"
                                name="sudo_password"
                                value={formData.sudo_password}
                                onChange={handleChange}
                                placeholder="Sudo password (optional)"
                                autoComplete="off"
                            />
                            <span style={{
                                fontSize: '12px',
                                color: '#6b7280',
                                display: 'block',
                                marginTop: '4px'
                            }}>
                                Required for root access (defaults to SSH password)
                            </span>
                        </div>
                    )}

                    {/* ── SSH Password - Always Last ── */}
                    <div className="form-group form-group-full">
                        <label htmlFor="ssh_password">
                            Password
                            <span className="required" style={{ color: '#ef4444' }}>*</span>
                        </label>
                        <input
                            id="ssh_password"
                            type="password"
                            name="ssh_password"
                            value={formData.ssh_password}
                            onChange={handleChange}
                            placeholder="Enter SSH password"
                            className={errors.ssh_password ? "error" : ""}
                            autoComplete="current-password"
                        />
                        {errors.ssh_password && (
                            <span className="error-message">{errors.ssh_password}</span>
                        )}
                    </div>

                </div>

                {/* ── Actions ── */}
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
