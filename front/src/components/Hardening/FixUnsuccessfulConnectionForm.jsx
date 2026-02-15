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
        console.log("📄 Fetching audit sessions..."); // Debug
        dispatch(fetchAuditSessions());
    }, [dispatch]);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));

        // If session selected, save its details and extract device type
        if (name === "session_id" && value) {
            const session = auditSessions.find((s) => s.session_id === parseInt(value));
            console.log("📌 Selected session:", session); // Debug
            setSelectedSession(session);

            // ✅ AUTO-DETECT DEVICE TYPE from session
            if (session?.device_type) {
                setDeviceType(session.device_type);
                console.log("🎯 Device type detected:", session.device_type); // Debug
            }
        }

        // Clear error
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

        console.log("🚀 Form submitted"); // Debug

        if (!validate()) {
            console.log("❌ Validation failed:", errors); // Debug
            return;
        }

        const sessionId = parseInt(formData.session_id);
        if (isNaN(sessionId) || !selectedSession) {
            setErrors({ session_id: "Please select a valid audit job" });
            console.log("❌ Invalid session ID"); // Debug
            return;
        }

        // Prepare credentials
        const credentials = {
            ssh_username: formData.ssh_username,
            ssh_password: formData.ssh_password,
        };

        // Add device-specific credentials
        if (deviceType === "cisco" && formData.ssh_secret) {
            credentials.ssh_secret = formData.ssh_secret;
        }
        if (deviceType === "fortinet" && formData.vdom) {
            credentials.vdom = formData.vdom;
        }
        if ((deviceType?.startsWith("linux-") || deviceType === "apache") && formData.sudo_password) {
            credentials.sudo_password = formData.sudo_password;
        }

        // Pass data to parent including device type
        const dataToSubmit = {
            session_id: sessionId,
            session: selectedSession,
            device_type: deviceType, // IMPORTANT: Include device type
            credentials
        };

        console.log("✅ Submitting data:", dataToSubmit); // Debug
        onSubmit(dataToSubmit);
    };

    // Helper function to get device name
    const getDeviceName = (deviceType) => {
        const names = {
            'cisco': 'Cisco Router/Switch',
            'fortinet': 'FortiGate Firewall',
            'linux-ubuntu-22.04': 'Ubuntu 22.04 LTS',
            'linux-ubuntu-24.04': 'Ubuntu 24.04 LTS',
            'linux-rocky-8': 'Rocky Linux 8',
            'apache': 'Apache Web Server'
        };
        return names[deviceType] || deviceType || 'Unknown';
    };

    // Filter only completed sessions
    const completedSessions = auditSessions?.filter(
        session => session.status === 'completed'
    ) || [];

    return (
        <div className="auditing-form-container">
            <form onSubmit={handleSubmit} className="auditing-form">
                <div className="form-grid-two-column">
                    {/* Session Selector */}
                    <div className="form-group form-group-full">
                        <label htmlFor="session_id">
                            Audit Job Name
                            <span className="required" style={{color: '#ef4444'}}>*</span>
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
                                <span>Loading sessions...</span>
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
                                {completedSessions.map((session) => (
                                    <option key={session.session_id} value={session.session_id}>
                                        {session.asset_name || session.target_ip} - {session.completed_at ? new Date(session.completed_at).toLocaleDateString() : 'N/A'}
                                    </option>
                                ))}
                            </select>
                        )}
                        {errors.session_id && (
                            <span className="error-message">{errors.session_id}</span>
                        )}
                    </div>

                    {/* Display selected session info */}
                    {selectedSession && (
                        <div className="form-group form-group-full" style={{
                            background: '#eff6ff',
                            borderLeft: '4px solid #3b82f6',
                            padding: '12px 16px',
                            borderRadius: '6px',
                            marginTop: '8px'
                        }}>
                            <p style={{margin: '4px 0', fontSize: '13px', color: '#1f2937'}}>
                                <strong>Device Type:</strong> {getDeviceName(deviceType)}
                            </p>
                            <p style={{margin: '4px 0', fontSize: '13px', color: '#1f2937'}}>
                                <strong>Device:</strong> {selectedSession.target_ip}
                            </p>
                            <p style={{margin: '4px 0', fontSize: '13px', color: '#1f2937'}}>
                                <strong>Type:</strong> {selectedSession.device_type || 'N/A'}
                            </p>
                            <p style={{margin: '4px 0', fontSize: '13px', color: '#1f2937'}}>
                                <strong>Status:</strong> {selectedSession.status}
                            </p>
                            {selectedSession.compliance && (
                                <p style={{margin: '4px 0', fontSize: '13px', color: '#1f2937'}}>
                                    <strong>Failed Checks:</strong> {selectedSession.compliance.failed || 0}
                                </p>
                            )}
                        </div>
                    )}

                    {/* SSH Username - Always visible */}
                    <div className="form-group">
                        <label htmlFor="ssh_username">
                            Username
                            <span className="required" style={{color: '#ef4444'}}>*</span>
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

                    {/* CISCO ONLY: Enable Password */}
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

                    {/* FORTINET ONLY: VDOM */}
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

                    {/* LINUX (ALL VARIANTS): Sudo Password */}
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

                    {/* APACHE: Sudo Password */}
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

                    {/* SSH Password - Always Last */}
                    <div className="form-group form-group-full">
                        <label htmlFor="ssh_password">
                            Password
                            <span className="required" style={{color: '#ef4444'}}>*</span>
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
                        disabled={isLoading}
                    >
                        Next
                    </button>
                </div>
            </form>
        </div>
    );
};

export default FixUnsuccessfulConnectionForm;