import { useState } from "react";
import { useDispatch } from "react-redux";
import api from "../config/api";
import { passwordChanged } from "../store/authSlice";
import { t } from "../i18n";
import { tb } from "../i18n/backendText";

const MessageBox = ({ type, message, onClose }) => {
    if (!message) return null;

    const config = {
        success: {
            bg: "#f0fdf4",
            border: "#bbf7d0",
            iconBg: "#d1fae5",
            iconColor: "#065f46",
            titleColor: "#15803d",
            icon: "✓",
            title: t("Password changed successfully"),
        },
        error: {
            bg: "#fef2f2",
            border: "#fecaca",
            iconBg: "#fee2e2",
            iconColor: "#991b1b",
            titleColor: "#dc2626",
            icon: "✕",
            title: t("Failed to change password"),
        },
    };

    const c = config[type];

    return (
        <div style={{
            background: c.bg,
            border: `1px solid ${c.border}`,
            borderRadius: "12px",
            padding: "14px 16px",
            marginBottom: "16px",
            display: "flex",
            alignItems: "flex-start",
            gap: "12px",
        }}>
            <div style={{
                width: 36, height: 36, borderRadius: "50%",
                background: c.iconBg, color: c.iconColor,
                display: "flex", alignItems: "center",
                justifyContent: "center", fontWeight: 600, fontSize: 16,
                flexShrink: 0,
            }}>
                {c.icon}
            </div>
            <div style={{ flex: 1 }}>
                <p style={{ margin: "0 0 3px", fontWeight: 500, fontSize: 14, color: c.titleColor }}>{c.title}</p>
                <p style={{ margin: 0, fontSize: 13, color: "#6b7280", lineHeight: 1.5 }}>{message}</p>
            </div>
            <button
                onClick={onClose}
                style={{
                    background: "none", border: "none", cursor: "pointer",
                    opacity: 0.4, fontSize: 16, padding: "2px 4px", lineHeight: 1,
                }}
            >
                ✕
            </button>
        </div>
    );
};

/**
 * The signed-in user changes their own password (PUT /auth/me/password; no
 * user-management permission needed). With `forced`, the password was chosen
 * by someone else: the dialog cannot be dismissed, and after the change the
 * session continues with the fresh token the server returns.
 */
export const ChangePasswordModal = ({ onClose, forced = false }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        current_password: "",
        new_password: "",
        confirm_password: "",
    });

    const [errors, setErrors] = useState({});
    const [msgBox, setMsgBox] = useState({ type: "", message: "" });
    const [busy, setBusy] = useState(false);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));
        if (errors[name]) setErrors((prev) => ({ ...prev, [name]: "" }));
    };

    const validate = () => {
        const newErrors = {};
        if (!formData.current_password) newErrors.current_password = t("Required");
        if (formData.new_password.length < 8) newErrors.new_password = t("At least 8 characters");
        if (formData.new_password !== formData.confirm_password) newErrors.confirm_password = t("Passwords don't match");
        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setMsgBox({ type: "", message: "" });
        if (!validate()) return;
        setBusy(true);
        try {
            const { data } = await api.put("/auth/me/password", {
                current_password: formData.current_password,
                new_password: formData.new_password,
            });
            dispatch(passwordChanged(data));
            setMsgBox({ type: "success", message: t("Your password has been updated. Use your new password next time you log in.") });
            setTimeout(onClose, forced ? 1200 : 2500);
        } catch (err) {
            const detail = err.response?.data?.detail;
            const message = typeof detail === "string" ? tb(detail)
                : Array.isArray(detail) ? detail.map((d) => tb(String(d.msg || "").replace(/^Value error, /, ""))).join(" ")
                : t("Something went wrong. Please try again.");
            setMsgBox({ type: "error", message });
        } finally {
            setBusy(false);
        }
    };

    const close = forced ? undefined : onClose;

    return (
        <div className="modal-overlay" onClick={close}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>{forced ? t("Choose your own password") : t("Change Password")}</h2>
                    {!forced && <button className="modal-close" onClick={onClose}>✕</button>}
                </div>

                <form onSubmit={handleSubmit} className="modal-body">
                    <MessageBox
                        type={msgBox.type}
                        message={msgBox.message}
                        onClose={() => setMsgBox({ type: "", message: "" })}
                    />
                    {forced && (
                        <p style={{ margin: "0 0 16px", fontSize: 13, color: "#4b5563", lineHeight: 1.6 }}>
                            {t("Your password was set by an administrator. Choose your own password to continue.")}
                        </p>
                    )}

                    <div className="form-group">
                        <label>{t("Current Password")}</label>
                        <input
                            type="password"
                            name="current_password"
                            value={formData.current_password}
                            onChange={handleChange}
                            placeholder={t("Enter current password")}
                            className={errors.current_password ? "error" : ""}
                        />
                        {errors.current_password && (
                            <span className="error-message">{errors.current_password}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>{t("New Password")}</label>
                        <input
                            type="password"
                            name="new_password"
                            value={formData.new_password}
                            onChange={handleChange}
                            placeholder={t("Enter new password")}
                            className={errors.new_password ? "error" : ""}
                        />
                        {errors.new_password && (
                            <span className="error-message">{errors.new_password}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>{t("Confirm New Password")}</label>
                        <input
                            type="password"
                            name="confirm_password"
                            value={formData.confirm_password}
                            onChange={handleChange}
                            placeholder={t("Confirm new password")}
                            className={errors.confirm_password ? "error" : ""}
                        />
                        {errors.confirm_password && (
                            <span className="error-message">{errors.confirm_password}</span>
                        )}
                    </div>

                    <div className="modal-footer">
                        {!forced && <button type="button" className="btn-cancel" onClick={onClose}>{t("Cancel")}</button>}
                        <button type="submit" className="btn-submit" disabled={busy}>{t("Change Password")}</button>
                    </div>
                </form>
            </div>
        </div>
    );
};