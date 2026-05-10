import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { updateUser, fetchUsers } from "../store/userSlice.jsx";

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
            title: "Password changed successfully",
        },
        error: {
            bg: "#fef2f2",
            border: "#fecaca",
            iconBg: "#fee2e2",
            iconColor: "#991b1b",
            titleColor: "#dc2626",
            icon: "✕",
            title: "Failed to change password",
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

export const ChangePasswordModal = ({ onClose }) => {
    const dispatch = useDispatch();
    const { username } = useSelector((state) => state.auth);
    const users = useSelector((state) => state.users.users);
    const currentUser = users.find(u => u.username === username);

    const [formData, setFormData] = useState({
        current_password: "",
        new_password: "",
        confirm_password: "",
    });

    const [errors, setErrors] = useState({});
    const [msgBox, setMsgBox] = useState({ type: "", message: "" });

    useEffect(() => {
        if (users.length === 0) {
            dispatch(fetchUsers());
        }
    }, []);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));
        if (errors[name]) setErrors((prev) => ({ ...prev, [name]: "" }));
    };

    const validate = () => {
        const newErrors = {};
        if (!formData.current_password) newErrors.current_password = "Required";
        if (formData.new_password.length < 8) newErrors.new_password = "At least 8 characters";
        if (formData.new_password !== formData.confirm_password) newErrors.confirm_password = "Passwords don't match";
        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setMsgBox({ type: "", message: "" });
        if (!validate()) return;

        if (!currentUser?.id) {
            setMsgBox({ type: "error", message: "User not found. Please refresh the page." });
            return;
        }

        const result = await dispatch(updateUser({
            userId: currentUser.id,
            userData: {
                password: formData.new_password,
                current_password: formData.current_password,
            },
        }));

        if (result.meta.requestStatus === "fulfilled") {
            setMsgBox({ type: "success", message: "Your password has been updated. Use your new password next time you log in." });
            setTimeout(onClose, 2500);
        } else {
            setMsgBox({ type: "error", message: result.payload || "Something went wrong. Please try again." });
        }
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>Change Password</h2>
                    <button className="modal-close" onClick={onClose}>✕</button>
                </div>

                <form onSubmit={handleSubmit} className="modal-body">
                    <MessageBox
                        type={msgBox.type}
                        message={msgBox.message}
                        onClose={() => setMsgBox({ type: "", message: "" })}
                    />

                    <div className="form-group">
                        <label>Current Password</label>
                        <input
                            type="password"
                            name="current_password"
                            value={formData.current_password}
                            onChange={handleChange}
                            placeholder="Enter current password"
                            className={errors.current_password ? "error" : ""}
                        />
                        {errors.current_password && (
                            <span className="error-message">{errors.current_password}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>New Password</label>
                        <input
                            type="password"
                            name="new_password"
                            value={formData.new_password}
                            onChange={handleChange}
                            placeholder="Enter new password"
                            className={errors.new_password ? "error" : ""}
                        />
                        {errors.new_password && (
                            <span className="error-message">{errors.new_password}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>Confirm New Password</label>
                        <input
                            type="password"
                            name="confirm_password"
                            value={formData.confirm_password}
                            onChange={handleChange}
                            placeholder="Confirm new password"
                            className={errors.confirm_password ? "error" : ""}
                        />
                        {errors.confirm_password && (
                            <span className="error-message">{errors.confirm_password}</span>
                        )}
                    </div>

                    <div className="modal-footer">
                        <button type="button" className="btn-cancel" onClick={onClose}>Cancel</button>
                        <button type="submit" className="btn-submit">Change Password</button>
                    </div>
                </form>
            </div>
        </div>
    );
};