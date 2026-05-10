import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { updateUser, fetchUsers } from "../store/userSlice.jsx";

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
    const [submitError, setSubmitError] = useState("");

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
        setSubmitError("");
        if (!validate()) return;

        if (!currentUser?.id) {
            setSubmitError("User not found. Please refresh the page.");
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
            onClose();
        } else {
            setSubmitError(result.payload || "Failed to change password");
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
                    {submitError && (
                        <div style={{
                            color: "#EF4444",
                            background: "#FEF2F2",
                            border: "1px solid #FECACA",
                            borderRadius: "6px",
                            padding: "10px 14px",
                            fontSize: "13px",
                            marginBottom: "12px",
                        }}>
                            {submitError}
                        </div>
                    )}

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