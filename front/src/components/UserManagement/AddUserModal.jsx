import { useState } from "react";
import { useDispatch } from "react-redux";
import { createUser, fetchUsers } from "../../store/userSlice";
import { PERMISSION_MODULES as MODULES } from "./permissionModules";
import { t } from "../../i18n";

const validatePassword = (password) => {
    if (password.length < 8) return t("At least 8 characters required");
    if (!/[A-Z]/.test(password)) return t("Must contain at least one uppercase letter");
    if (!/[a-z]/.test(password)) return t("Must contain at least one lowercase letter");
    if (!/[0-9]/.test(password)) return t("Must contain at least one number");
    if (!/[@$!%*?&_#]/.test(password)) return t("Must contain at least one special character (@$!%*?&_#)");
    return "";
};

export const AddUserModal = ({ onClose }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        username: "",
        email: "",
        phone: "",
        password: "",
        confirmPassword: "",
        role: "user",
        is_active: true,
    });

    const [permissions, setPermissions] = useState(
        MODULES.reduce((acc, module) => {
            acc[module.name] = { read: false, write: false, delete: false };
            return acc;
        }, {})
    );

    const [passwordError, setPasswordError] = useState("");
    const [submitError, setSubmitError] = useState("");

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
        if (e.target.name === "password") {
            setPasswordError(validatePassword(e.target.value));
        }
    };

    const handlePermissionChange = (moduleName, permissionType) => {
        setPermissions({
            ...permissions,
            [moduleName]: {
                ...permissions[moduleName],
                [permissionType]: !permissions[moduleName][permissionType],
            },
        });
    };

    const handleActiveToggle = () => {
        setFormData({ ...formData, is_active: !formData.is_active });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setSubmitError("");

        const pwdErr = validatePassword(formData.password);
        if (pwdErr) {
            setPasswordError(pwdErr);
            return;
        }

        if (formData.password !== formData.confirmPassword) {
            setPasswordError(t("Passwords do not match"));
            return;
        }

        const permissionsArray = Object.keys(permissions).map((module) => ({
            module: module,
            can_read: permissions[module].read,
            can_write: permissions[module].write,
            can_delete: permissions[module].delete,
        }));

        const userData = { ...formData, permissions: permissionsArray };
        const result = await dispatch(createUser(userData));

        if (result.type === "users/create/fulfilled") {
            dispatch(fetchUsers());
            onClose();
        } else {
            setSubmitError(result.payload || t("Failed to create user"));
        }
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content modal-large" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h3>{t("Add User")}</h3>
                    <button className="modal-close" onClick={onClose}>✕</button>
                </div>

                <form onSubmit={handleSubmit}>
                    <div className="modal-body">

                        {/* ارور کلی از بک‌اند */}
                        {submitError && (
                            <div style={{
                                color: "#EF4444",
                                backgroundColor: "#FEF2F2",
                                border: "1px solid #FECACA",
                                borderRadius: "6px",
                                padding: "10px 14px",
                                fontSize: "13px",
                                marginBottom: "12px",
                            }}>
                                {submitError}
                            </div>
                        )}

                        <div className="form-row">
                            <div className="form-group">
                                <label>{t("Username *")}</label>
                                <input
                                    type="text"
                                    name="username"
                                    value={formData.username}
                                    onChange={handleChange}
                                    required
                                    minLength={3}
                                    placeholder={t("Enter username")}
                                />
                            </div>

                            <div className="form-group">
                                <label>{t("Email *")}</label>
                                <input
                                    type="email"
                                    name="email"
                                    value={formData.email}
                                    onChange={handleChange}
                                    required
                                    placeholder={t("Enter email")}
                                />
                            </div>
                        </div>

                        <div className="form-row">
                            <div className="form-group">
                                <label>{t("Mobile number")}</label>
                                <input
                                    type="tel"
                                    name="phone"
                                    value={formData.phone}
                                    onChange={handleChange}
                                    inputMode="tel"
                                    maxLength={20}
                                    placeholder={t("For SMS alerts, e.g. 09121234567")}
                                />
                            </div>
                        </div>

                        <div className="form-row">
                            <div className="form-group">
                                <label>{t("Password *")}</label>
                                <input
                                    type="password"
                                    name="password"
                                    value={formData.password}
                                    onChange={handleChange}
                                    required
                                    placeholder={t("Enter password")}
                                />
                                {passwordError ? (
                                    <small style={{ color: "#EF4444", fontSize: "11px" }}>
                                        {passwordError}
                                    </small>
                                ) : (
                                    <small style={{ color: "#6B7280", fontSize: "11px" }}>
                                        {t("Min 8 chars, uppercase, lowercase, number, special (@$!%*?&_#)")}
                                    </small>
                                )}
                            </div>

                            <div className="form-group">
                                <label>{t("Confirm Password *")}</label>
                                <input
                                    type="password"
                                    name="confirmPassword"
                                    value={formData.confirmPassword}
                                    onChange={handleChange}
                                    required
                                    placeholder={t("Re-enter password")}
                                />
                            </div>
                        </div>

                        <div className="form-row">
                            <div className="form-group">
                                <label>{t("Role *")}</label>
                                <select
                                    name="role"
                                    value={formData.role}
                                    onChange={handleChange}
                                >
                                    <option value="user">{t("user")}</option>
                                    <option value="manager">{t("manager")}</option>
                                    <option value="admin">{t("admin")}</option>
                                    <option value="guest">{t("guest")}</option>
                                </select>
                            </div>
                        </div>

                        {/* Active Status Toggle */}
                        <div className="form-row">
                            <div className="form-group">
                                <label>{t("Status")}</label>
                                <div className="active-toggle-container">
                                    <button
                                        type="button"
                                        className={`active-toggle-btn ${formData.is_active ? 'active' : 'inactive'}`}
                                        onClick={handleActiveToggle}
                                    >
                                        <span className="toggle-label">
                                            {formData.is_active ? t("Active") : t("Inactive")}
                                        </span>
                                        <span className={`toggle-switch ${formData.is_active ? 'active' : 'inactive'}`}>
                                            <span className="toggle-slider"></span>
                                        </span>
                                    </button>
                                </div>
                            </div>
                        </div>

                        {/* Permissions Section */}
                        <div className="permissions-section">
                            <h4 className="permissions-title">{t("Permissions")}</h4>
                            <p className="permissions-subtitle">{t("Set access permissions for each module")}</p>

                            <table className="permissions-table">
                                <thead>
                                <tr>
                                    <th>{t("Module")}</th>
                                    <th>{t("Read")}</th>
                                    <th>{t("Write")}</th>
                                    <th>{t("Delete")}</th>
                                </tr>
                                </thead>
                                <tbody>
                                {MODULES.map((module) => (
                                    <tr key={module.name}>
                                        <td className="module-name">{module.label}</td>
                                        <td>
                                            <input
                                                type="checkbox"
                                                checked={permissions[module.name].read}
                                                onChange={() => handlePermissionChange(module.name, "read")}
                                            />
                                        </td>
                                        <td>
                                            <input
                                                type="checkbox"
                                                checked={permissions[module.name].write}
                                                onChange={() => handlePermissionChange(module.name, "write")}
                                            />
                                        </td>
                                        <td>
                                            <input
                                                type="checkbox"
                                                checked={permissions[module.name].delete}
                                                onChange={() => handlePermissionChange(module.name, "delete")}
                                            />
                                        </td>
                                    </tr>
                                ))}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div className="modal-actions">
                        <button type="button" className="btn-cancel" onClick={onClose}>
                            {t("Cancel")}
                        </button>
                        <button type="submit" className="btn-submit">
                            {t("Create")}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};