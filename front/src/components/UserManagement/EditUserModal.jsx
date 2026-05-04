import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { updateUser, fetchUser } from "../../store/userSlice";

const MODULES = [
    { name: "dashboard", label: "Dashboard" },
    { name: "asset_requirement", label: "Asset Requirement" },
    { name: "asset_list", label: "Asset List" },
    { name: "asset_auto_discovery", label: "Auto Discovery" },
    { name: "user_management", label: "User Management" },
];

export const EditUserModal = ({ user, onClose }) => {
    const dispatch = useDispatch();
    const { username: authUsername } = useSelector((state) => state.auth);
    const isSelfEdit = authUsername === user.username;

    const [formData, setFormData] = useState({
        username: user.username,
        email: user.email,
        password: "",
        current_password: "",
        role: user.role,
        is_active: user.is_active,
    });

    const [permissions, setPermissions] = useState(
        MODULES.reduce((acc, module) => {
            acc[module.name] = { read: false, write: false, delete: false };
            return acc;
        }, {})
    );

    const [loadingPermissions, setLoadingPermissions] = useState(true);
    const [passwordError, setPasswordError] = useState(null);

    useEffect(() => {
        const loadUserPermissions = async () => {
            try {
                const result = await dispatch(fetchUser(user.id));
                if (result.payload?.permissions) {
                    const perms = {};
                    result.payload.permissions.forEach((perm) => {
                        perms[perm.module] = {
                            read: perm.can_read,
                            write: perm.can_write,
                            delete: perm.can_delete,
                        };
                    });
                    setPermissions(perms);
                }
            } catch (error) {
                console.error("Failed to load permissions:", error);
            } finally {
                setLoadingPermissions(false);
            }
        };

        loadUserPermissions();
    }, [dispatch, user.id]);

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value,
        });
        if (e.target.name === "current_password") {
            setPasswordError(null);
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
        setFormData({
            ...formData,
            is_active: !formData.is_active,
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setPasswordError(null);

        const updateData = {};
        if (formData.username !== user.username) updateData.username = formData.username;
        if (formData.email !== user.email) updateData.email = formData.email;
        if (formData.role !== user.role) updateData.role = formData.role;
        if (formData.is_active !== user.is_active) updateData.is_active = formData.is_active;

        if (formData.password) {
            updateData.password = formData.password;
            if (isSelfEdit) {
                updateData.current_password = formData.current_password;
            }
        }

        const permissionsArray = Object.keys(permissions).map((module) => ({
            module: module,
            can_read: permissions[module].read,
            can_write: permissions[module].write,
            can_delete: permissions[module].delete,
        }));
        updateData.permissions = permissionsArray;

        const result = await dispatch(updateUser({ userId: user.id, userData: updateData }));

        if (result.error) {
            const msg = result.payload;
            if (msg?.includes("Current password is required") || msg?.includes("Current password is incorrect")) {
                setPasswordError(msg);
                setFormData({ ...formData, current_password: "" });
                return;
            }
        }

        onClose();
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content modal-large" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h3>Edit User</h3>
                    <button className="modal-close" onClick={onClose}>✕</button>
                </div>

                <form onSubmit={handleSubmit}>
                    <div className="modal-body">
                        <div className="form-row">
                            <div className="form-group">
                                <label>Username *</label>
                                <input
                                    type="text"
                                    name="username"
                                    value={formData.username}
                                    onChange={handleChange}
                                    required
                                    minLength={3}
                                />
                            </div>

                            <div className="form-group">
                                <label>Email *</label>
                                <input
                                    type="email"
                                    name="email"
                                    value={formData.email}
                                    onChange={handleChange}
                                    required
                                />
                            </div>
                        </div>

                        <div className="form-row">
                            <div className="form-group">
                                <label>Password (leave empty to keep current)</label>
                                <input
                                    type="password"
                                    name="password"
                                    value={formData.password}
                                    onChange={handleChange}
                                    placeholder="Enter new password"
                                />
                            </div>

                            <div className="form-group">
                                <label>Role *</label>
                                <select
                                    name="role"
                                    value={formData.role}
                                    onChange={handleChange}
                                >
                                    <option value="user">user</option>
                                    <option value="manager">manager</option>
                                    <option value="admin">admin</option>
                                    <option value="guest">guest</option>
                                </select>
                            </div>
                        </div>

                        {/* Current Password - فقط برای self edit */}
                        {isSelfEdit && formData.password && (
                            <div className="form-row">
                                <div className="form-group">
                                    <label>Current Password *</label>
                                    <input
                                        type="password"
                                        name="current_password"
                                        value={formData.current_password}
                                        onChange={handleChange}
                                        placeholder="Enter current password"
                                        required
                                    />
                                    {passwordError && (
                                        <div style={{ color: "#DC2626", fontSize: "13px", marginTop: "4px" }}>
                                            ⚠️ {passwordError}
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Active Status Toggle */}
                        <div className="form-row">
                            <div className="form-group">
                                <label>Status</label>
                                <div className="active-toggle-container">
                                    <button
                                        type="button"
                                        className={`active-toggle-btn ${formData.is_active ? 'active' : 'inactive'}`}
                                        onClick={handleActiveToggle}
                                    >
                                        <span className="toggle-label">
                                            {formData.is_active ? 'Active' : 'Inactive'}
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
                            <h4 className="permissions-title">Permissions</h4>
                            <p className="permissions-subtitle">Set access permissions for each module</p>

                            {loadingPermissions ? (
                                <div className="loading-permissions">Loading permissions...</div>
                            ) : (
                                <table className="permissions-table">
                                    <thead>
                                    <tr>
                                        <th>Module</th>
                                        <th>Read</th>
                                        <th>Write</th>
                                        <th>Delete</th>
                                    </tr>
                                    </thead>
                                    <tbody>
                                    {MODULES.map((module) => (
                                        <tr key={module.name}>
                                            <td className="module-name">{module.label}</td>
                                            <td>
                                                <input
                                                    type="checkbox"
                                                    checked={permissions[module.name]?.read || false}
                                                    onChange={() => handlePermissionChange(module.name, "read")}
                                                />
                                            </td>
                                            <td>
                                                <input
                                                    type="checkbox"
                                                    checked={permissions[module.name]?.write || false}
                                                    onChange={() => handlePermissionChange(module.name, "write")}
                                                />
                                            </td>
                                            <td>
                                                <input
                                                    type="checkbox"
                                                    checked={permissions[module.name]?.delete || false}
                                                    onChange={() => handlePermissionChange(module.name, "delete")}
                                                />
                                            </td>
                                        </tr>
                                    ))}
                                    </tbody>
                                </table>
                            )}
                        </div>
                    </div>

                    <div className="modal-actions">
                        <button type="button" className="btn-cancel" onClick={onClose}>
                            cancel
                        </button>
                        <button type="submit" className="btn-submit">
                            Update
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};