import { useState, useEffect } from "react";
import { useDispatch } from "react-redux";
import { updateUser, fetchUser } from "../../store/userSlice";

const MODULES = [
    { name: "dashboard", label: "Dashboard" },
    { name: "asset_requirement", label: "Asset Requirement" },
    { name: "asset_list", label: "Asset List" },
    { name: "auto_discovery", label: "Auto Discovery" },
    { name: "user_management", label: "User Management" },
];

export const EditUserModal = ({ user, onClose }) => {
    const dispatch = useDispatch();
    const [formData, setFormData] = useState({
        username: user.username,
        email: user.email,
        password: "",
        role: user.role,
    });

    const [permissions, setPermissions] = useState(
        MODULES.reduce((acc, module) => {
            acc[module.name] = { read: false, write: false, delete: false };
            return acc;
        }, {})
    );

    const [loadingPermissions, setLoadingPermissions] = useState(true);

    // بارگذاری permissions کاربر
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

    const handleSubmit = async (e) => {
        e.preventDefault();

        const updateData = {};
        if (formData.username !== user.username) updateData.username = formData.username;
        if (formData.email !== user.email) updateData.email = formData.email;
        if (formData.password) updateData.password = formData.password;
        if (formData.role !== user.role) updateData.role = formData.role;

        // اضافه کردن permissions
        const permissionsArray = Object.keys(permissions).map((module) => ({
            module: module,
            can_read: permissions[module].read,
            can_write: permissions[module].write,
            can_delete: permissions[module].delete,
        }));
        updateData.permissions = permissionsArray;

        await dispatch(updateUser({ userId: user.id, userData: updateData }));
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