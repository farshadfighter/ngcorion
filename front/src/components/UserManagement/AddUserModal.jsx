import { useState } from "react";
import { useDispatch } from "react-redux";
import { createUser, fetchUsers } from "../../store/userSlice";

const MODULES = [
    { name: "dashboard", label: "Dashboard" },
    { name: "asset_requirement", label: "Asset Requirement" },
    { name: "asset_list", label: "Asset List" },
    { name: "auto_discovery", label: "Auto Discovery" },
    { name: "user_management", label: "User Management" },
];

export const AddUserModal = ({ onClose }) => {
    const dispatch = useDispatch();
    const [formData, setFormData] = useState({
        username: "",
        email: "",
        password: "",
        role: "user",
    });

    const [permissions, setPermissions] = useState(
        MODULES.reduce((acc, module) => {
            acc[module.name] = { read: false, write: false, delete: false };
            return acc;
        }, {})
    );

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
        console.log("Submitting form data:", formData);

        // تبدیل permissions به فرمت API
        const permissionsArray = Object.keys(permissions).map((module) => ({
            module: module,
            can_read: permissions[module].read,
            can_write: permissions[module].write,
            can_delete: permissions[module].delete,
        }));

        const userData = {
            ...formData,
            permissions: permissionsArray,
        };

        console.log("Creating user with permissions:", userData);

        const result = await dispatch(createUser(userData));

        if (result.type === "users/create/fulfilled") {
            console.log("User created! Refreshing list...");
            dispatch(fetchUsers());
            onClose();
        } else {
            console.error("Failed to create user:", result.payload);
        }
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content modal-large" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h3>Add User</h3>
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
                                    placeholder="Enter username"
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
                                    placeholder="Enter email"
                                />
                            </div>
                        </div>

                        <div className="form-row">
                            <div className="form-group">
                                <label>Password *</label>
                                <input
                                    type="password"
                                    name="password"
                                    value={formData.password}
                                    onChange={handleChange}
                                    required
                                    minLength={4}
                                    placeholder="Enter password"
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
                            cancel
                        </button>
                        <button type="submit" className="btn-submit">
                            Create
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};