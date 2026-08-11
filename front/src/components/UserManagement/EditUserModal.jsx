import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { updateUser, fetchUser } from "../../store/userSlice";
import { PERMISSION_MODULES as MODULES } from "./permissionModules";

const styles = {
    overlay: {
        position: "fixed",
        inset: 0,
        background: "rgba(10, 20, 40, 0.55)",
        backdropFilter: "blur(3px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
        padding: "20px",
    },
    modal: {
        width: "100%",
        maxWidth: "780px",
        maxHeight: "92vh",
        overflowY: "auto",
        background: "#ffffff",
        borderRadius: "20px",
        boxShadow: "0 24px 60px rgba(10,20,40,0.18), 0 4px 16px rgba(10,20,40,0.08)",
        fontFamily: "'DM Sans', 'Segoe UI', sans-serif",
    },
    header: {
        padding: "24px 32px 20px",
        borderBottom: "1px solid #eef1f6",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        background: "linear-gradient(135deg, #1e3a5f 0%, #2d5490 100%)",
        borderRadius: "20px 20px 0 0",
    },
    headerLeft: {
        display: "flex",
        alignItems: "center",
        gap: "12px",
    },
    headerAvatar: {
        width: "42px",
        height: "42px",
        borderRadius: "12px",
        background: "rgba(255,255,255,0.15)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontSize: "18px",
        color: "white",
        fontWeight: 600,
        border: "1px solid rgba(255,255,255,0.2)",
    },
    headerTitle: {
        margin: 0,
        fontSize: "17px",
        fontWeight: 600,
        color: "#ffffff",
        letterSpacing: "-0.2px",
    },
    headerSub: {
        fontSize: "12px",
        color: "rgba(255,255,255,0.65)",
        marginTop: "2px",
    },
    closeBtn: {
        background: "rgba(255,255,255,0.12)",
        border: "1px solid rgba(255,255,255,0.2)",
        color: "rgba(255,255,255,0.8)",
        width: "32px",
        height: "32px",
        borderRadius: "8px",
        cursor: "pointer",
        fontSize: "14px",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        transition: "all 0.15s",
    },
    body: {
        padding: "28px 32px 20px",
    },
    sectionLabel: {
        fontSize: "11px",
        fontWeight: 700,
        color: "#1e3a5f",
        letterSpacing: "0.8px",
        textTransform: "uppercase",
        marginBottom: "16px",
        display: "flex",
        alignItems: "center",
        gap: "8px",
    },
    sectionLine: {
        flex: 1,
        height: "1px",
        background: "linear-gradient(to right, #dce6f5, transparent)",
    },
    formRow: {
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        gap: "18px",
        marginBottom: "18px",
    },
    formGroup: {
        display: "flex",
        flexDirection: "column",
    },
    label: {
        fontSize: "12px",
        fontWeight: 600,
        color: "#374151",
        marginBottom: "6px",
        letterSpacing: "0.1px",
    },
    input: {
        padding: "10px 14px",
        borderRadius: "10px",
        border: "1.5px solid #e2e8f0",
        fontSize: "14px",
        color: "#1a2332",
        background: "#f8fafd",
        transition: "all 0.2s",
        outline: "none",
        width: "100%",
        boxSizing: "border-box",
    },
    inputFocus: {
        border: "1.5px solid #1e3a5f",
        background: "#ffffff",
        boxShadow: "0 0 0 3px rgba(30,58,95,0.1)",
    },
    inputError: {
        border: "1.5px solid #ef4444",
        background: "#fff8f8",
        boxShadow: "0 0 0 3px rgba(239,68,68,0.08)",
    },
    select: {
        padding: "10px 14px",
        borderRadius: "10px",
        border: "1.5px solid #e2e8f0",
        fontSize: "14px",
        color: "#1a2332",
        background: "#f8fafd",
        transition: "all 0.2s",
        outline: "none",
        width: "100%",
        boxSizing: "border-box",
        cursor: "pointer",
        appearance: "none",
        backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%231e3a5f' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E")`,
        backgroundRepeat: "no-repeat",
        backgroundPosition: "right 14px center",
        paddingRight: "36px",
    },
    errorText: {
        fontSize: "12px",
        color: "#ef4444",
        marginTop: "5px",
        display: "flex",
        alignItems: "center",
        gap: "4px",
    },
    passwordWarning: {
        background: "linear-gradient(135deg, #fff8f0, #fff3e8)",
        border: "1.5px solid #fed7aa",
        borderRadius: "12px",
        padding: "14px 16px",
        marginBottom: "18px",
        display: "flex",
        alignItems: "flex-start",
        gap: "10px",
    },
    warningIcon: {
        fontSize: "18px",
        flexShrink: 0,
        marginTop: "1px",
    },
    warningText: {
        fontSize: "13px",
        color: "#92400e",
        lineHeight: 1.5,
    },
    divider: {
        height: "1px",
        background: "#eef1f6",
        margin: "22px 0",
    },
    statusToggle: {
        display: "inline-flex",
        alignItems: "center",
        gap: "10px",
        padding: "8px 14px",
        borderRadius: "10px",
        border: "1.5px solid",
        cursor: "pointer",
        transition: "all 0.2s",
        fontSize: "13px",
        fontWeight: 600,
        background: "none",
    },
    track: {
        width: "38px",
        height: "20px",
        borderRadius: "20px",
        position: "relative",
        transition: "background 0.25s",
        flexShrink: 0,
    },
    thumb: {
        position: "absolute",
        top: "2px",
        width: "16px",
        height: "16px",
        borderRadius: "50%",
        background: "white",
        transition: "transform 0.25s",
        boxShadow: "0 1px 4px rgba(0,0,0,0.2)",
    },
    permissionsSection: {
        marginTop: "4px",
    },
    permTable: {
        width: "100%",
        borderCollapse: "separate",
        borderSpacing: 0,
        fontSize: "13px",
        border: "1.5px solid #e2e8f0",
        borderRadius: "12px",
        overflow: "hidden",
    },
    permThead: {
        background: "linear-gradient(135deg, #1e3a5f, #2d5490)",
    },
    permTh: {
        padding: "11px 16px",
        textAlign: "left",
        color: "rgba(255,255,255,0.9)",
        fontSize: "11px",
        fontWeight: 700,
        letterSpacing: "0.5px",
        textTransform: "uppercase",
    },
    permTd: {
        padding: "10px 16px",
        borderBottom: "1px solid #eef1f6",
        color: "#374151",
    },
    permCheckbox: {
        width: "17px",
        height: "17px",
        accentColor: "#1e3a5f",
        cursor: "pointer",
    },
    moduleName: {
        fontWeight: 500,
        color: "#1a2332",
        fontSize: "13px",
    },
    footer: {
        padding: "18px 32px 24px",
        borderTop: "1px solid #eef1f6",
        display: "flex",
        justifyContent: "flex-end",
        gap: "10px",
    },
    btnCancel: {
        padding: "9px 22px",
        borderRadius: "10px",
        border: "1.5px solid #e2e8f0",
        background: "#f8fafd",
        color: "#374151",
        fontSize: "14px",
        fontWeight: 500,
        cursor: "pointer",
        transition: "all 0.15s",
    },
    btnSubmit: {
        padding: "9px 26px",
        borderRadius: "10px",
        border: "none",
        background: "linear-gradient(135deg, #1e3a5f, #2d5490)",
        color: "white",
        fontSize: "14px",
        fontWeight: 600,
        cursor: "pointer",
        transition: "all 0.15s",
        boxShadow: "0 4px 12px rgba(30,58,95,0.3)",
    },
    loadingBox: {
        textAlign: "center",
        padding: "24px",
        color: "#6b7280",
        fontSize: "13px",
    },
};

const FocusInput = ({ style, errorStyle, hasError, ...props }) => {
    const [focused, setFocused] = useState(false);
    return (
        <input
            {...props}
            style={{
                ...style,
                ...(focused ? styles.inputFocus : {}),
                ...(hasError ? styles.inputError : {}),
            }}
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
        />
    );
};

const FocusSelect = ({ ...props }) => {
    const [focused, setFocused] = useState(false);
    return (
        <select
            {...props}
            style={{
                ...styles.select,
                ...(focused ? styles.inputFocus : {}),
            }}
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
        />
    );
};

export const EditUserModal = ({ user, onClose }) => {
    const dispatch = useDispatch();
    const { username: authUsername } = useSelector((state) => state.auth);
    const isSelfEdit = authUsername === user.username;

    const [formData, setFormData] = useState({
        username: user.username,
        email: user.email,
        password: "",
        confirm_password: "",
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
                    setPermissions(prev => ({ ...prev, ...perms }));
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
        setFormData({ ...formData, [e.target.name]: e.target.value });
        if (e.target.name === "current_password") setPasswordError(null);
        if (e.target.name === "password" && !e.target.value) {
            setFormData(prev => ({ ...prev, password: "", confirm_password: "", current_password: "" }));
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

    const handleSubmit = async (e) => {
        e.preventDefault();
        setPasswordError(null);

        if (formData.password && formData.password !== formData.confirm_password) {
            setPasswordError("Passwords do not match.");
            return;
        }

        if (formData.password && !formData.current_password) {
            setPasswordError("Current password is required to set a new password.");
            return;
        }

        const updateData = {};
        if (formData.username !== user.username) updateData.username = formData.username;
        if (formData.email !== user.email) updateData.email = formData.email;
        if (formData.role !== user.role) updateData.role = formData.role;
        if (formData.is_active !== user.is_active) updateData.is_active = formData.is_active;

        if (formData.password) {
            updateData.password = formData.password;
            updateData.current_password = formData.current_password;
        }

        const permissionsArray = Object.keys(permissions).map((module) => ({
            module,
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
                setFormData(prev => ({ ...prev, current_password: "" }));
                return;
            }
        }

        onClose();
    };

    const initials = user.username?.slice(0, 2).toUpperCase() || "U";
    const showCurrentPasswordField = !!formData.password;

    return (
        <div style={styles.overlay} onClick={onClose}>
            <div style={styles.modal} onClick={(e) => e.stopPropagation()}>

                {/* ── Header ── */}
                <div style={styles.header}>
                    <div style={styles.headerLeft}>
                        <div style={styles.headerAvatar}>{initials}</div>
                        <div>
                            <h3 style={styles.headerTitle}>Edit User</h3>
                            <p style={styles.headerSub}>@{user.username}</p>
                        </div>
                    </div>
                    <button style={styles.closeBtn} onClick={onClose}>✕</button>
                </div>

                <form onSubmit={handleSubmit}>
                    <div style={styles.body}>

                        {/* ── Account Info ── */}
                        <div style={styles.sectionLabel}>
                            Account Info
                            <span style={styles.sectionLine} />
                        </div>

                        <div style={styles.formRow}>
                            <div style={styles.formGroup}>
                                <label style={styles.label}>Username *</label>
                                <FocusInput
                                    type="text"
                                    name="username"
                                    value={formData.username}
                                    onChange={handleChange}
                                    required
                                    minLength={3}
                                    style={styles.input}
                                />
                            </div>
                            <div style={styles.formGroup}>
                                <label style={styles.label}>Email *</label>
                                <FocusInput
                                    type="email"
                                    name="email"
                                    value={formData.email}
                                    onChange={handleChange}
                                    required
                                    style={styles.input}
                                />
                            </div>
                        </div>

                        <div style={styles.formRow}>
                            <div style={styles.formGroup}>
                                <label style={styles.label}>Role *</label>
                                <FocusSelect
                                    name="role"
                                    value={formData.role}
                                    onChange={handleChange}
                                >
                                    <option value="user">User</option>
                                    <option value="manager">Manager</option>
                                    <option value="admin">Admin</option>
                                    <option value="guest">Guest</option>
                                </FocusSelect>
                            </div>
                            <div style={styles.formGroup}>
                                <label style={styles.label}>Status</label>
                                <div style={{ marginTop: "4px" }}>
                                    <button
                                        type="button"
                                        style={{
                                            ...styles.statusToggle,
                                            display: "flex",
                                            alignItems: "center",
                                            gap: "8px",
                                            padding: "8px 12px",
                                            border: "1px solid",
                                            borderRadius: "6px",
                                            cursor: "pointer",
                                            fontWeight: "600",
                                            fontSize: "14px",
                                            borderColor: formData.is_active ? "#16a34a" : "#dc2626",
                                            color: formData.is_active ? "#15803d" : "#b91c1c",
                                            background: formData.is_active ? "#f0fdf4" : "#fef2f2",
                                        }}
                                        onClick={() => setFormData(prev => ({ ...prev, is_active: !prev.is_active }))}
                                    >
                                        <span style={{
                                            position: "relative",
                                            display: "inline-block",
                                            width: "36px",
                                            height: "20px",
                                            borderRadius: "20px",
                                            background: formData.is_active ? "#16a34a" : "#dc2626",
                                            transition: "background-color 0.2s",
                                            flexShrink: 0,
                                        }}>
                                            <span style={{
                                                position: "absolute",
                                                top: "2px",
                                                left: "2px",
                                                width: "16px",
                                                height: "16px",
                                                backgroundColor: "#fff",
                                                borderRadius: "50%",
                                                transition: "transform 0.2s ease-in-out",
                                                boxShadow: "0 1px 2px rgba(0,0,0,0.2)",
                                                transform: formData.is_active ? "translateX(16px)" : "translateX(0)",
                                            }} />
                                        </span>
                                        <span>{formData.is_active ? "Active" : "Inactive"}</span>
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div style={styles.divider} />

                        {/* ── Password Change ── */}
                        <div style={styles.sectionLabel}>
                            Change Password
                            <span style={styles.sectionLine} />
                        </div>

                        {!isSelfEdit && (
                            <div style={{
                                background: "#eff6ff",
                                border: "1.5px solid #bfdbfe",
                                borderRadius: "10px",
                                padding: "10px 14px",
                                marginBottom: "16px",
                                fontSize: "12.5px",
                                color: "#1d4ed8",
                            }}>
                                ℹ️ To change this user's password, their current password is also required for security.
                            </div>
                        )}

                        <div style={styles.formRow}>
                            <div style={styles.formGroup}>
                                <label style={styles.label}>New Password</label>
                                <FocusInput
                                    type="password"
                                    name="password"
                                    value={formData.password}
                                    onChange={handleChange}
                                    placeholder="Leave empty to keep current"
                                    style={styles.input}
                                />
                                <span style={{ fontSize: "11px", color: "#9ca3af", marginTop: "4px" }}>
                                    Minimum 8 characters
                                </span>
                            </div>

                            {showCurrentPasswordField && (
                                <div style={styles.formGroup}>
                                    <label style={styles.label}>Confirm New Password *</label>
                                    <FocusInput
                                        type="password"
                                        name="confirm_password"
                                        value={formData.confirm_password}
                                        onChange={handleChange}
                                        placeholder="Re-enter new password"
                                        style={styles.input}
                                        hasError={!!(passwordError && passwordError.includes("match"))}
                                    />
                                </div>
                            )}
                        </div>

                        <div style={styles.formRow}>
                            {showCurrentPasswordField && (
                                <div style={styles.formGroup}>
                                    <label style={styles.label}>
                                        {isSelfEdit ? "Current Password *" : "User's Current Password *"}
                                    </label>
                                    <FocusInput
                                        type="password"
                                        name="current_password"
                                        value={formData.current_password}
                                        onChange={handleChange}
                                        placeholder={isSelfEdit
                                            ? "Enter your current password"
                                            : "Enter this user's current password"}
                                        required
                                        style={styles.input}
                                        hasError={!!passwordError}
                                    />
                                    {passwordError && (
                                        <span style={styles.errorText}>
                                            ⚠ {passwordError}
                                        </span>
                                    )}
                                </div>
                            )}
                        </div>

                        {showCurrentPasswordField && !formData.current_password && (
                            <div style={styles.passwordWarning}>
                                <span style={styles.warningIcon}>🔒</span>
                                <p style={styles.warningText}>
                                    To change the password, you must provide the <strong>current password</strong> for verification.
                                </p>
                            </div>
                        )}

                        <div style={styles.divider} />

                        {/* ── Permissions ── */}
                        <div style={styles.sectionLabel}>
                            Permissions
                            <span style={styles.sectionLine} />
                        </div>
                        <p style={{ fontSize: "12px", color: "#6b7280", marginBottom: "14px", marginTop: "-8px" }}>
                            Set module-level access for this user
                        </p>

                        {loadingPermissions ? (
                            <div style={styles.loadingBox}>Loading permissions…</div>
                        ) : (
                            <table style={styles.permTable}>
                                <thead style={styles.permThead}>
                                <tr>
                                    <th style={styles.permTh}>Module</th>
                                    <th style={{ ...styles.permTh, textAlign: "center" }}>Read</th>
                                    <th style={{ ...styles.permTh, textAlign: "center" }}>Write</th>
                                    <th style={{ ...styles.permTh, textAlign: "center" }}>Delete</th>
                                </tr>
                                </thead>
                                <tbody>
                                {MODULES.map((module, idx) => (
                                    <tr key={module.name} style={{
                                        background: idx % 2 === 0 ? "#ffffff" : "#f9fbfd",
                                    }}>
                                        <td style={styles.permTd}>
                                            <span style={styles.moduleName}>
                                                <i className={module.icon}
                                                   style={{ width: "16px", textAlign: "center" }} />
                                                &nbsp;&nbsp;{module.label}
                                            </span>
                                        </td>
                                        {["read", "write", "delete"].map(perm => (
                                            <td key={perm} style={{ ...styles.permTd, textAlign: "center" }}>
                                                <input
                                                    type="checkbox"
                                                    style={styles.permCheckbox}
                                                    checked={permissions[module.name]?.[perm] || false}
                                                    onChange={() => handlePermissionChange(module.name, perm)}
                                                />
                                            </td>
                                        ))}
                                    </tr>
                                ))}
                                </tbody>
                            </table>
                        )}

                    </div>

                    {/* ── Footer ── */}
                    <div style={styles.footer}>
                        <button
                            type="button"
                            style={styles.btnCancel}
                            onClick={onClose}
                            onMouseEnter={e => e.target.style.background = "#eef1f6"}
                            onMouseLeave={e => e.target.style.background = "#f8fafd"}
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            style={styles.btnSubmit}
                            onMouseEnter={e => e.target.style.opacity = "0.88"}
                            onMouseLeave={e => e.target.style.opacity = "1"}
                        >
                            Save Changes
                        </button>
                    </div>

                </form>
            </div>
        </div>
    );
};