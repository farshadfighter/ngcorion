/**
 * User Management page (administrators): list, search, add, edit, delete, and (system
 * administrators) each user's two-step sign-in state, a temporary password for a user who cannot
 * sign in, and a reset of two-step sign-in for one who lost the phone.
 */
import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useSearchParams } from "react-router-dom";
import { fetchUsers, deleteUser, clearMessages } from "../../store/userSlice";
import { AddUserModal } from "./AddUserModal";
import { EditUserModal } from "./EditUserModal";
import { DeleteConfirmModal } from "./DeleteConfirmModal";
import { TempPasswordModal } from "./TempPasswordModal";
import { ResetTwoStepModal } from "./ResetTwoStepModal";
import api from "../../config/api";
import { t } from "../../i18n";
import { formatDate } from "../../utils/dates";
import "../../assets/TwoStep.css";
import "../../assets/Directory.css";
import { tv } from "../../i18n/backendText";

const TwoStepBadge = ({ state }) => {
    if (!state) return <span className="ts-badge off">—</span>;
    if (state.enabled) return <span className="ts-badge on"><i className="fa-solid fa-lock" aria-hidden="true" /> {t("On")}</span>;
    if (state.enrolment_due) return <span className="ts-badge due">{t("Required, not set up")}</span>;
    if (state.required && state.deadline) {
        return <span className="ts-badge grace">{t("Due by {{date}}", { date: formatDate(state.deadline) })}</span>;
    }
    if (state.required) return <span className="ts-badge grace">{t("Required at next sign-in")}</span>;
    return <span className="ts-badge off">{t("Off")}</span>;
};

export const UserManagement = () => {
    const dispatch = useDispatch();
    const { users: allUsers, isLoading, error, successMessage } = useSelector((state) => state.users);
    // ?q= (the global search): only the users whose name or email contains it
    const [params, setParams] = useSearchParams();
    const only = (params.get("q") || "").trim().toLowerCase();
    const users = only ? allUsers.filter((u) => `${u.username} ${u.email || ""}`.toLowerCase().includes(only)) : allUsers;
    // Only a system administrator sets temporary passwords, and never their own (the server checks too).
    const { role: myRole, username: myName } = useSelector((state) => state.auth);
    const [tempPasswordFor, setTempPasswordFor] = useState(null);
    const [resetTwoStepFor, setResetTwoStepFor] = useState(null);
    // user id → { enabled, required, enrolment_due, deadline } (system administrators only)
    const [twoStep, setTwoStep] = useState({});
    const loadTwoStep = () => {
        if (myRole !== "admin") return;
        api.get("/api/system/authentication/users")
            .then(({ data }) => setTwoStep(Object.fromEntries(data.map((s) => [s.user_id, s]))))
            .catch(() => setTwoStep({}));
    };
    useEffect(loadTwoStep, [myRole]);

    const [showAddModal, setShowAddModal] = useState(false);
    const [showEditModal, setShowEditModal] = useState(false);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [selectedUser, setSelectedUser] = useState(null);

    useEffect(() => {
        dispatch(fetchUsers());
    }, [dispatch]);

    useEffect(() => {
        if (successMessage) {
            setTimeout(() => dispatch(clearMessages()), 3000);
        }
    }, [successMessage, dispatch]);

    const handleEdit = (user) => {
        setSelectedUser(user);
        setShowEditModal(true);
    };

    const handleDeleteClick = (user) => {
        setSelectedUser(user);
        setShowDeleteModal(true);
    };

    const handleDeleteConfirm = () => {
        if (selectedUser) {
            dispatch(deleteUser(selectedUser.id));
            setShowDeleteModal(false);
            setSelectedUser(null);
        }
    };

    return (
        <div className="user-management-container">
            <div className="um-header">
                <h2 className="um-title">{t("User Management")}</h2>
                <button className="btn-add-user" onClick={() => setShowAddModal(true)}>
                   {t("+ Add User")}
                </button>
            </div>

            {/* Success/Error Messages */}
            {successMessage && (
                <div className="alert alert-success">{successMessage}</div>
            )}
            {error && (
                <div className="alert alert-error">{error}</div>
            )}

            {only && (
                <div className="alert alert-success um-only">
                    {t("Only users matching {{text}}", { text: params.get("q") })}
                    <button type="button" className="um-show-all" onClick={() => setParams({})}>{t("Show all")}</button>
                </div>
            )}

            {/* Loading State */}
            {isLoading && <div className="loading-spinner">{t("Loading...")}</div>}

            {/* Users Table */}
            {!isLoading && (
                <div className="table-container">
                    <table className="users-table">
                        <thead>
                        <tr>
                            <th>{t("Username")}</th>
                            <th>{t("Email")}</th>
                            <th>{t("Role")}</th>
                            <th>{t("Status")}</th>
                            {myRole === "admin" && <th>{t("Two-step sign-in")}</th>}
                            <th>{t("Actions")}</th>
                        </tr>
                        </thead>
                        <tbody>
                        {users.map((user) => (
                            <tr key={user.id}>
                                <td>
                                    {user.username}
                                    {user.auth_source === "ldap" && (
                                        <span className="dir-badge" title={t("Signs in through the organization's directory")}>AD</span>
                                    )}
                                </td>
                                <td>{user.email || "—"}</td>
                                <td>
                                        <span className={`badge badge-${user.role}`}>
                                            {tv(user.role)}
                                        </span>
                                </td>
                                <td>
                                        <span className={`badge badge-${user.is_active ? 'active' : 'inactive'}`}>
                                            {user.is_active ? t("Active") : user.disabled_by_directory ? t("Off in the directory") : t("Inactive")}
                                        </span>
                                </td>
                                {myRole === "admin" && <td><TwoStepBadge state={twoStep[user.id]} /></td>}
                                <td>
                                    <button
                                        className="btn-icon btn-edit"
                                        onClick={() => handleEdit(user)}
                                        title={t("Edit")}
                                    >
                                        <i className="fa-solid fa-pen"></i>
                                    </button>
                                    {myRole === "admin" && user.username !== myName && user.auth_source !== "ldap" && (
                                        <button
                                            className="btn-icon btn-edit"
                                            onClick={() => setTempPasswordFor(user)}
                                            title={t("Set a temporary password")}
                                            aria-label={t("Set a temporary password")}
                                        >
                                            <i className="fa-solid fa-key"></i>
                                        </button>
                                    )}
                                    {myRole === "admin" && user.username !== myName && twoStep[user.id]?.enabled && (
                                        <button
                                            className="btn-icon btn-edit"
                                            onClick={() => setResetTwoStepFor(user)}
                                            title={t("Reset two-step sign-in")}
                                            aria-label={t("Reset two-step sign-in")}
                                        >
                                            <i className="fa-solid fa-mobile-screen-button"></i>
                                        </button>
                                    )}
                                    <button
                                        className="btn-icon btn-delete"
                                        onClick={() => handleDeleteClick(user)}
                                        title={t("Delete")}
                                    >
                                        <i className="fa-solid fa-trash"></i>
                                    </button>
                                </td>
                            </tr>
                        ))}
                        </tbody>
                    </table>

                    {users.length === 0 && (
                        <div className="no-data">{t("No users found")}</div>
                    )}
                </div>
            )}

            {/* Modals */}
            {showAddModal && <AddUserModal onClose={() => setShowAddModal(false)} />}
            {showEditModal && selectedUser && (
                <EditUserModal
                    user={selectedUser}
                    onClose={() => {
                        setShowEditModal(false);
                        setSelectedUser(null);
                    }}
                />
            )}
            {tempPasswordFor && (
                <TempPasswordModal user={tempPasswordFor} onClose={() => setTempPasswordFor(null)} />
            )}
            {resetTwoStepFor && (
                <ResetTwoStepModal user={resetTwoStepFor}
                                   onClose={(changed) => { setResetTwoStepFor(null); if (changed) loadTwoStep(); }} />
            )}
            {showDeleteModal && selectedUser && (
                <DeleteConfirmModal
                    user={selectedUser}
                    onConfirm={handleDeleteConfirm}
                    onCancel={() => {
                        setShowDeleteModal(false);
                        setSelectedUser(null);
                    }}
                />
            )}
        </div>
    );
};