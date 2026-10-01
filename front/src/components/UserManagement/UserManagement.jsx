import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchUsers, deleteUser, clearMessages } from "../../store/userSlice";
import { AddUserModal } from "./AddUserModal";
import { EditUserModal } from "./EditUserModal";
import { DeleteConfirmModal } from "./DeleteConfirmModal";
import { t } from "../../i18n";
import { tv } from "../../i18n/backendText";

export const UserManagement = () => {
    const dispatch = useDispatch();
    const { users, isLoading, error, successMessage } = useSelector((state) => state.users);

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
                            <th>{t("Actions")}</th>
                        </tr>
                        </thead>
                        <tbody>
                        {users.map((user) => (
                            <tr key={user.id}>
                                <td>{user.username}</td>
                                <td>{user.email}</td>
                                <td>
                                        <span className={`badge badge-${user.role}`}>
                                            {tv(user.role)}
                                        </span>
                                </td>
                                <td>
                                        <span className={`badge badge-${user.is_active ? 'active' : 'inactive'}`}>
                                            {user.is_active ? t("Active") : t("Inactive")}
                                        </span>
                                </td>
                                <td>
                                    <button
                                        className="btn-icon btn-edit"
                                        onClick={() => handleEdit(user)}
                                        title={t("Edit")}
                                    >
                                        <i className="fa-solid fa-pen"></i>
                                    </button>
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