// src/components/UserManagement/UserTable.jsx
import React from "react";
import { t } from "../../i18n";

const UserTable = ({ users, onEdit, onDelete }) => {
    return (
        <table className="user-table">
            <thead>
            <tr>
                <th>{t("ID")}</th>
                <th>{t("Username")}</th>
                <th>{t("Email")}</th>
                <th>{t("Role")}</th>
                <th>{t("Status")}</th>
                <th style={{ textAlign: "end" }}>{t("Actions")}</th>
            </tr>
            </thead>

            <tbody>
            {users.map((u) => (
                <tr key={u.id}>
                    <td>{u.id}</td>
                    <td>{u.username}</td>
                    <td>{u.email}</td>
                    <td>{u.role}</td>
                    <td>
              <span
                  className={
                      u.is_active ? "badge badge--active" : "badge badge--inactive"
                  }
              >
                {u.is_active ? t("Active") : t("Inactive")}
              </span>
                    </td>
                    <td style={{ textAlign: "end" }}>
                        <button
                            className="btn-icon"
                            onClick={() => onEdit(u.id)}
                            title={t("Edit user")}
                            aria-label={t("Edit user")}
                        >
                            <i className="fa-solid fa-pen" />
                        </button>
                        <button
                            className="btn-icon btn-icon--danger"
                            onClick={() => onDelete(u)}
                            title={t("Delete user")}
                            aria-label={t("Delete user")}
                        >
                            <i className="fa-solid fa-trash" />
                        </button>
                    </td>
                </tr>
            ))}
            </tbody>
        </table>
    );
};

export default UserTable;
