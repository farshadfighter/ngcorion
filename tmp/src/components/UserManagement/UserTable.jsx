// src/components/UserManagement/UserTable.jsx
import React from "react";

const UserTable = ({ users, onEdit, onDelete }) => {
    return (
        <table className="user-table">
            <thead>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th style={{ textAlign: "right" }}>Actions</th>
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
                {u.is_active ? "Active" : "Inactive"}
              </span>
                    </td>
                    <td style={{ textAlign: "right" }}>
                        <button
                            className="btn-icon"
                            onClick={() => onEdit(u.id)}
                        >
                            ✏
                        </button>
                        <button
                            className="btn-icon btn-icon--danger"
                            onClick={() => onDelete(u)}
                        >
                            🗑
                        </button>
                    </td>
                </tr>
            ))}
            </tbody>
        </table>
    );
};

export default UserTable;
