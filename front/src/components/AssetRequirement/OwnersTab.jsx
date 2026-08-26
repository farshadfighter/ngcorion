import React, { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchOwners, deleteOwner } from "../../store/requirementSlice";
import { OwnerModal } from "./OwnerModal";
import { DeleteConfirmModal } from "./DeleteConfirmModal";
import { BulkDeleteBar } from "./BulkDeleteBar";
import { RequirementError } from "./RequirementError";
import { EditRequirementModal } from "./EditRequirementModal";
import { useTableSelection } from "./useTableSelection";
import { Pagination } from "../Logs/Pagination.jsx";
import "../../assets/LogsPage.css";

export const OwnersTab = () => {
    const dispatch = useDispatch();
    const { owners, isLoading } = useSelector((state) => state.requirements);

    const [showModal, setShowModal] = useState(false);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [selectedItem, setSelectedItem] = useState(null);
    const [searchTerm, setSearchTerm] = useState("");

    // Sort state
    const [sortColumn, setSortColumn] = useState("id");
    const [sortDirection, setSortDirection] = useState("asc"); // 'asc' or 'desc'

    useEffect(() => {
        dispatch(fetchOwners());
    }, [dispatch]);

    const handleDelete = (item) => {
        setSelectedItem(item);
        setShowDeleteModal(true);
    };

    const confirmDelete = () => {
        if (selectedItem) {
            dispatch(deleteOwner(selectedItem.id));
            setShowDeleteModal(false);
            setSelectedItem(null);
        }
    };

    const handleAdd = () => {
        setShowModal(true);
    };

    // Sort handler
    const handleSort = (column) => {
        if (sortColumn === column) {
            // Toggle direction
            setSortDirection(sortDirection === "asc" ? "desc" : "asc");
        } else {
            // New column, default to ascending
            setSortColumn(column);
            setSortDirection("asc");
        }
    };

    // Filter data
    const filteredData = owners.filter((item) =>
        item.full_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.department?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.email?.toLowerCase().includes(searchTerm.toLowerCase())
    );

    // Sort data
    const sortedData = [...filteredData].sort((a, b) => {
        let aVal = a[sortColumn];
        let bVal = b[sortColumn];

        // Handle null/undefined
        if (aVal == null) aVal = "";
        if (bVal == null) bVal = "";

        // Convert to string for comparison
        aVal = String(aVal).toLowerCase();
        bVal = String(bVal).toLowerCase();

        if (sortDirection === "asc") {
            return aVal.localeCompare(bVal, undefined, { numeric: true });
        } else {
            return bVal.localeCompare(aVal, undefined, { numeric: true });
        }
    });

    // Paging + selection (shared with the other requirement tabs).
    const {
        page, setPage, pageSize, setPageSize, paged, total,
        selectedIds, selectedCount, allSelected, toggleOne, toggleAll,
        clearSelection,
    } = useTableSelection(sortedData);

    const [editItem, setEditItem] = useState(null);
    const [isBulkDeleting, setIsBulkDeleting] = useState(false);
    const [showBulkConfirm, setShowBulkConfirm] = useState(false);

    const confirmBulkDelete = async () => {
        setIsBulkDeleting(true);
        try {
            // Sequential rather than parallel: the list refetches per delete,
            // and a burst of them races the store into an inconsistent list.
            for (const id of [...selectedIds]) {
                await dispatch(deleteOwner(id)).unwrap().catch(() => {});
            }
        } finally {
            setIsBulkDeleting(false);
            setShowBulkConfirm(false);
            clearSelection();
        }
    };

    // Render sort icon
    const renderSortIcon = (column) => {
        if (sortColumn !== column) return " ↕";
        return sortDirection === "asc" ? " ↑" : " ↓";
    };

    if (isLoading) {
        return <div className="loading-spinner">Loading...</div>;
    }

    return (
        <div className="tab-content">
            <div className="tab-header">
                <div className="search-wrapper">
                    <input
                        type="text"

                        placeholder="Search asset types..."
                        className="search-input"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        style={{
                            width: "240px",
                            padding: "8px 14px",
                            fontSize: "13px",
                            border: "1px solid #d0d5dd",
                            borderRadius: "8px",
                            background: "#ffffff",
                            outline: "none",
                        }}
                    />
                </div>
                <button className="btn-add" onClick={handleAdd}>
                    + Add Owner
                </button>
            </div>

            <RequirementError />

            <BulkDeleteBar
                count={selectedCount}
                onDelete={() => setShowBulkConfirm(true)}
                onClear={clearSelection}
                isDeleting={isBulkDeleting}
            />

            <div className="table-container">
                <table className="requirement-table">
                    <thead>
                    <tr>
                        <th className="cell-select">
                            <input
                                type="checkbox"
                                checked={allSelected}
                                onChange={toggleAll}
                                aria-label="Select all rows on this page"
                            />
                        </th>
                        <th>Number</th>

                        <th onClick={() => handleSort("full_name")} style={{ cursor: "pointer" }}>
                            Full Name{renderSortIcon("full_name")}
                        </th>
                        <th onClick={() => handleSort("department")} style={{ cursor: "pointer" }}>
                            Department{renderSortIcon("department")}
                        </th>
                        <th onClick={() => handleSort("role")} style={{ cursor: "pointer" }}>
                            Role{renderSortIcon("role")}
                        </th>
                        <th onClick={() => handleSort("email")} style={{ cursor: "pointer" }}>
                            Email{renderSortIcon("email")}
                        </th>
                        <th onClick={() => handleSort("phone")} style={{ cursor: "pointer" }}>
                            Phone{renderSortIcon("phone")}
                        </th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {paged.length === 0 ? (
                        <tr>
                            <td colSpan="8" className="no-data">
                                No owners found
                            </td>
                        </tr>
                    ) : (
                        paged.map((item, index) => (
                            <tr
                                key={item.id}
                                className={selectedIds.has(item.id) ? "row-selected" : ""}
                            >
                                <td className="cell-select">
                                    <input
                                        type="checkbox"
                                        checked={selectedIds.has(item.id)}
                                        onChange={() => toggleOne(item.id)}
                                        aria-label={`Select ${item.full_name}`}
                                    />
                                </td>
                                {/* Continues across pages rather than restarting at 1. */}
                                <td>{(page - 1) * pageSize + index + 1}</td>
                                <td>{item.full_name}</td>
                                <td>{item.department || "-"}</td>
                                <td>{item.role || "-"}</td>
                                <td>{item.email || "-"}</td>
                                <td>{item.phone || "-"}</td>
                                <td className="actions">
                                    <button
                                        className="btn-icon"
                                        onClick={() => setEditItem(item)}
                                        title="Edit"
                                    >
                                        <i className="fa-solid fa-pen"></i>
                                    </button>
                                    <button
                                        className="btn-icon"
                                        onClick={() => handleDelete(item)}
                                    >
                                        <i className="fa-solid fa-trash"></i>

                                    </button>
                                </td>
                            </tr>
                        ))
                    )}
                    </tbody>
                </table>
            </div>

            <Pagination
                page={page}
                pageSize={pageSize}
                totalItems={total}
                onPageChange={setPage}
                onPageSizeChange={setPageSize}
            />

            {showModal && (
                <OwnerModal
                    onClose={() => setShowModal(false)}
                />
            )}

            {editItem && (
                <EditRequirementModal
                    kind="owner"
                    item={editItem}
                    onClose={() => setEditItem(null)}
                />
            )}

            {showBulkConfirm && (
                <DeleteConfirmModal
                    title="Delete Owners"
                    message={`Are you sure you want to delete ${selectedCount} owner${selectedCount === 1 ? "" : "s"}?`}
                    onConfirm={confirmBulkDelete}
                    onCancel={() => setShowBulkConfirm(false)}
                />
            )}

            {showDeleteModal && (
                <DeleteConfirmModal
                    title="Delete Owner"
                    message={`Are you sure you want to delete "${selectedItem?.full_name}"?`}
                    onConfirm={confirmDelete}
                    onCancel={() => {
                        setShowDeleteModal(false);
                        setSelectedItem(null);
                    }}
                />
            )}
        </div>
    );
};