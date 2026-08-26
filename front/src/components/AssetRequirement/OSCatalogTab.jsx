import React, { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchOSCatalog, deleteOS } from "../../store/requirementSlice";
import { OSCatalogModal } from "./OSCatalogModal";
import { DeleteConfirmModal } from "./DeleteConfirmModal";
import { BulkDeleteBar } from "./BulkDeleteBar";
import { RequirementError } from "./RequirementError";
import { EditRequirementModal } from "./EditRequirementModal";
import { useTableSelection } from "./useTableSelection";
import { Pagination } from "../Logs/Pagination.jsx";
import "../../assets/LogsPage.css";

export const OSCatalogTab = () => {
    const dispatch = useDispatch();
    const { osCatalog, isLoading } = useSelector((state) => state.requirements);

    const [showModal, setShowModal] = useState(false);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [selectedItem, setSelectedItem] = useState(null);
    const [searchTerm, setSearchTerm] = useState("");
    const [sortColumn, setSortColumn] = useState("id");
    const [sortDirection, setSortDirection] = useState("asc");

    useEffect(() => {
        dispatch(fetchOSCatalog());
    }, [dispatch]);

    const handleDelete = (item) => {
        setSelectedItem(item);
        setShowDeleteModal(true);
    };

    const confirmDelete = () => {
        if (selectedItem) {
            dispatch(deleteOS(selectedItem.id));
            setShowDeleteModal(false);
            setSelectedItem(null);
        }
    };

    const handleAdd = () => {
        setShowModal(true);
    };

    const handleSort = (column) => {
        if (sortColumn === column) {
            setSortDirection(sortDirection === "asc" ? "desc" : "asc");
        } else {
            setSortColumn(column);
            setSortDirection("asc");
        }
    };

    const filteredData = osCatalog.filter((item) =>
        item.os_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.os_version?.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const sortedData = [...filteredData].sort((a, b) => {
        let aVal = a[sortColumn];
        let bVal = b[sortColumn];
        if (aVal == null) aVal = "";
        if (bVal == null) bVal = "";
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
            // Sequential: each delete refetches the list, and parallel calls
            // race the store into an inconsistent state.
            for (const id of [...selectedIds]) {
                await dispatch(deleteOS(id)).unwrap().catch(() => {});
            }
        } finally {
            setIsBulkDeleting(false);
            setShowBulkConfirm(false);
            clearSelection();
        }
    };

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
                        placeholder="Search OS..."
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
                    + Add OS
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
                        <th onClick={() => handleSort("os_name")} style={{ cursor: "pointer" }}>
                            OS Name{renderSortIcon("os_name")}
                        </th>
                        <th onClick={() => handleSort("os_version")} style={{ cursor: "pointer" }}>
                            OS Version{renderSortIcon("os_version")}
                        </th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {paged.length === 0 ? (
                        <tr>
                            <td colSpan="4" className="no-data">
                                No OS found
                            </td>
                        </tr>
                    ) : (
                        paged.map((item) => (
                            <tr key={item.id} className={selectedIds.has(item.id) ? "row-selected" : ""}>
                                <td className="cell-select">
                                    <input
                                        type="checkbox"
                                        checked={selectedIds.has(item.id)}
                                        onChange={() => toggleOne(item.id)}
                                        aria-label={`Select ${item.os_name || item.id}`}
                                    />
                                </td>
                                <td>{item.os_name}</td>
                                <td>{item.os_version || "-"}</td>
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

            {editItem && (
                <EditRequirementModal
                    kind="os"
                    item={editItem}
                    onClose={() => setEditItem(null)}
                />
            )}

            {showBulkConfirm && (
                <DeleteConfirmModal
                    title="Delete OS Entries"
                    message={`Are you sure you want to delete ${selectedCount} item${selectedCount === 1 ? "" : "s"}?`}
                    onConfirm={confirmBulkDelete}
                    onCancel={() => setShowBulkConfirm(false)}
                />
            )}

            {showModal && (
                <OSCatalogModal
                    onClose={() => setShowModal(false)}
                />
            )}

            {showDeleteModal && (
                <DeleteConfirmModal
                    title="Delete OS"
                    message={`Are you sure you want to delete "${selectedItem?.os_name}"?`}
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