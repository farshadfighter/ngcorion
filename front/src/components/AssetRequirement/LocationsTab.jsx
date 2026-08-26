import React, { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchLocations, deleteLocation } from "../../store/requirementSlice";
import { LocationModal } from "./LocationModal";
import { DeleteConfirmModal } from "./DeleteConfirmModal";
import { BulkDeleteBar } from "./BulkDeleteBar";
import { RequirementError } from "./RequirementError";
import { EditRequirementModal } from "./EditRequirementModal";
import { useTableSelection } from "./useTableSelection";
import { Pagination } from "../Logs/Pagination.jsx";
import "../../assets/LogsPage.css";

export const LocationsTab = () => {
    const dispatch = useDispatch();
    const { locations, isLoading } = useSelector((state) => state.requirements);

    const [showModal, setShowModal] = useState(false);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [selectedItem, setSelectedItem] = useState(null);
    const [searchTerm, setSearchTerm] = useState("");
    const [sortColumn, setSortColumn] = useState("id");
    const [sortDirection, setSortDirection] = useState("asc");

    useEffect(() => {
        dispatch(fetchLocations());
    }, [dispatch]);

    const handleDelete = (item) => {
        setSelectedItem(item);
        setShowDeleteModal(true);
    };

    const confirmDelete = () => {
        if (selectedItem) {
            dispatch(deleteLocation(selectedItem.id));
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

    const filteredData = locations.filter((item) =>
        item.site_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.rack_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.room?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.unit?.toLowerCase().includes(searchTerm.toLowerCase())
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
                await dispatch(deleteLocation(id)).unwrap().catch(() => {});
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
                    + Add Location
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

                        <th onClick={() => handleSort("site_name")} style={{ cursor: "pointer" }}>
                            Site Name{renderSortIcon("site_name")}
                        </th>
                        <th onClick={() => handleSort("rack_name")} style={{ cursor: "pointer" }}>
                            Rack{renderSortIcon("rack_name")}
                        </th>
                        <th onClick={() => handleSort("room")} style={{ cursor: "pointer" }}>
                            Room{renderSortIcon("room")}
                        </th>
                        <th onClick={() => handleSort("floor")} style={{ cursor: "pointer" }}>
                            Floor{renderSortIcon("floor")}
                        </th>
                        <th onClick={() => handleSort("unit")} style={{ cursor: "pointer" }}>
                            Unit{renderSortIcon("unit")}
                        </th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {paged.length === 0 ? (
                        <tr>
                            <td colSpan="8" className="no-data">
                                No locations found
                            </td>
                        </tr>
                    ) : (
                        paged.map((item, index) => (
                            <tr key={item.id} className={selectedIds.has(item.id) ? "row-selected" : ""}>
                                <td className="cell-select">
                                    <input
                                        type="checkbox"
                                        checked={selectedIds.has(item.id)}
                                        onChange={() => toggleOne(item.id)}
                                        aria-label={`Select ${item.site_name || item.id}`}
                                    />
                                </td>
                                <td>{(page - 1) * pageSize + index + 1}</td>
                                <td>{item.site_name}</td>
                                <td>{item.rack_name || "-"}</td>
                                <td>{item.room || "-"}</td>
                                <td>{item.floor || "-"}</td>
                                <td>{item.unit || "-"}</td>
                                <td className="actions">
                                    <button className="btn-icon"
                                            onClick={() => setEditItem(item)}
                                            title="Edit"
                                    >
                                        <i className="fa-solid fa-pen"></i>
                                    </button>
                                    <button className="btn-icon"
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
                    kind="location"
                    item={editItem}
                    onClose={() => setEditItem(null)}
                />
            )}

            {showBulkConfirm && (
                <DeleteConfirmModal
                    title="Delete Locations"
                    message={`Are you sure you want to delete ${selectedCount} item${selectedCount === 1 ? "" : "s"}?`}
                    onConfirm={confirmBulkDelete}
                    onCancel={() => setShowBulkConfirm(false)}
                />
            )}

            {showModal && (
                <LocationModal
                    onClose={() => setShowModal(false)}
                />
            )}

            {showDeleteModal && (
                <DeleteConfirmModal
                    title="Delete Location"
                    message={`Are you sure you want to delete "${selectedItem?.site_name}"?`}
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