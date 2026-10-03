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
import { t, n } from "../../i18n";

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
        return <div className="loading-spinner">{t("Loading...")}</div>;
    }

    return (
        <div className="tab-content">
            <div className="tab-header">
                <div className="search-wrapper">
                    <input
                        type="text"
                        placeholder={t("Search asset types...")}
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
                    {t("+ Add Location")}
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
                                aria-label={t("Select all rows on this page")}
                            />
                        </th>
                        <th>{t("Number")}</th>

                        <th onClick={() => handleSort("site_name")} style={{ cursor: "pointer" }}>
                            {t("Site Name")}{renderSortIcon("site_name")}
                        </th>
                        <th onClick={() => handleSort("rack_name")} style={{ cursor: "pointer" }}>
                            {t("Rack")}{renderSortIcon("rack_name")}
                        </th>
                        <th onClick={() => handleSort("room")} style={{ cursor: "pointer" }}>
                            {t("Room")}{renderSortIcon("room")}
                        </th>
                        <th onClick={() => handleSort("floor")} style={{ cursor: "pointer" }}>
                            {t("Floor")}{renderSortIcon("floor")}
                        </th>
                        <th onClick={() => handleSort("unit")} style={{ cursor: "pointer" }}>
                            {t("Unit")}{renderSortIcon("unit")}
                        </th>
                        <th>{t("Actions")}</th>
                    </tr>
                    </thead>
                    <tbody>
                    {paged.length === 0 ? (
                        <tr>
                            <td colSpan="8" className="no-data">
                                {t("No locations found")}
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
                                        aria-label={t("Select {{value}}", { value: item.site_name || item.id })}
                                    />
                                </td>
                                <td>{n((page - 1) * pageSize + index + 1)}</td>
                                <td>{item.site_name}</td>
                                <td>{item.rack_name || "-"}</td>
                                <td>{item.room || "-"}</td>
                                <td>{item.floor || "-"}</td>
                                <td>{item.unit || "-"}</td>
                                <td className="actions">
                                    <button className="btn-icon"
                                            onClick={() => setEditItem(item)}
                                            title={t("Edit")}
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
                    title={t("Delete Locations")}
                    message={t("Are you sure you want to delete {{count}} items?", { count: selectedCount })}
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
                    title={t("Delete Location")}
                    message={t("Are you sure you want to delete \"{{site_name}}\"?", { site_name: selectedItem?.site_name })}
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