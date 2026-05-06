import React, { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchLocations, deleteLocation } from "../../store/requirementSlice";
import { LocationModal } from "./LocationModal";
import { DeleteConfirmModal } from "./DeleteConfirmModal";

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
        item.room?.toLowerCase().includes(searchTerm.toLowerCase())
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

            <div className="table-container">
                <table className="requirement-table">
                    <thead>
                    <tr>
                        <th>Number</th>
                        <th onClick={() => handleSort("id")} style={{ cursor: "pointer" }}>
                            ID{renderSortIcon("id")}
                        </th>
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
                        <th onClick={() => handleSort("network_zone")} style={{ cursor: "pointer" }}>
                            Zone{renderSortIcon("network_zone")}
                        </th>
                        <th onClick={() => handleSort("vlan_id")} style={{ cursor: "pointer" }}>
                            VLAN{renderSortIcon("vlan_id")}
                        </th>
                        <th onClick={() => handleSort("subnet")} style={{ cursor: "pointer" }}>
                            Subnet{renderSortIcon("subnet")}
                        </th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {sortedData.length === 0 ? (
                        <tr>
                            <td colSpan="10" className="no-data">
                                No locations found
                            </td>
                        </tr>
                    ) : (
                        sortedData.map((item, index) => (
                            <tr key={item.id}>
                                <td>{index + 1}</td>
                                <td>{item.id}</td>
                                <td>{item.site_name}</td>
                                <td>{item.rack_name || "-"}</td>
                                <td>{item.room || "-"}</td>
                                <td>{item.floor || "-"}</td>
                                <td>{item.network_zone || "-"}</td>
                                <td>{item.vlan_id || "-"}</td>
                                <td>{item.subnet || "-"}</td>
                                <td className="actions">
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