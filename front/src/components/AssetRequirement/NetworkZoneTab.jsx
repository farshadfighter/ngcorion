import React, { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchZones, deleteZone } from "../../store/requirementSlice";
import { NetworkZoneModal } from "./NetworkZoneModal";
import { DeleteConfirmModal } from "./DeleteConfirmModal";

const DescriptionModal = ({ description, zoneName, onClose }) => {
    return (
        <div
            style={{
                position: "fixed",
                inset: 0,
                backgroundColor: "rgba(0,0,0,0.5)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                zIndex: 1000,
            }}
            onClick={onClose}
        >
            <div
                style={{
                    backgroundColor: "#fff",
                    borderRadius: "12px",
                    width: "420px",
                    maxWidth: "90vw",
                    boxShadow: "0 20px 60px rgba(0,0,0,0.3)",
                    overflow: "hidden",
                }}
                onClick={(e) => e.stopPropagation()}
            >
                {/* Header */}
                <div
                    style={{
                        backgroundColor: "#1e3a5f",
                        padding: "16px 20px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                    }}
                >
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <i className="fa-solid fa-circle-info" style={{ color: "#fff", fontSize: "16px" }}></i>
                        <span style={{ color: "#fff", fontWeight: "600", fontSize: "15px" }}>
                            Description
                        </span>
                    </div>
                    <button
                        onClick={onClose}
                        style={{
                            background: "rgba(255,255,255,0.15)",
                            border: "none",
                            borderRadius: "6px",
                            color: "#fff",
                            width: "28px",
                            height: "28px",
                            cursor: "pointer",
                            fontSize: "14px",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                        }}
                    >
                        ✕
                    </button>
                </div>

                {/* Zone Name */}
                <div
                    style={{
                        backgroundColor: "#f0f4f8",
                        padding: "10px 20px",
                        borderBottom: "1px solid #e2e8f0",
                    }}
                >
                    <span style={{ fontSize: "12px", color: "#64748b", fontWeight: "500" }}>
                        Zone:
                    </span>
                    <span style={{ fontSize: "13px", color: "#1e3a5f", fontWeight: "600", marginLeft: "6px" }}>
                        {zoneName}
                    </span>
                </div>

                {/* Description */}
                <div style={{ padding: "20px" }}>
                    <p
                        style={{
                            margin: 0,
                            fontSize: "14px",
                            color: "#374151",
                            lineHeight: "1.7",
                            whiteSpace: "pre-wrap",
                        }}
                    >
                        {description}
                    </p>
                </div>

                {/* Footer */}
                <div
                    style={{
                        padding: "12px 20px",
                        borderTop: "1px solid #e2e8f0",
                        display: "flex",
                        justifyContent: "flex-end",
                    }}
                >
                    <button
                        onClick={onClose}
                        style={{
                            backgroundColor: "#1e3a5f",
                            color: "#fff",
                            border: "none",
                            borderRadius: "8px",
                            padding: "8px 20px",
                            fontSize: "13px",
                            fontWeight: "500",
                            cursor: "pointer",
                        }}
                    >
                        Close
                    </button>
                </div>
            </div>
        </div>
    );
};

export const NetworkZoneTab = () => {
    const dispatch = useDispatch();
    const { zones, isLoading } = useSelector((state) => state.requirements);

    const [showModal, setShowModal] = useState(false);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [selectedItem, setSelectedItem] = useState(null);
    const [searchTerm, setSearchTerm] = useState("");
    const [sortColumn, setSortColumn] = useState("id");
    const [sortDirection, setSortDirection] = useState("asc");
    const [selectedDescription, setSelectedDescription] = useState(null);
    const [selectedZoneName, setSelectedZoneName] = useState("");

    useEffect(() => {
        dispatch(fetchZones());
    }, [dispatch]);

    const handleDelete = (item) => {
        setSelectedItem(item);
        setShowDeleteModal(true);
    };

    const confirmDelete = () => {
        if (selectedItem) {
            dispatch(deleteZone(selectedItem.id));
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

    const filteredData = zones.filter((item) =>
        item.zone_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.description?.toLowerCase().includes(searchTerm.toLowerCase())
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
        <>
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
                        + Add Zone
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
                            <th onClick={() => handleSort("zone_name")} style={{ cursor: "pointer" }}>
                                Zone Name{renderSortIcon("zone_name")}
                            </th>
                            <th>Description</th>
                            <th>Actions</th>
                        </tr>
                        </thead>
                        <tbody>
                        {sortedData.length === 0 ? (
                            <tr>
                                <td colSpan="5" className="no-data">
                                    No zones found
                                </td>
                            </tr>
                        ) : (
                            sortedData.map((item, index) => (
                                <tr key={item.id}>
                                    <td>{index + 1}</td>
                                    <td>{item.id}</td>
                                    <td>{item.zone_name}</td>
                                    <td>
                                        {item.description ? (
                                            <button style={{paddingLeft:"35px",}}
                                                className="btn-icon"
                                                onClick={() => {
                                                    setSelectedDescription(item.description);
                                                    setSelectedZoneName(item.zone_name);
                                                }}
                                                title="View description"
                                            >
                                                <i
                                                    className="fa-solid fa-circle-info"
                                                    style={{ color: "#1e3a5f" }}
                                                ></i>
                                            </button>
                                        ) : "-"}
                                    </td>
                                    <td className="actions">
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

                {showModal && (
                    <NetworkZoneModal onClose={() => setShowModal(false)} />
                )}

                {showDeleteModal && (
                    <DeleteConfirmModal
                        title="Delete Zone"
                        message={`Are you sure you want to delete "${selectedItem?.zone_name}"?`}
                        onConfirm={confirmDelete}
                        onCancel={() => {
                            setShowDeleteModal(false);
                            setSelectedItem(null);
                        }}
                    />
                )}
            </div>

            {selectedDescription && (
                <DescriptionModal
                    description={selectedDescription}
                    zoneName={selectedZoneName}
                    onClose={() => {
                        setSelectedDescription(null);
                        setSelectedZoneName("");
                    }}
                />
            )}
        </>
    );
};