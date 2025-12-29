import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchOSCatalog, deleteOS } from "../../store/requirementSlice";
import { OSCatalogModal } from "./OSCatalogModal";
import { DeleteConfirmModal } from "./DeleteConfirmModal";

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
        item.os_version?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.os_family?.toLowerCase().includes(searchTerm.toLowerCase())
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
                    + Add OS
                </button>
            </div>

            <div className="table-container">
                <table className="requirement-table">
                    <thead>
                    <tr>
                        <th onClick={() => handleSort("id")} style={{ cursor: "pointer" }}>
                            ID{renderSortIcon("id")}
                        </th>
                        <th onClick={() => handleSort("os_name")} style={{ cursor: "pointer" }}>
                            OS Name{renderSortIcon("os_name")}
                        </th>
                        <th onClick={() => handleSort("os_version")} style={{ cursor: "pointer" }}>
                            OS Version{renderSortIcon("os_version")}
                        </th>
                        <th onClick={() => handleSort("os_family")} style={{ cursor: "pointer" }}>
                            OS Family{renderSortIcon("os_family")}
                        </th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {sortedData.length === 0 ? (
                        <tr>
                            <td colSpan="5" className="no-data">
                                No OS found
                            </td>
                        </tr>
                    ) : (
                        sortedData.map((item) => (
                            <tr key={item.id}>
                                <td>{item.id}</td>
                                <td>{item.os_name}</td>
                                <td>{item.os_version || "-"}</td>
                                <td>{item.os_family || "-"}</td>
                                <td className="actions">
                                    <button
                                        className="btn-delete"
                                        onClick={() => handleDelete(item)}
                                    >
                                        <img src={"/icons/delete.svg"} alt={"delete"} />
                                    </button>
                                </td>
                            </tr>
                        ))
                    )}
                    </tbody>
                </table>
            </div>

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