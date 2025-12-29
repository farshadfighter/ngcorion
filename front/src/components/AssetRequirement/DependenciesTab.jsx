import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { deleteDependency, fetchEnums } from "../../store/requirementSlice";
import { DependencyModal } from "./DependencyModal";
import { DeleteConfirmModal } from "./DeleteConfirmModal";

export const DependenciesTab = () => {
    const dispatch = useDispatch();
    const { dependencies, isLoading, enums } = useSelector((state) => state.requirements);

    const [showModal, setShowModal] = useState(false);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [selectedItem, setSelectedItem] = useState(null);
    const [searchTerm, setSearchTerm] = useState("");
    const [sortColumn, setSortColumn] = useState("id");
    const [sortDirection, setSortDirection] = useState("asc");

    useEffect(() => {
        dispatch(fetchEnums());
    }, [dispatch]);

    const handleDelete = (item) => {
        setSelectedItem(item);
        setShowDeleteModal(true);
    };

    const confirmDelete = () => {
        if (selectedItem) {
            dispatch(deleteDependency(selectedItem.id));
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

    const filteredData = dependencies.filter((item) =>
        item.asset_id?.toString().includes(searchTerm.toLowerCase()) ||
        item.depends_on_id?.toString().includes(searchTerm.toLowerCase()) ||
        item.relation_type?.toLowerCase().includes(searchTerm.toLowerCase())
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
                    + Add Dependency
                </button>
            </div>

            <div className="table-container">
                <table className="requirement-table">
                    <thead>
                    <tr>
                        <th onClick={() => handleSort("id")} style={{ cursor: "pointer" }}>
                            ID{renderSortIcon("id")}
                        </th>
                        <th onClick={() => handleSort("asset_id")} style={{ cursor: "pointer" }}>
                            Asset ID{renderSortIcon("asset_id")}
                        </th>
                        <th onClick={() => handleSort("depends_on_id")} style={{ cursor: "pointer" }}>
                            Depends On ID{renderSortIcon("depends_on_id")}
                        </th>
                        <th onClick={() => handleSort("relation_type")} style={{ cursor: "pointer" }}>
                            Relation Type{renderSortIcon("relation_type")}
                        </th>
                        <th onClick={() => handleSort("description")} style={{ cursor: "pointer" }}>
                            Description{renderSortIcon("description")}
                        </th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {sortedData.length === 0 ? (
                        <tr>
                            <td colSpan="6" className="no-data">
                                No dependencies found
                            </td>
                        </tr>
                    ) : (
                        sortedData.map((item) => (
                            <tr key={item.id}>
                                <td>{item.id}</td>
                                <td>{item.asset_id}</td>
                                <td>{item.depends_on_id}</td>
                                <td>{item.relation_type}</td>
                                <td>{item.description || "-"}</td>
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
                <DependencyModal
                    onClose={() => setShowModal(false)}
                    relationTypes={enums.relationTypes || []}
                />
            )}

            {showDeleteModal && (
                <DeleteConfirmModal
                    title="Delete Dependency"
                    message={`Are you sure you want to delete this dependency?`}
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