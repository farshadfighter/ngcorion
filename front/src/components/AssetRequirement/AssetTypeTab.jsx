import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAssetTypes, deleteAssetType } from "../../store/requirementSlice";
import { AssetTypeModal } from "./AssetTypeModal";
import { DeleteConfirmModal } from "./DeleteConfirmModal";

export const AssetTypeTab = () => {
    const dispatch = useDispatch();
    const { assetTypes, isLoading } = useSelector((state) => state.requirements);

    const [showModal, setShowModal] = useState(false);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [selectedItem, setSelectedItem] = useState(null);
    const [searchTerm, setSearchTerm] = useState("");
    const [sortColumn, setSortColumn] = useState("id");
    const [sortDirection, setSortDirection] = useState("asc");

    useEffect(() => {
        dispatch(fetchAssetTypes());
    }, [dispatch]);

    const handleDelete = (item) => {
        setSelectedItem(item);
        setShowDeleteModal(true);
    };

    const confirmDelete = () => {
        if (selectedItem) {
            dispatch(deleteAssetType(selectedItem.id));
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

    const filteredData = assetTypes.filter((item) =>
        item.type_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.category?.toLowerCase().includes(searchTerm.toLowerCase()) ||
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
                    + Add Asset Type
                </button>
            </div>

            <div className="table-container">
                <table className="requirement-table">
                    <thead>
                    <tr>
                        <th onClick={() => handleSort("id")} style={{ cursor: "pointer" }}>
                            ID{renderSortIcon("id")}
                        </th>
                        <th onClick={() => handleSort("type_name")} style={{ cursor: "pointer" }}>
                            Type Name{renderSortIcon("type_name")}
                        </th>
                        <th onClick={() => handleSort("category")} style={{ cursor: "pointer" }}>
                            Category{renderSortIcon("category")}
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
                            <td colSpan="5" className="no-data">
                                No asset types found
                            </td>
                        </tr>
                    ) : (
                        sortedData.map((item) => (
                            <tr key={item.id}>
                                <td>{item.id}</td>
                                <td>{item.type_name}</td>
                                <td>{item.category || "-"}</td>
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
                <AssetTypeModal
                    onClose={() => setShowModal(false)}
                />
            )}

            {showDeleteModal && (
                <DeleteConfirmModal
                    title="Delete Asset Type"
                    message={`Are you sure you want to delete "${selectedItem?.type_name}"?`}
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