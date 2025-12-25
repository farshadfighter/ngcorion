import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchVendors, deleteVendor } from "../../store/requirementSlice";
import { VendorModal } from "./VendorModal";
import { DeleteConfirmModal } from "./DeleteConfirmModal";

export const VendorsTab = () => {
    const dispatch = useDispatch();
    const { vendors, isLoading } = useSelector((state) => state.requirements);

    const [showModal, setShowModal] = useState(false);
    const [showDeleteModal, setShowDeleteModal] = useState(false);
    const [selectedItem, setSelectedItem] = useState(null);
    const [searchTerm, setSearchTerm] = useState("");
    const [sortColumn, setSortColumn] = useState("id");
    const [sortDirection, setSortDirection] = useState("asc");

    useEffect(() => {
        dispatch(fetchVendors());
    }, [dispatch]);

    const handleDelete = (item) => {
        setSelectedItem(item);
        setShowDeleteModal(true);
    };

    const confirmDelete = () => {
        if (selectedItem) {
            dispatch(deleteVendor(selectedItem.id));
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

    const filteredData = vendors.filter((item) =>
        item.vendor_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.vendor_type?.toLowerCase().includes(searchTerm.toLowerCase())
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
                <input
                    type="text"
                    placeholder="Search vendors..."
                    className="search-input"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                />
                <button className="btn-add" onClick={handleAdd}>
                    + Add Vendor
                </button>
            </div>

            <div className="table-container">
                <table className="requirement-table">
                    <thead>
                    <tr>
                        <th onClick={() => handleSort("id")} style={{ cursor: "pointer" }}>
                            ID{renderSortIcon("id")}
                        </th>
                        <th onClick={() => handleSort("vendor_name")} style={{ cursor: "pointer" }}>
                            Vendor Name{renderSortIcon("vendor_name")}
                        </th>
                        <th onClick={() => handleSort("vendor_type")} style={{ cursor: "pointer" }}>
                            Vendor Type{renderSortIcon("vendor_type")}
                        </th>
                        <th>Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    {sortedData.length === 0 ? (
                        <tr>
                            <td colSpan="4" className="no-data">
                                No vendors found
                            </td>
                        </tr>
                    ) : (
                        sortedData.map((item) => (
                            <tr key={item.id}>
                                <td>{item.id}</td>
                                <td>{item.vendor_name}</td>
                                <td>{item.vendor_type || "-"}</td>
                                <td className="actions">
                                    <button
                                        className="btn-delete"
                                        onClick={() => handleDelete(item)}
                                    >
                                        🗑️ Delete
                                    </button>
                                </td>
                            </tr>
                        ))
                    )}
                    </tbody>
                </table>
            </div>

            {showModal && (
                <VendorModal
                    onClose={() => setShowModal(false)}
                />
            )}

            {showDeleteModal && (
                <DeleteConfirmModal
                    title="Delete Vendor"
                    message={`Are you sure you want to delete "${selectedItem?.vendor_name}"?`}
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