export const OverviewTab = ({ assets, onEdit, onDelete }) => {
    return (
        <div className="table-container">
            <table className="assets-table">
                <thead>
                <tr>
                    <th>ID</th>
                    <th>Asset Name</th>
                    <th>Hostname</th>
                    <th>Type</th>
                    <th>Role</th>
                    <th>Vendor</th>
                    <th>Model</th>
                    <th>Actions</th>
                </tr>
                </thead>
                <tbody>
                {assets.map((asset) => (
                    <tr key={asset.id}>
                        <td>{asset.id}</td>
                        <td>{asset.asset_name}</td>
                        <td>{asset.hostname || "-"}</td>
                        <td>{asset.asset_type_id || "-"}</td>
                        <td>{asset.asset_role || "-"}</td>
                        <td>{asset.manufacturer || "-"}</td>
                        <td>{asset.model || "-"}</td>
                        <td>
                            <button
                                className="btn-icon btn-edit"
                                onClick={() => onEdit(asset)}
                                title="Edit"
                            >
                                <img src="/icons/edetie.svg" alt="edit" />
                            </button>
                            <button
                                className="btn-icon btn-delete"
                                onClick={() => onDelete(asset)}
                                title="Delete"
                            >
                                <img src="/icons/delete.svg" alt="delete" />
                            </button>
                        </td>
                    </tr>
                ))}
                </tbody>
            </table>
        </div>
    );
};