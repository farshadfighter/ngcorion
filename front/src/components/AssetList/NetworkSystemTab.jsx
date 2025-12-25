export const NetworkSystemTab = ({ assets, onEdit, onDelete }) => {
    return (
        <div className="table-container">
            <table className="assets-table">
                <thead>
                <tr>
                    <th>ID</th>
                    <th>Asset Name</th>
                    <th>Serial</th>
                    <th>Os</th>
                    <th>Ip Address</th>
                    <th>Mac Address</th>
                    <th>Actions</th>
                </tr>
                </thead>
                <tbody>
                {assets.map((asset) => (
                    <tr key={asset.id}>
                        <td>{asset.id}</td>
                        <td>{asset.asset_name}</td>
                        <td>{asset.serial_number || "-"}</td>
                        <td>{asset.os_name ? `${asset.os_name} ${asset.os_version || ""}`.trim() : "-"}</td>
                        <td>{asset.ip_address || "-"}</td>
                        <td>{asset.mac_address || "-"}</td>
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