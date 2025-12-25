export const LocationOwnerTab = ({ assets, onEdit, onDelete }) => {
    const getStatusBadge = (status) => {
        const statusMap = {
            active: { label: "Active", class: "badge-active" },
            standby: { label: "Standby", class: "badge-standby" },
            decommissioned: { label: "Decommissioned", class: "badge-inactive" },
            unknown: { label: "Unknown", class: "badge-unknown" },
        };
        const statusInfo = statusMap[status] || statusMap.unknown;
        return <span className={`badge ${statusInfo.class}`}>{statusInfo.label}</span>;
    };

    return (
        <div className="table-container">
            <table className="assets-table">
                <thead>
                <tr>
                    <th>ID</th>
                    <th>Asset Name</th>
                    <th>Location</th>
                    <th>Zone</th>
                    <th>Owner</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
                </thead>
                <tbody>
                {assets.map((asset) => (
                    <tr key={asset.id}>
                        <td>{asset.id}</td>
                        <td>{asset.asset_name}</td>
                        <td>{asset.location_id || "-"}</td>
                        <td>{asset.network_zone || "-"}</td>
                        <td>{asset.owner_id || "-"}</td>
                        <td>{getStatusBadge(asset.status)}</td>
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