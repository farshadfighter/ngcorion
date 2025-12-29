import { useEffect, useState } from "react";
import api from "../../config/api";

export const NetworkSystemTab = ({ assets, onEdit, onDelete }) => {
    const [portsMap, setPortsMap] = useState({});

    useEffect(() => {
        if (!assets.length) return;

        const missingAssets = assets.filter(
            (asset) => portsMap[asset.id] === undefined
        );

        if (!missingAssets.length) return;

        const fetchPorts = async () => {
            const result = { ...portsMap };

            await Promise.all(
                missingAssets.map(async (asset) => {
                    try {
                        const res = await api.get(
                            `/api/discovery/assets/${asset.id}/ports`
                        );

                        const payload = res.data;

                        result[asset.id] =
                            Array.isArray(payload)
                                ? payload
                                : Array.isArray(payload?.ports)
                                    ? payload.ports
                                    : Array.isArray(payload?.data)
                                        ? payload.data
                                        : [];
                    } catch {
                        result[asset.id] = [];
                    }
                })
            );

            setPortsMap(result);
        };

        fetchPorts();
    }, [assets, portsMap]);

    const renderPorts = (assetId) => {
        const ports = portsMap[assetId];
        if (!ports || ports.length === 0) return "-";

        const preview = ports
            .slice(0, 3)
            .map((p) => `${p.port_number}/${p.protocol}`)
            .join(", ");

        return ports.length > 3
            ? `${preview} +${ports.length - 3}`
            : preview;
    };

    return (
        <div className="table-container">
            <table className="assets-table">
                <thead>
                <tr>
                    <th>ID</th>
                    <th>Asset Name</th>
                    <th>Serial</th>
                    <th>OS</th>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Ports</th>
                    <th>Actions</th>
                </tr>
                </thead>

                <tbody>
                {assets.map((asset) => (
                    <tr key={asset.id}>
                        <td>{asset.id}</td>
                        <td>{asset.asset_name}</td>
                        <td>{asset.serial_number || "-"}</td>
                        <td>
                            {asset.os_name
                                ? `${asset.os_name} ${asset.os_version || ""}`.trim()
                                : "-"}
                        </td>
                        <td>{asset.ip_address || "-"}</td>
                        <td>{asset.mac_address || "-"}</td>
                        <td>{renderPorts(asset.id)}</td>
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
