import { useEffect, useState } from "react";
import api from "../../config/api";

export const AssetPortsTable = ({ assetId }) => {
    const [ports, setPorts] = useState([]);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (!assetId) return;

        const fetchPorts = async () => {
            setLoading(true);
            try {
                const res = await api.get(
                    `/api/discovery/assets/${assetId}/ports`
                );

                setPorts(Array.isArray(res.data) ? res.data : []);
            } catch {
                setPorts([]);
            } finally {
                setLoading(false);
            }
        };

        fetchPorts();
    }, [assetId]);

    return (
        <div style={{ padding: "0 16px 16px" }}>
            <div
                style={{
                    fontSize: 13,
                    fontWeight: 600,
                    color: "#2C3E50",
                    padding: "12px 0",
                }}
            >
                Open Ports
            </div>

            {loading && (
                <div className="loading-spinner">Loading ports...</div>
            )}

            {!loading && ports.length === 0 && (
                <div className="no-data">No ports detected</div>
            )}

            {!loading && ports.length > 0 && (
                <div className="table-container">
                    <table className="assets-table">
                        <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Service</th>
                            <th>Product</th>
                            <th>Version</th>
                            <th>Status</th>
                        </tr>
                        </thead>
                        <tbody>
                        {ports.map((p, idx) => (
                            <tr key={idx}>
                                <td>{p.port_number}</td>
                                <td>{p.protocol}</td>
                                <td>{p.service_name || "-"}</td>
                                <td>{p.service_product || "-"}</td>
                                <td>{p.service_version || "-"}</td>
                                <td>{p.state}</td>
                            </tr>
                        ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
};
