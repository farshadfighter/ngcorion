export const SecurityAuditTab = ({ assets, onEdit, onDelete }) => {
    // Helper function برای فرمت تاریخ
    const formatDate = (dateString) => {
        if (!dateString) return "-";
        const date = new Date(dateString);
        return date.toLocaleDateString("en-US", {
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
        });
    };

    // Helper function برای نمایش confidentiality badge
    const getConfidentialityBadge = (level) => {
        const levelMap = {
            public: { label: "public", class: "badge-public" },
            internal: { label: "internal", class: "badge-internal" },
            confidential: { label: "confidential", class: "badge-confidential" },
            critical: { label: "critical", class: "badge-critical" },
        };
        const levelInfo = levelMap[level] || { label: "-", class: "" };
        return levelInfo.class ? (
            <span className={`badge ${levelInfo.class}`}>{levelInfo.label}</span>
        ) : (
            "-"
        );
    };

    // Helper function برای نمایش risk badge
    const getRiskBadge = (level) => {
        const levelMap = {
            low: { label: "low", class: "badge-risk-low" },
            medium: { label: "medium", class: "badge-risk-medium" },
            high: { label: "high", class: "badge-risk-high" },
            critical: { label: "critical", class: "badge-risk-critical" },
        };
        const levelInfo = levelMap[level] || { label: "-", class: "" };
        return levelInfo.class ? (
            <span className={`badge ${levelInfo.class}`}>{levelInfo.label}</span>
        ) : (
            "-"
        );
    };

    return (
        <div className="table-container">
            <table className="assets-table">
                <thead>
                <tr>
                    <th>ID</th>
                    <th>Asset Name</th>
                    <th>Confidentiality</th>
                    <th>Risk</th>
                    <th>Last Audit</th>
                    <th>Last Patch</th>
                    <th>Value</th>
                    <th>Actions</th>
                </tr>
                </thead>
                <tbody>
                {assets.map((asset) => (
                    <tr key={asset.id}>
                        <td>{asset.id}</td>
                        <td>{asset.asset_name}</td>
                        <td>{getConfidentialityBadge(asset.confidentiality_level)}</td>
                        <td>{getRiskBadge(asset.risk_level)}</td>
                        <td>{formatDate(asset.last_audit_date)}</td>
                        <td>{formatDate(asset.last_patch_date)}</td>
                        <td>{asset.asset_value || "-"}</td>
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