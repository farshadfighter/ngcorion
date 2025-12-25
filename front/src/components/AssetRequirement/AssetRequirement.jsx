import { useState, useEffect, useRef } from "react";
import { useDispatch, useSelector } from "react-redux";
import { clearMessages } from "../../store/requirementSlice";
import api from "../../config/api";
import { AssetTypeTab } from "./AssetTypeTab";
import { OwnersTab } from "./OwnersTab";
import { LocationsTab } from "./LocationsTab";
import { NetworkZoneTab } from "./NetworkZoneTab";
import { OSCatalogTab } from "./OSCatalogTab";
import { VendorsTab } from "./VendorsTab";
import { DependenciesTab } from "./DependenciesTab";
import { StatusTab } from "./StatusTab";
import { ConfidentialityTab } from "./ConfidentialityTab";
import { RiskLevelsTab } from "./RiskLevelsTab";

const TABS = [
    { id: "asset-type", label: "Asset Type" },
    { id: "owners", label: "Owners" },
    { id: "location", label: "Location" },
    { id: "network-zone", label: "Network Zone" },
    { id: "os-catalog", label: "Os Catalog" },
    { id: "vendors", label: "Vendors" },
    { id: "dependencies", label: "Dependencies" },
    { id: "status", label: "Status" },
    { id: "confidentiality", label: "Confidentiality Levels" },
    { id: "risk", label: "Risk Levels" },
];

export const AssetRequirement = () => {
    const dispatch = useDispatch();
    const { successMessage, error } = useSelector((state) => state.requirements);

    const [activeTab, setActiveTab] = useState("asset-type");
    const [uploading, setUploading] = useState(false);
    const fileInputRef = useRef(null);

    // Auto-clear messages after 3 seconds
    useEffect(() => {
        if (successMessage || error) {
            const timer = setTimeout(() => dispatch(clearMessages()), 3000);
            return () => clearTimeout(timer);
        }
    }, [successMessage, error, dispatch]);

    // =============== IMPORT ===============
    const handleImport = () => {
        fileInputRef.current?.click();
    };

    const handleFileChange = async (event) => {
        const file = event.target.files?.[0];
        if (!file) return;

        setUploading(true);

        try {
            const formData = new FormData();
            formData.append("file", file);

            const response = await api.post("/api/asset-requirements/import/excel", formData, {
                headers: {
                    "Content-Type": "multipart/form-data",
                },
            });

            alert("Import successful! " + JSON.stringify(response.data));
            window.location.reload(); // Simple reload; consider fetching data instead in production
        } catch (err) {
            console.error("Import failed:", err);
            alert("Import failed: " + (err.response?.data?.detail || err.message));
        } finally {
            setUploading(false);
            event.target.value = "";
        }
    };

    // =============== EXPORT ===============
    const handleExport = async () => {
        try {
            const response = await api.get("/api/asset-requirements/export/excel", {
                responseType: "blob",
            });

            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement("a");
            link.href = url;
            link.setAttribute("download", `asset-requirements-${Date.now()}.xlsx`);
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.URL.revokeObjectURL(url);

            alert("Export successful!");
        } catch (err) {
            console.error("Export failed:", err);
            alert("Export failed: " + (err.response?.data?.detail || err.message));
        }
    };

    // =============== DOWNLOAD TEMPLATE ===============
    const handleDownloadTemplate = async () => {
        try {
            const response = await api.get("/api/asset-requirements/export/template", {
                responseType: "blob",
            });

            // Create blob with correct MIME type
            const blob = new Blob([response.data], {
                type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            });
            const url = window.URL.createObjectURL(blob);

            // Create and trigger download
            const link = document.createElement("a");
            link.href = url;
            link.setAttribute("download", "asset-requirements-template.xlsx");
            document.body.appendChild(link);
            link.click();

            // Cleanup
            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);
        } catch (err) {
            console.error("Template download failed:", err);
            let message = "Failed to download template.";
            if (err.response?.data?.detail) {
                message = err.response.data.detail;
            } else if (err.code === "ERR_NETWORK") {
                message = "Network error. Please check CORS or backend settings.";
            }
            alert(message);
        }
    };

    // =============== RENDER TABS ===============
    const renderTabContent = () => {
        switch (activeTab) {
            case "asset-type":
                return <AssetTypeTab />;
            case "owners":
                return <OwnersTab />;
            case "location":
                return <LocationsTab />;
            case "network-zone":
                return <NetworkZoneTab />;
            case "os-catalog":
                return <OSCatalogTab />;
            case "vendors":
                return <VendorsTab />;
            case "dependencies":
                return <DependenciesTab />;
            case "status":
                return <StatusTab />;
            case "confidentiality":
                return <ConfidentialityTab />;
            case "risk":
                return <RiskLevelsTab />;
            default:
                return <AssetTypeTab />;
        }
    };

    return (
        <div className="asset-requirement-container">
            {/* Header with buttons */}
            <div className="requirement-header">
                <div className="requirement-actions">
                    <button
                        className="btn-import"
                        onClick={handleImport}
                        disabled={uploading}
                    >
                        {uploading ? "⏳ Importing..." : "⬇ Import"}
                    </button>
                    <button className="btn-export" onClick={handleExport}>
                        ⬆ Export
                    </button>
                    {/* ✅ NEW: Download Template Button */}
                    <button className="btn-download-template" onClick={handleDownloadTemplate}>
                        📥 Download Template
                    </button>
                </div>
            </div>

            {/* Hidden file input */}
            <input
                ref={fileInputRef}
                type="file"
                accept=".xlsx,.xls"
                onChange={handleFileChange}
                style={{ display: "none" }}
            />

            {/* Success/Error Messages */}
            {successMessage && <div className="alert alert-success">{successMessage}</div>}
            {error && <div className="alert alert-error">{error}</div>}

            {/* Tabs */}
            <div className="requirement-tabs">
                {TABS.map((tab) => (
                    <div
                        key={tab.id}
                        className={`requirement-tab ${activeTab === tab.id ? "active" : ""}`}
                        onClick={() => setActiveTab(tab.id)}
                    >
                        {tab.label}
                    </div>
                ))}
            </div>

            {/* Tab Content */}
            <div className="requirement-content">{renderTabContent()}</div>
        </div>
    );
};