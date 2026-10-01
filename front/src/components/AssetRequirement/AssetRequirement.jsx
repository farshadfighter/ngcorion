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
import { OthersTab } from "./OthersTab"; // <i className="fa-solid fa-star" /> Combined tab
import { t } from "../../i18n";

// 🔥 Updated TABS - Dependencies حذف شد، 3 تب ترکیب شدند
const TABS = [
    { id: "asset-type", label: t("Asset Type") },
    { id: "owners", label: t("Owners") },
    { id: "location", label: t("Location") },
    { id: "network-zone", label: t("Network Zone") },
    { id: "os-catalog", label: t("OS Catalog") },
    { id: "vendors", label: t("Vendors") },
    { id: "others", label: t("Others") }, // <i className="fa-solid fa-star" /> Status + Confidentiality + Risk
];

export const AssetRequirement = () => {
    const dispatch = useDispatch();
    const { successMessage, error } = useSelector((state) => state.requirements);

    const [activeTab, setActiveTab] = useState("asset-type");
    const [uploading, setUploading] = useState(false);
    const fileInputRef = useRef(null);

    useEffect(() => {
        if (successMessage || error) {
            const timer = setTimeout(() => dispatch(clearMessages()), 3000);
            return () => clearTimeout(timer);
        }
    }, [successMessage, error, dispatch]);

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

            // Do NOT set Content-Type manually here: the browser needs to compute it
            // itself (including the multipart boundary) when sending a FormData body.
            // A hardcoded "multipart/form-data" header has no boundary, so the
            // backend can't parse the request and the import silently fails.
            const response = await api.post("/api/asset-requirements/import/excel", formData);

            alert(t("Import successful! {{result}}", { result: JSON.stringify(response.data) }));
            window.location.reload();
        } catch (err) {
            console.error("Import failed:", err);
            alert(t("Import failed: {{error}}", { error: err.response?.data?.detail || err.message }));
        } finally {
            setUploading(false);
            event.target.value = "";
        }
    };

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

            alert(t("Export successful!"));
        } catch (err) {
            console.error("Export failed:", err);
            alert(t("Export failed: {{error}}", { error: err.response?.data?.detail || err.message }));
        }
    };

    const handleDownloadTemplate = async () => {
        try {
            const response = await api.get("/api/asset-requirements/export/template", {
                responseType: "blob",
            });

            const blob = new Blob([response.data], {
                type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            });
            const url = window.URL.createObjectURL(blob);

            const link = document.createElement("a");
            link.href = url;
            link.setAttribute("download", "asset-requirements-template.xlsx");
            document.body.appendChild(link);
            link.click();

            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);
        } catch (err) {
            console.error("Template download failed:", err);
            let message = t("Failed to download template.");
            if (err.response?.data?.detail) {
                message = err.response.data.detail;
            } else if (err.code === "ERR_NETWORK") {
                message = t("Network error. Please check CORS or backend settings.");
            }
            alert(message);
        }
    };

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
            case "others":
                return <OthersTab />; // <i className="fa-solid fa-star" /> Combined tab
            default:
                return <AssetTypeTab />;
        }
    };

    return (
        <div className="asset-requirement-container">
            {/* Header */}
            <div className="requirement-header">
                <h1 className="page-title">{t("Asset Requirement")}</h1>
                <div className="requirement-actions">
                    <button
                        className="btn-header"
                        onClick={handleImport}
                        disabled={uploading}
                    >
                        {uploading ? t("⏳ Importing...") : t("⬇ Import")}
                    </button>
                    <button className="btn-header" onClick={handleExport}>
                       {t("⬆ Export")}
                    </button>
                    <button className="btn-header" onClick={handleDownloadTemplate}>

                        <i className="fa-solid fa-download"></i>   {" "}{t("Download Template")}

                    </button>
                </div>
            </div>

            <input
                ref={fileInputRef}
                type="file"
                accept=".xlsx,.xls"
                onChange={handleFileChange}
                style={{ display: "none" }}
            />

            {successMessage && <div className="alert alert-success">{successMessage}</div>}
            {error && <div className="alert alert-error">{error}</div>}

            {/* 🎨 Beautiful Tabs - Same style as Asset List */}
            <div className="requirement-tabs">
                {TABS.map((tab) => (
                    <button
                        key={tab.id}
                        className={`requirement-tab ${activeTab === tab.id ? "active" : ""}`}
                        onClick={() => setActiveTab(tab.id)}
                    >
                        {tab.label}
                    </button>
                ))}
            </div>

            <div className="requirement-content">{renderTabContent()}</div>
        </div>
    );
};
