import { useState, useEffect } from "react";
import api from "../../config/api";

const STATUS_FALLBACK = ["active", "standby", "decommissioned", "unknown"];
const CONFIDENTIALITY_FALLBACK = ["public", "internal", "confidential", "critical"];
const RISK_FALLBACK = ["low", "medium", "high", "critical"];

function mapEnumOptions(raw, fallbackArray) {
    let source = [];

    if (Array.isArray(raw) && raw.length > 0) {
        source = raw;
    } else {
        source = fallbackArray || [];
    }

    return source.map((item) => {
        if (typeof item === "string") {
            return { value: item, label: item };
        }

        if (item && typeof item === "object") {
            if ("value" in item && "label" in item) {
                return { value: String(item.value), label: String(item.label) };
            }

            const keys = Object.keys(item);
            const firstKey = keys[0] || "";
            const value =
                item.value ??
                item.key ??
                firstKey ??
                JSON.stringify(item);
            const label =
                item.label ??
                item.name ??
                item.title ??
                value;

            return { value: String(value), label: String(label) };
        }

        return { value: String(item), label: String(item) };
    });
}

export const useAssetFormOptions = () => {
    const [isLoading, setIsLoading] = useState(true);
    const [assetTypes, setAssetTypes] = useState([]);
    const [locations, setLocations] = useState([]);
    const [owners, setOwners] = useState([]);
    const [zones, setZones] = useState([]);
    const [vendors, setVendors] = useState([]);
    const [osCatalog, setOSCatalog] = useState([]);
    
    const [statusOptions, setStatusOptions] = useState(
        () => mapEnumOptions(null, STATUS_FALLBACK)
    );
    const [confidentialityOptions, setConfidentialityOptions] = useState(
        () => mapEnumOptions(null, CONFIDENTIALITY_FALLBACK)
    );
    const [riskOptions, setRiskOptions] = useState(
        () => mapEnumOptions(null, RISK_FALLBACK)
    );

    const loadOptions = async () => {
        setIsLoading(true);

        try {
            const [
                typesRes,
                locsRes,
                ownersRes,
                zonesRes,
                vendorsRes,
                osCatalogRes,
                statusRes,
                confRes,
                riskRes
            ] = await Promise.allSettled([
                api.get("/api/asset-types/"),
                api.get("/api/locations/"),
                api.get("/api/owners/"),
                api.get("/api/zones/"),
                api.get("/api/vendors/"),
                api.get("/api/os-catalog/"),
                api.get("/api/enums/status"),
                api.get("/api/enums/confidentiality"),
                api.get("/api/enums/risk")
            ]);

            if (typesRes.status === "fulfilled" && Array.isArray(typesRes.value.data)) {
                setAssetTypes(typesRes.value.data);
            }

            if (locsRes.status === "fulfilled" && Array.isArray(locsRes.value.data)) {
                setLocations(locsRes.value.data);
            }

            if (ownersRes.status === "fulfilled" && Array.isArray(ownersRes.value.data)) {
                setOwners(ownersRes.value.data);
            }

            if (zonesRes.status === "fulfilled" && Array.isArray(zonesRes.value.data)) {
                setZones(zonesRes.value.data);
            }

            if (vendorsRes.status === "fulfilled" && Array.isArray(vendorsRes.value.data)) {
                setVendors(vendorsRes.value.data);
            }

            if (osCatalogRes.status === "fulfilled" && Array.isArray(osCatalogRes.value.data)) {
                setOSCatalog(osCatalogRes.value.data);
            }

            let statusRaw = null;
            if (statusRes.status === "fulfilled") {
                statusRaw = statusRes.value.data;
            }
            setStatusOptions(mapEnumOptions(statusRaw, STATUS_FALLBACK));

            let confRaw = null;
            if (confRes.status === "fulfilled") {
                confRaw = confRes.value.data;
            }
            setConfidentialityOptions(
                mapEnumOptions(confRaw, CONFIDENTIALITY_FALLBACK)
            );

            let riskRaw = null;
            if (riskRes.status === "fulfilled") {
                riskRaw = riskRes.value.data;
            }
            setRiskOptions(mapEnumOptions(riskRaw, RISK_FALLBACK));

        } catch (err) {
            console.error("Failed to load dropdown options:", err);
        } finally {
            setIsLoading(false);
        }
    };

    // Declared after loadOptions on purpose: `const` is not hoisted, so an
    // effect placed above it referenced the binding before initialisation.
    useEffect(() => {
        loadOptions();
    }, []);

    return {
        isLoading,
        assetTypes,
        locations,
        owners,
        zones,
        vendors,
        osCatalog,
        statusOptions,
        confidentialityOptions,
        riskOptions
    };
};
