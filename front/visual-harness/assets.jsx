/* Asset Management dashboard visual check — the real component against a static
   store, so the screen renders without a backend. Not part of the app.

   The critical-assets tile fetches /api/risk/summary at mount; with no backend
   here that request fails and the tile falls back to "—", which is exactly the
   no-data behaviour worth eyeballing. */
import React from "react";
import ReactDOM from "react-dom/client";
import { Provider } from "react-redux";
import { configureStore } from "@reduxjs/toolkit";

import "../src/index.css";
import "../src/assets/AssetManagementDashboard.css";

import { AssetManagementDashboard } from "../src/components/AssetManagement/AssetManagementDashboard";

const TYPES = [
    { id: 1, type_name: "Firewall" },
    { id: 2, type_name: "Switch" },
    { id: 3, type_name: "Server" },
    { id: 4, type_name: "Router" },
];
const VENDORS = ["Cisco", "Fortinet", "HP", "Dell", "VMware"];
const OSES = ["Windows Server 2019", "Ubuntu 22.04", "RHEL 9", "FortiOS 7.2", "IOS XE"];

const now = Date.now();
const assets = Array.from({ length: 42 }, (_, i) => ({
    id: i + 1,
    asset_name: `asset-${String(i + 1).padStart(2, "0")}`,
    status: i % 5 === 0 ? "decommissioned" : "active",
    // A third of them land inside the 30-day window.
    created_at: new Date(now - (i % 3 === 0 ? 5 : 90) * 86400000).toISOString(),
    asset_type_id: TYPES[i % TYPES.length].id,
    manufacturer: VENDORS[i % VENDORS.length],
    os_name: OSES[i % OSES.length],
    // Deliberately absent: asset_inventory.risk_level is never populated.
    risk_level: null,
}));

const store = configureStore({
    reducer: {
        auth: (s = { username: "Ali Mansori", role: "admin", permissions: {} }) => s,
        assets: (s = { assets, isLoading: false }) => s,
    },
});

ReactDOM.createRoot(document.getElementById("root")).render(
    <Provider store={store}>
        <AssetManagementDashboard />
    </Provider>
);
