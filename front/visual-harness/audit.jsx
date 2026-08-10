/* Auditing dashboard visual check — the real AuditingDashboard against a static
   store, so the whole screen renders without a backend. Not part of the app. */
import React from "react";
import ReactDOM from "react-dom/client";
import { Provider } from "react-redux";
import { configureStore } from "@reduxjs/toolkit";

import "../src/index.css";
import "../src/assets/AuditingDashboard.css";

import { AuditingDashboard } from "../src/components/Auditing/AuditingDashboard";

// ── Sessions feed the panels that predate the aggregate endpoints ────────────
const DEVICES = ["cisco", "fortinet", "linux", "windows", "apache"];
const sessions = Array.from({ length: 18 }, (_, i) => ({
    session_id: i + 1,
    asset_id: i + 1,
    asset_name: ["DC01", "FW-Core", "SW-Access", "Linux02", "Web01"][i % 5] + `-${i + 1}`,
    device_type: DEVICES[i % DEVICES.length],
    sub_device_type: DEVICES[i % DEVICES.length],
    status: "completed",
    started_at: new Date(2026, 6 - (i % 6), 10 + i).toISOString(),
    compliance_pct: [92, 82, 71, 78, 90, 64, 88, 55][i % 8],
    compliance: {
        compliance_pct: [92, 82, 71, 78, 90, 64, 88, 55][i % 8],
        total_checks: 67,
        failed: [5, 12, 19, 15, 7, 24, 8, 30][i % 8],
    },
}));

// ── Aggregate endpoint payloads ──────────────────────────────────────────────
const auditDashboard = {
    overview: {
        total_sessions: 18,
        completed_sessions: 18,
        failed_sessions: 0,
        running_sessions: 0,
        audited_assets: 2145,
        never_audited_assets: 255,
        total_checks: 3900,
        passed_checks: 3276,
        failed_checks: 3284,
        average_compliance: 84,
    },
    severity: {
        items: [
            { severity: "critical", count: 5 },
            { severity: "high", count: 16 },
            { severity: "medium", count: 10 },
            { severity: "low", count: 20 },
        ],
    },
    topFailed: {
        items: [
            { check_number: "Password Policy", check_title: "Password policy enforced", fail_count: 5, affected_assets: 3, severity: "high" },
            { check_number: "SNMP Security", check_title: "SNMP v3 only", fail_count: 5, affected_assets: 2, severity: "medium" },
            { check_number: "NTP Configuration", check_title: "NTP configured", fail_count: 16, affected_assets: 8, severity: "low" },
            { check_number: "Syslog Configuration", check_title: "Syslog enabled", fail_count: 16, affected_assets: 7, severity: "medium" },
            { check_number: "SSH Hardening", check_title: "SSH hardened", fail_count: 16, affected_assets: 9, severity: "high" },
        ],
    },
    trend: {
        points: Array.from({ length: 30 }, (_, i) => ({
            period: `2026-02-${String(i + 1).padStart(2, "0")}`,
            average_compliance: [71,77,52,62,80,84,88,94,71,77,52,62,80,84,88,71,77,52,62,80,84,88,94,71,77,52,62,80,84,88][i],
            session_count: 2 + (i % 4),
        })),
    },
    byDevice: { items: [] },
    recent: { items: [] },
    remediation: {
        open_findings: 3284,
        fixed_this_month: 642,
        fixed_total: 780,
        resolved_percent: 19,
    },
    critical: {
        items: Array.from({ length: 10 }, (_, i) => ({
            id: i + 1,
            session_id: 1,
            asset_name: i === 0 ? "DC01" : "FW-Core",
            check_number: "SMBv1",
            check_title: "SMBv1 protocol disabled",
            severity: i < 3 ? "high" : "medium",
            checked_at: "2026-06-12T10:00:00Z",
        })),
    },
    failedPanels: [],
    isLoading: false,
    error: null,
};

const store = configureStore({
    reducer: {
        auth: (s = { username: "Ali Mansori", role: "admin", permissions: {} }) => s,
        audit: (s = { sessions, isLoading: false }) => s,
        hardening: (s = { deviceTypes: [] }) => s,
        auditDashboard: (s = auditDashboard) => s,
    },
});

ReactDOM.createRoot(document.getElementById("root")).render(
    <Provider store={store}>
        <AuditingDashboard />
    </Provider>
);
