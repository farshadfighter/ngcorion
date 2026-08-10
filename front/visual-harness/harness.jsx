/* Visual review harness — renders the "See Result" views with mock data.
   Not part of the app; used only for headless screenshots. */
import React from "react";
import ReactDOM from "react-dom/client";
import { Provider } from "react-redux";
import { configureStore } from "@reduxjs/toolkit";

import "../src/index.css";
import "../src/assets/Dashboard.css";
import "../src/assets/Auditing.css";
// LogsPage reuses .requirement-table / .table-container from AssetRequirement.css,
// which App.jsx loads globally.
import "../src/assets/AssetRequirement.css";
import "../src/assets/LogsPage.css";
import "../src/assets/HardeningDashboard.css";

import { AuditingResultModal } from "../src/components/Auditing/AuditingResultModal";
import { FixUnsuccessfulResults } from "../src/components/Hardening/FixUnsuccessfulResults";
import { HardeningResults } from "../src/components/Hardening/HardeningResults";
import { LogsPage } from "../src/components/Logs/LogsPage";
import { HardeningDashboard } from "../src/components/Hardening/dashboard/HardeningDashboard";

// ── Mock data ────────────────────────────────────────────────────────────────

const longEvidence = [
    "FAIL — 4 of 133 policies violate the rule:",
    "  Policy ID 13 (Allow-Web-Traffic-From-Branch-Offices-To-Datacenter): set service \"ALL\" — overly permissive service definition on an accept policy",
    "  Policy ID 27 (Legacy-FTP): set service \"ALL\"",
    "  Policy ID 55 (Temp-Vendor-Access-2024-Q3-Remote-Maintenance-Window): set service \"ALL\"",
    "  Policy ID 101 (test): set service \"ALL\"",
    "",
    "Remediation:",
    "  config firewall policy",
    "    edit 13",
    "      set service \"HTTPS\" \"SSH\" \"DNS\"",
    "    next",
    "  end",
].join("\n");

const auditResults = [
    { id: 1,  check_number: "FG-BL-001", check_title: "Ensure DNS server is configured", severity: "medium", level: "L1", vdom: "global", status: "PASS", evidence_snippet: "set primary 96.45.45.45\nset secondary 96.45.46.46", checked_at: "2026-07-14T10:00:00Z" },
    { id: 2,  check_number: "FG-BL-002", check_title: "Ensure intra-zone traffic is not always allowed and administrative access over insecure protocols (telnet / HTTP) is disabled on every interface of the device", severity: "high", level: "L1", vdom: "global", status: "FAIL", evidence_snippet: longEvidence, checked_at: "2026-07-14T10:00:00Z" },
    { id: 3,  check_number: "FG-BL-010", check_title: "Ensure 'Pre-Login Banner' is set", severity: "low", level: "L1", vdom: "global", status: "FAIL", evidence_snippet: "pre-login-banner : disable", checked_at: "2026-07-14T10:00:00Z" },
    { id: 4,  check_number: "FG-POL-001", check_title: "Detect unused firewall policies", severity: "medium", level: "L1", vdom: "root", status: "FAIL", needs_review: true, evidence_snippet: longEvidence, checked_at: "2026-07-14T10:00:00Z" },
    { id: 5,  check_number: "FG-POL-001", check_title: "Detect unused firewall policies", severity: "medium", level: "L1", vdom: "dmz-segment-A", status: "PASS", evidence_snippet: "All 12 policies carry traffic", checked_at: "2026-07-14T10:00:00Z" },
    { id: 6,  check_number: "FG-UTM-002", check_title: "Ensure antivirus profile is applied to all outbound accept policies", severity: "high", level: "L1", vdom: "root", status: "FAIL", needs_review: true, evidence_snippet: "Policy ID 13 (Allow-Web): no av-profile", checked_at: "2026-07-14T10:00:00Z" },
    { id: 7,  check_number: "FG-BL-040", check_title: "Ensure management GUI listens on secure port only — this is a deliberately very long recommendation title to exercise wrapping behaviour of the recommendation column in the results table at narrow widths", severity: "medium", level: "L2", vdom: "dmz-segment-A", status: "RUNNING", evidence_snippet: null, checked_at: "2026-07-14T10:00:00Z" },
    { id: 8,  check_number: "FG-BL-080", check_title: "Ensure policies do not use ALL as service", severity: "high", level: "L1", vdom: "root", status: "ERROR", evidence_snippet: "device returned unreadable policy table", checked_at: "2026-07-14T10:00:00Z" },
];

const auditSession = {
    session_id: 42,
    asset_name: "FortiGate-Datacenter-Edge-Firewall-01",
    target_ip: "10.20.30.40",
    device_type: "fortinet",
    sub_device_type: "fortinet",
    status: "completed",
    started_at: "2026-07-14T09:58:00Z",
    completed_at: "2026-07-14T10:04:00Z",
    compliance: { total_checks: 76, passed_checks: 41, failed_checks: 33 },
};

const cisChecks = [
    { id: 1,  check_number: "FG-BL-001", check_title: "Ensure DNS server is configured", status: "PASS", vdom: "global" },
    { id: 2,  check_number: "FG-BL-002", check_title: "Ensure intra-zone traffic is not always allowed and administrative access over insecure protocols (telnet / HTTP) is disabled on every interface of the device", status: "FAIL", vdom: "global" },
    { id: 3,  check_number: "FG-BL-010", check_title: "Ensure 'Pre-Login Banner' is set", status: "FAIL", vdom: "global", justHardened: true },
    { id: 4,  check_number: "FG-POL-001", check_title: "Detect unused firewall policies", status: "FAIL", vdom: "root", manualApplied: true, hardenedVdom: "root" },
    { id: 5,  check_number: "FG-POL-001", check_title: "Detect unused firewall policies", status: "PASS", vdom: "dmz-segment-A" },
    { id: 6,  check_number: "FG-UTM-002", check_title: "Ensure antivirus profile is applied to all outbound accept policies", status: "FAIL", vdom: "root" },
    { id: 7,  check_number: "FG-BL-040", check_title: "Ensure management GUI listens on secure port only — long title to exercise wrapping behaviour of the recommendation column", status: "FAIL", vdom: "dmz-segment-A" },
    { id: 8,  check_number: "FG-BL-080", check_title: "Ensure policies do not use ALL as service", status: "FAIL", vdom: "root" },
];

// FG-BL-010 / FG-BL-080 templated (auto-fixable); others manual → View Fix
const fortinetTemplatedChecks = ["FG-BL-010", "FG-BL-080", "FG-BL-002"];

// Filler rows so the table wrapper actually scrolls at small viewports
for (let i = 0; i < 25; i++) {
    const filler = {
        id: 100 + i,
        check_number: `FG-SYS-${String(i + 1).padStart(3, "0")}`,
        check_title: `Filler check ${i + 1} — makes the table tall enough to scroll`,
        severity: "low", level: "L1",
        vdom: i % 3 === 0 ? "global" : "root",
        status: i % 4 === 0 ? "FAIL" : "PASS",
        evidence_snippet: "example evidence",
        checked_at: "2026-07-14T10:00:00Z",
    };
    auditResults.push(filler);
    cisChecks.push({ ...filler });
}


// ── Logs mock (pagination check) ────────────────────────────────────────────
const SECTIONS = ["Login", "Auditing", "Hardening", "Asset Management", "Auto Discovery"];
const logItems = Array.from({ length: 137 }, (_, i) => ({
    id: `log-${i + 1}`,
    username: "admin",
    action: ["Login", "execute", "preview", "audit_executed"][i % 4],
    asset_name: i % 3 === 0 ? "Cisco" : "-",
    section: SECTIONS[i % SECTIONS.length],
    status: i % 5 === 0 ? "failed" : "success",
    timestamp: new Date(Date.now() - i * 3600_000).toISOString(),
}));


// ── Hardening dashboard mock ────────────────────────────────────────────────
const hdOverview = {
    hardening_score: 87, hardened_assets: 1920, non_hardened_assets: 280,
    applied_policies: 18540, failed_actions: 84, pending_actions: 212,
    distinct_controls: 340,
    automation: { executed_tasks: 5400, success_rate: 80, success: 2145, failed: 255 },
};
const hdProgress = { points: [71,77,52,62,80,84,88,94,71,77,52,62].map((r,i)=>(
    { period: `2026-${String(i+1).padStart(2,'0')}`, success_rate: r, total: 100+i*7, successful: r }
))};
const hdCoverage = { items: [
    { name:"Firewall", total_assets:120, hardened_assets:110, percent:92 },
    { name:"Switch",   total_assets:200, hardened_assets:164, percent:82 },
    { name:"Windows",  total_assets:310, hardened_assets:220, percent:71 },
    { name:"Linux",    total_assets:180, hardened_assets:140, percent:78 },
    { name:"F5",       total_assets:60,  hardened_assets:54,  percent:90 },
]};
const hdVendors = { items: [
    { name:"Cisco",     total:400, successful:368, percent:92 },
    { name:"Fortinet",  total:300, successful:246, percent:82 },
    { name:"Microsoft", total:500, successful:355, percent:71 },
    { name:"VMware",    total:150, successful:117, percent:78 },
    { name:"F5",        total:90,  successful:81,  percent:90 },
]};
const hdCompliance = { items: [
    { level:"L1", total:800, successful:736, percent:92 },
    { level:"L2", total:400, successful:328, percent:82 },
    { level:"INFO", total:120, successful:85, percent:71 },
]};
const hdActivities = { items: Array.from({length:8},(_,i)=>({
    id:i+1, check_number:`FG-BL-0${10+i}`,
    check_title:["SSH Hardened","TLS Updated","Banner set","NTP configured"][i%4],
    asset_name:["DC01","Linux02","FG-200","SW-Core"][i%4],
    status:["success","success","failed","pending"][i%4],
    action_type:"execute",
    created_at:new Date(Date.now()-i*3600_000).toISOString(), completed_at:null,
}))};

// ── Static store (thunks fire and reject against the file server; ignored) ──

const store = configureStore({
    reducer: {
        audit: (state = {
            results: auditResults,
            isLoadingResults: false,
            sessions: [], isLoading: false,
        }) => state,
        hardening: (state = {
            cisChecks,
            fortinetTemplatedChecks,
            isLoading: false,
        }) => state,
        logs: (state = { items: logItems, isLoading: false, isCleared: false }) => state,
        hardeningDashboard: (state = {
            overview: hdOverview, progress: hdProgress, coverage: hdCoverage,
            vendors: hdVendors, compliance: hdCompliance, activities: hdActivities,
            failedPanels: [], isLoading: false, error: null,
        }) => state,
    },
});

// ── View switch (?view=audit | fixres | hardres) ─────────────────────────────

const params = new URLSearchParams(window.location.search);
const view = params.get("view") || "audit";

// ?flat=1 strips vdom from every row to simulate a non-VDOM / cisco device
if (params.get("flat")) {
    auditResults.forEach((r) => delete r.vdom);
    cisChecks.forEach((c) => delete c.vdom);
}
const noop = () => {};

const View = () => {
    if (view === "fixres")
        return <FixUnsuccessfulResults sessionData={auditSession} onClose={noop} onNavigateToAuditing={noop} />;
    if (view === "hdash")
        return <HardeningDashboard />;
    if (view === "logs")
        return <LogsPage />;
    if (view === "hardres")
        return <HardeningResults sessionData={auditSession} onClose={noop} onNavigateToAuditing={noop} />;
    return <AuditingResultModal session={auditSession} isOpen={true} onClose={noop} />;
};

ReactDOM.createRoot(document.getElementById("root")).render(
    <Provider store={store}>
        <View />
    </Provider>
);

// ?scroll=N scrolls the results table wrapper after mount (sticky-header check)
const scrollTo = parseInt(params.get("scroll") || "0", 10);
if (scrollTo > 0) {
    setTimeout(() => {
        const w = document.querySelector(".result-table-wrapper");
        if (w) w.scrollTop = scrollTo;
    }, 500);
}
