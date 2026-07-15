/* Visual review harness — renders the "See Result" views with mock data.
   Not part of the app; used only for headless screenshots. */
import React from "react";
import ReactDOM from "react-dom/client";
import { Provider } from "react-redux";
import { configureStore } from "@reduxjs/toolkit";

import "../src/index.css";
import "../src/assets/Dashboard.css";
import "../src/assets/Auditing.css";

import { AuditingResultModal } from "../src/components/Auditing/AuditingResultModal";
import { FixUnsuccessfulResults } from "../src/components/Hardening/FixUnsuccessfulResults";
import { HardeningResults } from "../src/components/Hardening/HardeningResults";

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
