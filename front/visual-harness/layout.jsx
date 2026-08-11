/* Full sidebar + hardening dashboard, to check menu visibility and sizing. */
import React from "react";
import ReactDOM from "react-dom/client";
import { Provider } from "react-redux";
import { configureStore } from "@reduxjs/toolkit";
import { MemoryRouter, Routes, Route } from "react-router-dom";

// Bundled locally, same as the app — see src/main.jsx.
import "@fortawesome/fontawesome-free/css/all.min.css";

import "../src/index.css";
import "../src/assets/Dashboard.css";
import "../src/assets/HardeningDashboard.css";

import { DashboardLayout } from "../src/components/DashboardLayout";
import { HardeningDashboard } from "../src/components/Hardening/dashboard/HardeningDashboard";

const overview = { hardening_score:87, hardened_assets:1920, non_hardened_assets:280,
  applied_policies:18540, failed_actions:84, pending_actions:212, distinct_controls:340,
  automation:{ executed_tasks:5400, success_rate:80, success:2145, failed:255 } };
const progress = { points:[71,77,52,62,80,84,88,94,71,77,52,62].map((r,i)=>(
  { period:`2026-${String(i+1).padStart(2,'0')}`, success_rate:r, total:100+i*7, successful:r })) };
const mk = (arr) => ({ items: arr });
const coverage = mk([["Firewall",92],["Switch",82],["Windows",71],["Linux",78],["F5",90]]
  .map(([name,percent])=>({name,percent,total_assets:100,hardened_assets:percent})));
const vendors = mk([["Cisco",92],["Fortinet",82],["Microsoft",71],["VMware",78],["F5",90]]
  .map(([name,percent])=>({name,percent,total:100,successful:percent})));
const compliance = mk([["CIS Level 1",92],["CIS Level 2",82],["Internal Security Baseline",71]]
  .map(([level,percent])=>({level,percent,total:100,successful:percent})));
const activities = mk(Array.from({length:5},(_,i)=>({ id:i+1,
  check_number:`FG-BL-0${10+i}`, check_title:["SSH Hardened","TLS Updated"][i%2],
  asset_name:["DC01","Linux02"][i%2], status:["success","failed"][i%2],
  action_type:"execute", created_at:new Date(Date.now()-i*3600e3).toISOString(), completed_at:null })));

const requiring = mk([["DC01","critical",18,4],["Linux02","critical",14,2],["Linux03","high",9,6],
  ["SW-Core","high",7,1],["FG-200","medium",4,3]].map(([asset_name,risk_level,active,fixed],i)=>(
  {asset_id:i+1,asset_name,risk_level,active_findings_count:active,resolved_by_hardening:fixed})));
const missing = mk([["FG-BL-002","Disable SMBv1",12],["FG-BL-010","Enable banner",9],
  ["LNX-5.3.1","Enable auditd",7],["WIN-2.3.1","Disable guest",5],["FG-SYS-005","Disable USB",3]]
  .map(([check_number,check_title,affected_assets])=>({check_number,check_title,affected_assets,severity:"high"})));

const store = configureStore({ reducer: {
  auth:(s={username:"Ali Mansori",role:"admin",permissions:{}})=>s,
  license:(s={status:null,isLoading:false,modules:{}})=>s,
  hardeningDashboard:(s={overview,progress,coverage,vendors,compliance,activities,requiring,missing,
    failedPanels:[],isLoading:false,error:null})=>s,
}});

ReactDOM.createRoot(document.getElementById("root")).render(
  <Provider store={store}>
    <MemoryRouter initialEntries={["/hardening/overview"]}>
      <Routes>
        <Route element={<DashboardLayout />}>
          <Route path="/hardening/overview" element={<HardeningDashboard />} />
        </Route>
      </Routes>
    </MemoryRouter>
  </Provider>
);
