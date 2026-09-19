import { configureStore } from "@reduxjs/toolkit";
import authReducer from "./authSlice";
import userReducer from "./userSlice";
import assetReducer from "./assetSlice";
import requirementReducer from "./requirementSlice";
import discoveryReducer from "./discoverySlice";
import auditReducer from "./auditSlice";
import hardeningReducer from "./hardeningSlice";
import licenseReducer from "./licenseSlice";
import logsReducer from "./logsSlice.js";
import riskReducer from "./riskSlice.js";
import riskDetailReducer from "./riskDetailSlice.js";
import hardeningDashboardReducer from "./hardeningDashboardSlice.js";
import systemConfigReducer from "./systemConfigSlice.js";
import auditDashboardReducer from "./auditDashboardSlice.js";
import overviewDashboardReducer from "./overviewDashboardSlice.js";
import topologyReducer from "./topologySlice.jsx";


export const store = configureStore({
    reducer: {
        auth: authReducer,
        users: userReducer,
        assets: assetReducer,
        requirements: requirementReducer,
        discovery: discoveryReducer,
        audit: auditReducer,
        hardening: hardeningReducer,
        license: licenseReducer,
        logs: logsReducer,
        risk: riskReducer,
        riskDetail: riskDetailReducer,
        hardeningDashboard: hardeningDashboardReducer,
        systemConfig: systemConfigReducer,
        auditDashboard: auditDashboardReducer,
        overviewDashboard: overviewDashboardReducer,
        topology: topologyReducer,
    },
});