import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api";

/**
 * Auditing KPI dashboard data.
 *
 * Six aggregate endpoints are fetched together; each is allowed to fail on its
 * own so one broken panel does not blank the page. Mirrors
 * hardeningDashboardSlice so the two dashboards behave the same way.
 */
const ENDPOINTS = {
    overview: "/api/audit/dashboard/overview",
    severity: "/api/audit/dashboard/findings-by-severity",
    topFailed: "/api/audit/dashboard/top-failed-controls",
    trend: "/api/audit/dashboard/compliance-trend",
    byDevice: "/api/audit/dashboard/compliance-by-device-type",
    recent: "/api/audit/dashboard/recent-sessions",
    remediation: "/api/audit/dashboard/remediation-progress",
    critical: "/api/audit/dashboard/critical-findings",
};

const PARAMS = {
    trend: { days: 30 },
    topFailed: { limit: 10 },
    recent: { limit: 10 },
    critical: { limit: 10 },
};

export const fetchAuditDashboard = createAsyncThunk(
    "auditDashboard/fetch",
    async (_, { rejectWithValue }) => {
        try {
            const keys = Object.keys(ENDPOINTS);
            const results = await Promise.allSettled(
                keys.map((key) => api.get(ENDPOINTS[key], { params: PARAMS[key] }))
            );

            const data = {};
            const failed = [];
            results.forEach((res, i) => {
                const key = keys[i];
                if (res.status === "fulfilled") {
                    data[key] = res.value.data;
                } else {
                    data[key] = null;
                    failed.push(key);
                }
            });

            // Every panel failing means the request failed, not one panel.
            if (failed.length === keys.length) {
                throw results[0].reason || new Error("Audit dashboard unavailable");
            }
            return { data, failed };
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || err.message);
        }
    }
);

const auditDashboardSlice = createSlice({
    name: "auditDashboard",
    initialState: {
        overview: null,
        severity: null,
        topFailed: null,
        trend: null,
        byDevice: null,
        recent: null,
        remediation: null,
        critical: null,
        failedPanels: [],
        isLoading: false,
        error: null,
    },
    reducers: {},
    extraReducers: (builder) => {
        builder
            .addCase(fetchAuditDashboard.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(fetchAuditDashboard.fulfilled, (state, action) => {
                state.isLoading = false;
                Object.assign(state, action.payload.data);
                state.failedPanels = action.payload.failed;
            })
            .addCase(fetchAuditDashboard.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            });
    },
});

export default auditDashboardSlice.reducer;
