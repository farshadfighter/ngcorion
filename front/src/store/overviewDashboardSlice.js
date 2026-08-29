import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api";

/**
 * Main dashboard aggregates.
 *
 * There is no single dashboard endpoint: the screen is assembled from the risk,
 * audit and hardening modules, each guarded by its own permission. A user with
 * only some of those still gets a useful page, so every request is allowed to
 * fail on its own and the reducer records which ones did.
 *
 */
const SOURCES = {
    riskSummary: { url: "/api/risk/summary" },
    // The "Security Trend" and "Recent Security Events" panels were removed
    // from the page pending further development, so their sources
    // (/api/audit/dashboard/compliance-trend and /api/events/recent) are no
    // longer requested. Restore them here alongside the panels.
    auditOverview: { url: "/api/audit/dashboard/overview" },
    hardeningOverview: { url: "/api/hardening/dashboard/overview" },
    topRisky: {
        url: "/api/risk/assets",
        params: {
            page: 1,
            page_size: 20,
            sort_by: "final_risk_score",
            sort_order: "desc",
        },
    },
    // Assets needing attention are the worst-scoring ones, so this reads the
    // risk list rather than the hardening one: the hardening endpoint only
    // returns assets with active audit findings, so a high-risk asset that has
    // never been audited -- exactly the kind worth surfacing -- was hidden.
    // The API filters one risk_level at a time, so the page takes the top slice
    // (already sorted by score desc) and keeps high + critical.
    requiringAttention: {
        url: "/api/risk/assets",
        params: {
            page: 1,
            page_size: 50,
            sort_by: "final_risk_score",
            sort_order: "desc",
        },
    },
    securityScore: { url: "/api/dashboard/security-score" },
};

export const fetchOverviewDashboard = createAsyncThunk(
    "overviewDashboard/fetch",
    async (_, { rejectWithValue }) => {
        const keys = Object.keys(SOURCES);
        const results = await Promise.allSettled(
            keys.map((key) =>
                api.get(SOURCES[key].url, { params: SOURCES[key].params })
            )
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

        // Everything failing is a real page-level error; one panel failing is not.
        if (failed.length === keys.length) {
            const first = results[0].reason;
            return rejectWithValue(
                first?.response?.data?.detail ||
                    first?.message ||
                    "Dashboard data unavailable"
            );
        }
        return { data, failed };
    }
);

const overviewDashboardSlice = createSlice({
    name: "overviewDashboard",
    initialState: {
        riskSummary: null,
        auditOverview: null,
        hardeningOverview: null,
        topRisky: null,
        requiringAttention: null,
        securityScore: null,
        failedPanels: [],
        isLoading: false,
        error: null,
    },
    reducers: {},
    extraReducers: (builder) => {
        builder
            .addCase(fetchOverviewDashboard.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(fetchOverviewDashboard.fulfilled, (state, action) => {
                state.isLoading = false;
                Object.assign(state, action.payload.data);
                state.failedPanels = action.payload.failed;
            })
            .addCase(fetchOverviewDashboard.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            });
    },
});

export default overviewDashboardSlice.reducer;
