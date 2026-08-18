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
 * Not covered by any endpoint yet, so deliberately absent here:
 *   - the overall Security Score, its gauge and the six-row breakdown.
 * Those need a backend decision on the formula, not a query.
 */
const SOURCES = {
    riskSummary: { url: "/api/risk/summary" },
    // The design's trend is 30 daily bars, which is what this endpoint's
    // `days` mode returns — /api/risk/trend only groups by month.
    complianceTrend: {
        url: "/api/audit/dashboard/compliance-trend",
        params: { days: 30 },
    },
    auditOverview: { url: "/api/audit/dashboard/overview" },
    hardeningOverview: { url: "/api/hardening/dashboard/overview" },
    topRisky: {
        url: "/api/risk/assets",
        params: {
            page: 1,
            page_size: 10,
            sort_by: "final_risk_score",
            sort_order: "desc",
        },
    },
    requiringAttention: {
        url: "/api/hardening/dashboard/assets-requiring-hardening",
        params: { page: 1, page_size: 10 },
    },
    recentEvents: {
        url: "/api/events/recent",
        params: { limit: 8 },
    },
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
        complianceTrend: null,
        auditOverview: null,
        hardeningOverview: null,
        topRisky: null,
        requiringAttention: null,
        recentEvents: null,
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
