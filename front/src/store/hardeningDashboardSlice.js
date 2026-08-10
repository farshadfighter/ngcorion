import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api";

/**
 * Hardening KPI dashboard data.
 *
 * Six aggregate endpoints are fetched together; each is allowed to fail on its
 * own so one broken panel does not blank the page.
 *
 * Two panels from the Figma design have no endpoint yet because they need a
 * backend decision, not a query — see the notes in
 * app/modules/hardening/dashboard_router.py:
 *   - "Hardening Impact" (before/after) needs a pre-hardening baseline.
 *   - "Assets Requiring Hardening" pulls its Risk column from the risk module.
 */
const ENDPOINTS = {
    overview: "/api/hardening/dashboard/overview",
    progress: "/api/hardening/dashboard/progress",
    coverage: "/api/hardening/dashboard/coverage-by-asset-type",
    vendors: "/api/hardening/dashboard/by-vendor",
    compliance: "/api/hardening/dashboard/policy-compliance",
    activities: "/api/hardening/dashboard/recent-activities",
    requiring: "/api/hardening/dashboard/assets-requiring-hardening",
    missing: "/api/hardening/dashboard/top-missing-controls",
};

export const fetchHardeningDashboard = createAsyncThunk(
    "hardeningDashboard/fetch",
    async (_, { rejectWithValue }) => {
        try {
            const keys = Object.keys(ENDPOINTS);
            const results = await Promise.allSettled(
                keys.map((key) =>
                    api.get(ENDPOINTS[key], {
                        params:
                            key === "progress"
                                ? { months: 12 }
                                : // This one is paginated by the backend, so it
                                  // takes page_size rather than a plain limit.
                                key === "requiring"
                                ? { page: 1, page_size: 10 }
                                : ["activities", "missing"].includes(key)
                                ? { limit: 10 }
                                : undefined,
                    })
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

            // Every panel failing means the whole request failed, not one panel.
            if (failed.length === keys.length) {
                const first = results[0];
                throw first.reason || new Error("Hardening dashboard unavailable");
            }
            return { data, failed };
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || err.message);
        }
    }
);

const hardeningDashboardSlice = createSlice({
    name: "hardeningDashboard",
    initialState: {
        overview: null,
        progress: null,
        coverage: null,
        vendors: null,
        compliance: null,
        activities: null,
        requiring: null,
        missing: null,
        failedPanels: [],
        isLoading: false,
        error: null,
    },
    reducers: {},
    extraReducers: (builder) => {
        builder
            .addCase(fetchHardeningDashboard.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(fetchHardeningDashboard.fulfilled, (state, action) => {
                state.isLoading = false;
                Object.assign(state, action.payload.data);
                state.failedPanels = action.payload.failed;
            })
            .addCase(fetchHardeningDashboard.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            });
    },
});

export default hardeningDashboardSlice.reducer;
