import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api";
import { t } from "../i18n";
import { apiErrorDetail } from "../utils/apiError.js";

/**
 * Main dashboard data.
 *
 * GET /api/dashboard/overview answers every signed-in user, filled from the modules they may read;
 * the security score and the risk summary need risk access. Each request may fail on its own (a user
 * without risk access still gets the rest), and the reducer records which ones did.
 */
const SOURCES = {
    overview: { url: "/api/dashboard/overview" },
    securityScore: { url: "/api/dashboard/security-score" },
    riskSummary: { url: "/api/risk/summary" },
};

export const fetchOverviewDashboard = createAsyncThunk(
    "overviewDashboard/fetch",
    async (_, { rejectWithValue }) => {
        const keys = Object.keys(SOURCES);
        const results = await Promise.allSettled(
            keys.map((key) =>
                // the page leaves out what the user may not read: no toast per panel
                api.get(SOURCES[key].url, { params: SOURCES[key].params, skipPermissionToast: true })
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

        // The overview answers everyone, so its failure is a real page-level error.
        if (!data.overview) {
            const first = results[0].reason;
            return rejectWithValue(apiErrorDetail(first, first?.message || t("Dashboard data unavailable")));
        }
        return { data, failed };
    }
);

const overviewDashboardSlice = createSlice({
    name: "overviewDashboard",
    initialState: {
        overview: null,
        securityScore: null,
        riskSummary: null,
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
