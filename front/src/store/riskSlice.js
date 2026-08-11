import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api";

// The backend emits five levels (router.py::_RISK_LEVEL_ORDER); "very_high"
// was confirmed as an official level, so it is rendered as its own slice.
export const RISK_LEVELS = ["low", "medium", "high", "very_high", "critical"];

export const RISK_LEVEL_LABELS = {
    low: "Low",
    medium: "Medium",
    high: "High",
    very_high: "Very High",
    critical: "Critical",
};

// Backend caps page_size at 100; the table shows the highest-risk assets first.
const PAGE_SIZE = 100;

/**
 * Normalise the aggregate buckets from GET /api/risk/summary into the
 * { key, count } shape the charts render. The backend names the bucket
 * differently per group (level / zone_name), hence the explicit pick.
 */
const toBuckets = (rows, pick) =>
    (rows || []).map((row) => ({
        key: pick(row) || "unclassified",
        count: Number(row.count) || 0,
    }));

const normaliseSummary = (data) => ({
    totals: data?.totals || {},
    by_risk_level: toBuckets(data?.by_risk_level, (r) => r.level),
    by_zone: toBuckets(data?.by_zone, (r) => r.zone_name),
    by_confidentiality: toBuckets(data?.by_confidentiality, (r) => r.level),
});

/**
 * Dashboard data: the aggregates come from /summary (SQL-side, covers every
 * asset), the table rows from the first page of /assets, and the chart series
 * from /trend. They are fetched together so one failure does not blank the page.
 */
export const fetchRiskDashboard = createAsyncThunk(
    "risk/fetchDashboard",
    async (_, { rejectWithValue }) => {
        // allSettled, not all: a failing /summary or /trend must not blank the
        // asset table, which is the whole point of the Risk Asset screen.
        const [summaryRes, listRes, trendRes] = await Promise.allSettled([
            api.get("/api/risk/summary"),
            api.get("/api/risk/assets", {
                params: {
                    page: 1,
                    page_size: PAGE_SIZE,
                    sort_by: "final_risk_score",
                    sort_order: "desc",
                },
            }),
            api.get("/api/risk/trend", { params: { months: 12 } }),
        ]);

        // Only the asset list failing is a real error for this screen.
        if (listRes.status === "rejected") {
            const err = listRes.reason;
            return rejectWithValue(
                err?.response?.data?.detail || err?.message || "Risk data unavailable"
            );
        }

        const ok = (res) => (res.status === "fulfilled" ? res.value.data : null);
        return {
            summary: normaliseSummary(ok(summaryRes)),
            items: listRes.value.data?.items || [],
            total: listRes.value.data?.total || 0,
            trend: ok(trendRes)?.points || [],
            trendMessage: ok(trendRes)?.message || null,
        };
    }
);

export const fetchRiskZones = createAsyncThunk(
    "risk/fetchZones",
    async (_, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/risk/zones");
            return res.data || [];
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || err.message);
        }
    }
);

const riskSlice = createSlice({
    name: "risk",
    initialState: {
        items: [],
        total: 0,
        summary: null,
        trend: [],
        trendMessage: null,
        zones: [],
        isLoading: false,
        error: null,
    },
    reducers: {},
    extraReducers: (builder) => {
        builder
            .addCase(fetchRiskDashboard.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(fetchRiskDashboard.fulfilled, (state, action) => {
                state.isLoading = false;
                state.items = action.payload.items;
                state.total = action.payload.total;
                state.summary = action.payload.summary;
                state.trend = action.payload.trend;
                state.trendMessage = action.payload.trendMessage;
            })
            .addCase(fetchRiskDashboard.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            })
            .addCase(fetchRiskZones.fulfilled, (state, action) => {
                state.zones = action.payload;
            });
    },
});

export default riskSlice.reducer;
