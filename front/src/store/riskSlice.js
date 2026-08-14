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
    async (sort, { rejectWithValue }) => {
        // allSettled, not all: a failing /summary or /trend must not blank the
        // asset table, which is the whole point of the Risk Asset screen.
        const [summaryRes, listRes, trendRes] = await Promise.allSettled([
            api.get("/api/risk/summary"),
            api.get("/api/risk/assets", {
                params: {
                    page: 1,
                    page_size: PAGE_SIZE,
                    sort_by: sort?.sortBy || "final_risk_score",
                    sort_order: sort?.sortOrder || "desc",
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

/**
 * Recalculate one asset's risk score. The backend responds with the fresh
 * score, which replaces that row in place — no full refetch, so the table does
 * not jump or lose the user's scroll position.
 *
 * Needs RISK:write, unlike the rest of this screen which only needs read.
 */
export const recalculateAssetRisk = createAsyncThunk(
    "risk/recalculateAsset",
    async (assetId, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/risk/assets/${assetId}/calculate`);
            return { assetId, score: res.data };
        } catch (err) {
            return rejectWithValue({
                assetId,
                message: err.response?.data?.detail || err.message,
            });
        }
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
        // asset_id currently being recalculated, so only that row shows a spinner.
        recalculatingId: null,
        recalcError: null,
        // Mirrors the query the current rows came from, so the header arrow and
        // the next request stay in step.
        sortBy: "final_risk_score",
        sortOrder: "desc",
    },
    reducers: {
        clearRecalcError: (state) => {
            state.recalcError = null;
        },
        setSort: (state, action) => {
            state.sortBy = action.payload.sortBy;
            state.sortOrder = action.payload.sortOrder;
        },
    },
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
            })
            .addCase(recalculateAssetRisk.pending, (state, action) => {
                state.recalculatingId = action.meta.arg;
                state.recalcError = null;
            })
            .addCase(recalculateAssetRisk.fulfilled, (state, action) => {
                state.recalculatingId = null;
                const { assetId, score } = action.payload;
                const i = state.items.findIndex((r) => r.asset_id === assetId);
                if (i !== -1) {
                    // Merge, not replace: /calculate returns the score fields but
                    // not the row's asset_name / ip_address / rank, which come
                    // from the list endpoint.
                    state.items[i] = { ...state.items[i], ...score };
                }
            })
            .addCase(recalculateAssetRisk.rejected, (state, action) => {
                state.recalculatingId = null;
                state.recalcError = action.payload?.message || "Recalculation failed";
            });
    },
});

export const { clearRecalcError, setSort } = riskSlice.actions;
export default riskSlice.reducer;
