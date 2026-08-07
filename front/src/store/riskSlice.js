import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api";

// Risk levels the backend can emit. NOTE: service.py::_risk_level returns five
// levels (including "very_high") while RiskLevelEnum only declares four — see
// front/RISK_FRONTEND_BACKEND_REQUIREMENTS.md. We render all five until the
// backend team decides; an unknown level still falls through to "unclassified".
export const RISK_LEVELS = ["low", "medium", "high", "very_high", "critical"];

export const RISK_LEVEL_LABELS = {
    low: "Low",
    medium: "Medium",
    high: "High",
    very_high: "Very High",
    critical: "Critical",
};

export const CONFIDENTIALITY_LEVELS = ["public", "internal", "confidential", "critical"];

// Backend caps page_size at 100. Until GET /api/risk/summary exists we page
// through the list to build the dashboard aggregates client-side.
const PAGE_SIZE = 100;
const MAX_PAGES = 20;

/** Fetch every risk row by paging. Temporary — replace with /api/risk/summary. */
const fetchAllRiskAssets = async () => {
    const first = await api.get("/api/risk/assets", {
        params: { page: 1, page_size: PAGE_SIZE, sort_by: "final_risk_score", sort_order: "desc" },
    });
    const { total = 0, items = [] } = first.data || {};
    const all = [...items];

    const pageCount = Math.min(Math.ceil(total / PAGE_SIZE), MAX_PAGES);
    if (pageCount > 1) {
        const rest = await Promise.all(
            Array.from({ length: pageCount - 1 }, (_, i) =>
                api.get("/api/risk/assets", {
                    params: {
                        page: i + 2,
                        page_size: PAGE_SIZE,
                        sort_by: "final_risk_score",
                        sort_order: "desc",
                    },
                })
            )
        );
        rest.forEach((res) => all.push(...(res.data?.items || [])));
    }
    return { items: all, total };
};

/** Group rows by a key, keeping the declared order first and extras after. */
const groupBy = (rows, pick, order) => {
    const counts = new Map();
    rows.forEach((row) => {
        const key = pick(row) || "unclassified";
        counts.set(key, (counts.get(key) || 0) + 1);
    });
    const known = order
        .filter((key) => counts.has(key))
        .map((key) => ({ key, count: counts.get(key) }));
    const extra = [...counts.entries()]
        .filter(([key]) => !order.includes(key))
        .map(([key, count]) => ({ key, count }));
    return [...known, ...extra];
};

/** Build the KPI/chart aggregates the Figma dashboard needs. */
const buildSummary = (rows, total) => {
    const scored = rows.filter((r) => typeof r.final_risk_score === "number");
    const scoreAverage = scored.length
        ? scored.reduce((sum, r) => sum + r.final_risk_score, 0) / scored.length
        : null;

    return {
        totals: {
            total_assets: total || rows.length,
            risk_score_average: scoreAverage === null ? null : Math.round(scoreAverage * 10) / 10,
            incomplete_assets: rows.filter((r) => r.incomplete_data).length,
            open_ports_total: rows.reduce((sum, r) => sum + (r.open_ports_count || 0), 0),
            // "Non-conformity" is not defined by the backend yet; we approximate
            // it as assets carrying at least one active audit finding.
            non_conformity_assets: rows.filter((r) => (r.active_audit_findings_count || 0) > 0).length,
            // No aggregate endpoint exposes this; per-asset counts are not in
            // the list payload, so it stays null until /summary lands.
            fixed_by_hardening_total: null,
        },
        by_risk_level: groupBy(rows, (r) => r.risk_level, RISK_LEVELS),
        by_zone: groupBy(rows, (r) => r.zone_name, []),
        // confidentiality_level is not returned by the risk endpoints yet.
        by_confidentiality: groupBy(rows, (r) => r.confidentiality_level, CONFIDENTIALITY_LEVELS),
    };
};

export const fetchRiskDashboard = createAsyncThunk(
    "risk/fetchDashboard",
    async (_, { rejectWithValue }) => {
        try {
            const { items, total } = await fetchAllRiskAssets();
            return { items, total, summary: buildSummary(items, total) };
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || err.message);
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
