import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// =====================
// Thunks
// =====================

export const fetchDriftResults = createAsyncThunk(
    "drift/fetchResults",
    async ({ status, severity } = {}, { rejectWithValue }) => {
        try {
            const params = {};
            if (status) params.status = status;
            if (severity) params.severity = severity;
            const res = await api.get("/api/drift/results", { params });
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load drift results");
        }
    }
);

export const fetchDriftResultDetail = createAsyncThunk(
    "drift/fetchResultDetail",
    async (resultId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/drift/results/${resultId}`);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load drift result");
        }
    }
);

export const runDriftAnalysis = createAsyncThunk(
    "drift/analyze",
    async ({ assetId, credentials }, { rejectWithValue }) => {
        try {
            const res = await api.post("/api/drift/analyze", { asset_id: assetId, ...credentials });
            return res.data; // DriftRunSummary
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to run drift analysis");
        }
    }
);

export const acceptDriftResult = createAsyncThunk(
    "drift/accept",
    async (resultId, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/drift/results/${resultId}/accept`);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to accept drift result");
        }
    }
);

export const ignoreDriftResult = createAsyncThunk(
    "drift/ignore",
    async ({ resultId, reason }, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/drift/results/${resultId}/ignore`, { reason });
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to ignore drift result");
        }
    }
);

// =====================
// Slice
// =====================

const driftSlice = createSlice({
    name: "drift",
    initialState: {
        results: [],
        currentResult: null,
        isLoading: false,
        isAnalyzing: false,
        error: null,
        successMessage: null,
        lastRun: null, // DriftRunSummary
    },
    reducers: {
        clearMessages: (state) => {
            state.error = null;
            state.successMessage = null;
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(fetchDriftResults.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchDriftResults.fulfilled, (state, action) => { state.isLoading = false; state.results = action.payload; })
            .addCase(fetchDriftResults.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(fetchDriftResultDetail.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchDriftResultDetail.fulfilled, (state, action) => { state.isLoading = false; state.currentResult = action.payload; })
            .addCase(fetchDriftResultDetail.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(runDriftAnalysis.pending, (state) => { state.isAnalyzing = true; state.error = null; })
            .addCase(runDriftAnalysis.fulfilled, (state, action) => {
                state.isAnalyzing = false;
                state.lastRun = action.payload;
                if (action.payload.status === "failed") {
                    state.error = action.payload.error_message || "Drift analysis failed";
                } else if (action.payload.drift_found_count > 0) {
                    state.successMessage = "Drift detected - see the findings list.";
                } else {
                    state.successMessage = "No drift found. The device matches its baseline.";
                }
            })
            .addCase(runDriftAnalysis.rejected, (state, action) => { state.isAnalyzing = false; state.error = action.payload; })

            .addCase(acceptDriftResult.fulfilled, (state, action) => {
                const idx = state.results.findIndex((r) => r.id === action.payload.id);
                if (idx !== -1) state.results[idx] = action.payload;
                state.successMessage = "Drift result accepted.";
            })
            .addCase(acceptDriftResult.rejected, (state, action) => { state.error = action.payload; })

            .addCase(ignoreDriftResult.fulfilled, (state, action) => {
                const idx = state.results.findIndex((r) => r.id === action.payload.id);
                if (idx !== -1) state.results[idx] = action.payload;
                state.successMessage = "Drift result ignored.";
            })
            .addCase(ignoreDriftResult.rejected, (state, action) => { state.error = action.payload; });
    },
});

export const { clearMessages } = driftSlice.actions;
export default driftSlice.reducer;
