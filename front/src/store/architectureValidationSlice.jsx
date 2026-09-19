import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// =====================
// Thunks
// =====================

export const fetchFindings = createAsyncThunk(
    "architectureValidation/fetchFindings",
    async ({ status, severity } = {}, { rejectWithValue }) => {
        try {
            const params = {};
            if (status) params.status = status;
            if (severity) params.severity = severity;
            const res = await api.get("/api/architecture-validation/findings", { params });
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load findings");
        }
    }
);

export const runAnalysis = createAsyncThunk(
    "architectureValidation/analyze",
    async (_arg, { rejectWithValue }) => {
        try {
            const res = await api.post("/api/architecture-validation/analyze");
            return res.data; // { findings, asset_count, finding_count }
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to run analysis");
        }
    }
);

export const acceptFinding = createAsyncThunk(
    "architectureValidation/accept",
    async (findingId, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/architecture-validation/findings/${findingId}/accept`);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to accept finding");
        }
    }
);

export const ignoreFinding = createAsyncThunk(
    "architectureValidation/ignore",
    async ({ findingId, reason }, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/architecture-validation/findings/${findingId}/ignore`, { reason });
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to ignore finding");
        }
    }
);

// =====================
// Slice
// =====================

const architectureValidationSlice = createSlice({
    name: "architectureValidation",
    initialState: {
        findings: [],
        isLoading: false,
        isAnalyzing: false,
        error: null,
        successMessage: null,
        lastRun: null, // { assetCount, findingCount }
    },
    reducers: {
        clearMessages: (state) => {
            state.error = null;
            state.successMessage = null;
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(fetchFindings.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchFindings.fulfilled, (state, action) => { state.isLoading = false; state.findings = action.payload; })
            .addCase(fetchFindings.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(runAnalysis.pending, (state) => { state.isAnalyzing = true; state.error = null; })
            .addCase(runAnalysis.fulfilled, (state, action) => {
                state.isAnalyzing = false;
                state.lastRun = { assetCount: action.payload.asset_count, findingCount: action.payload.finding_count };
                state.successMessage = `Analysis complete: ${action.payload.finding_count} finding(s) across ${action.payload.asset_count} asset(s).`;
            })
            .addCase(runAnalysis.rejected, (state, action) => { state.isAnalyzing = false; state.error = action.payload; })

            .addCase(acceptFinding.fulfilled, (state, action) => {
                const idx = state.findings.findIndex((f) => f.id === action.payload.id);
                if (idx !== -1) state.findings[idx] = action.payload;
                state.successMessage = "Finding accepted.";
            })
            .addCase(acceptFinding.rejected, (state, action) => { state.error = action.payload; })

            .addCase(ignoreFinding.fulfilled, (state, action) => {
                const idx = state.findings.findIndex((f) => f.id === action.payload.id);
                if (idx !== -1) state.findings[idx] = action.payload;
                state.successMessage = "Finding ignored.";
            })
            .addCase(ignoreFinding.rejected, (state, action) => { state.error = action.payload; });
    },
});

export const { clearMessages } = architectureValidationSlice.actions;
export default architectureValidationSlice.reducer;
