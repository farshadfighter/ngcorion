import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// =====================
// Thunks
// =====================

export const fetchCveFindings = createAsyncThunk(
    "cve/fetchFindings",
    async (assetId, { rejectWithValue }) => {
        try {
            const url = assetId ? `/api/cve/findings/${assetId}` : "/api/cve/findings";
            const res = await api.get(url);
            return res.data; // CveFindingsResponse
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load CVE findings");
        }
    }
);

export const syncCveFromNvd = createAsyncThunk(
    "cve/sync",
    async (productKeyword, { rejectWithValue }) => {
        try {
            const res = await api.post("/api/cve/sync", { product_keyword: productKeyword || null });
            return res.data; // CveSyncResponse
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to sync from NVD");
        }
    }
);

// =====================
// Slice
// =====================

const cveSlice = createSlice({
    name: "cve",
    initialState: {
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
        findings: [],
        isLoading: false,
        isSyncing: false,
        error: null,
        successMessage: null,
        lastSync: null, // CveSyncResponse
    },
    reducers: {
        clearMessages: (state) => {
            state.error = null;
            state.successMessage = null;
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(fetchCveFindings.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchCveFindings.fulfilled, (state, action) => {
                state.isLoading = false;
                state.summary = action.payload.summary;
                state.findings = action.payload.findings;
            })
            .addCase(fetchCveFindings.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(syncCveFromNvd.pending, (state) => { state.isSyncing = true; state.error = null; })
            .addCase(syncCveFromNvd.fulfilled, (state, action) => {
                state.isSyncing = false;
                state.lastSync = action.payload;
                const added = action.payload.records_added;
                const updated = action.payload.records_updated;
                state.successMessage = `NVD sync complete: ${added} added, ${updated} updated.`
                    + (action.payload.message ? ` ${action.payload.message}` : "");
            })
            .addCase(syncCveFromNvd.rejected, (state, action) => { state.isSyncing = false; state.error = action.payload; });
    },
});

export const { clearMessages } = cveSlice.actions;
export default cveSlice.reducer;
