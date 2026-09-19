import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// =====================
// Thunks
// =====================

export const fetchConfigurationJobs = createAsyncThunk(
    "configuration/fetchJobs",
    async (_arg, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/configuration/jobs");
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load configuration jobs");
        }
    }
);

export const generateConfigurationJob = createAsyncThunk(
    "configuration/generateJob",
    async ({ designVersionId, name }, { rejectWithValue }) => {
        try {
            const res = await api.post("/api/configuration/jobs", { design_version_id: designVersionId, name });
            return res.data; // { job, objects }
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to generate configuration job");
        }
    }
);

export const fetchConfigurationJobDetail = createAsyncThunk(
    "configuration/fetchJobDetail",
    async (jobId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/configuration/jobs/${jobId}`);
            return res.data; // { job, objects }
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load configuration job");
        }
    }
);

export const applyConfigurationObject = createAsyncThunk(
    "configuration/applyObject",
    async ({ objectId, credentials }, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/configuration/objects/${objectId}/apply`, credentials);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to apply configuration");
        }
    }
);

// =====================
// Slice
// =====================

const configurationSlice = createSlice({
    name: "configuration",
    initialState: {
        jobs: [],
        currentJob: null, // { job, objects }
        isLoading: false,
        isGenerating: false,
        isApplying: false,
        error: null,
        successMessage: null,
    },
    reducers: {
        clearMessages: (state) => {
            state.error = null;
            state.successMessage = null;
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(fetchConfigurationJobs.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchConfigurationJobs.fulfilled, (state, action) => { state.isLoading = false; state.jobs = action.payload; })
            .addCase(fetchConfigurationJobs.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(generateConfigurationJob.pending, (state) => { state.isGenerating = true; state.error = null; })
            .addCase(generateConfigurationJob.fulfilled, (state, action) => {
                state.isGenerating = false;
                state.currentJob = action.payload;
                state.jobs.unshift(action.payload.job);
                state.successMessage = `Generated ${action.payload.objects.length} configuration object(s).`;
            })
            .addCase(generateConfigurationJob.rejected, (state, action) => { state.isGenerating = false; state.error = action.payload; })

            .addCase(fetchConfigurationJobDetail.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchConfigurationJobDetail.fulfilled, (state, action) => { state.isLoading = false; state.currentJob = action.payload; })
            .addCase(fetchConfigurationJobDetail.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(applyConfigurationObject.pending, (state) => { state.isApplying = true; state.error = null; })
            .addCase(applyConfigurationObject.fulfilled, (state, action) => {
                state.isApplying = false;
                if (state.currentJob) {
                    const idx = state.currentJob.objects.findIndex((o) => o.id === action.payload.id);
                    if (idx !== -1) state.currentJob.objects[idx] = action.payload;
                }
                state.successMessage =
                    action.payload.apply_status === "success"
                        ? "Configuration applied successfully."
                        : "Configuration apply failed - see output.";
            })
            .addCase(applyConfigurationObject.rejected, (state, action) => { state.isApplying = false; state.error = action.payload; });
    },
});

export const { clearMessages } = configurationSlice.actions;
export default configurationSlice.reducer;
