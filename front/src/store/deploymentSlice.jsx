import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// =====================
// Thunks
// =====================

export const fetchDeploymentJobs = createAsyncThunk(
    "deployment/fetchJobs",
    async (_arg, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/deployment/jobs");
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load deployment jobs");
        }
    }
);

export const createDeploymentJob = createAsyncThunk(
    "deployment/createJob",
    async (configurationObjectId, { rejectWithValue }) => {
        try {
            const res = await api.post("/api/deployment/jobs", { configuration_object_id: configurationObjectId });
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to create deployment job");
        }
    }
);

export const fetchDeploymentJobDetail = createAsyncThunk(
    "deployment/fetchJobDetail",
    async (jobId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/deployment/jobs/${jobId}`);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load deployment job");
        }
    }
);

export const startDeploymentJob = createAsyncThunk(
    "deployment/startJob",
    async ({ jobId, credentials }, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/deployment/jobs/${jobId}/start`, credentials);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to start deployment job");
        }
    }
);

export const rollbackDeploymentJob = createAsyncThunk(
    "deployment/rollbackJob",
    async ({ jobId, credentials }, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/deployment/jobs/${jobId}/rollback`, credentials);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to roll back deployment job");
        }
    }
);

// =====================
// Slice
// =====================

const deploymentSlice = createSlice({
    name: "deployment",
    initialState: {
        jobs: [],
        currentJob: null,
        isLoading: false,
        isStarting: false,
        isRollingBack: false,
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
            .addCase(fetchDeploymentJobs.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchDeploymentJobs.fulfilled, (state, action) => { state.isLoading = false; state.jobs = action.payload; })
            .addCase(fetchDeploymentJobs.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(createDeploymentJob.fulfilled, (state, action) => {
                state.jobs.unshift(action.payload);
                state.currentJob = action.payload;
                state.successMessage = "Deployment job created.";
            })
            .addCase(createDeploymentJob.rejected, (state, action) => { state.error = action.payload; })

            .addCase(fetchDeploymentJobDetail.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchDeploymentJobDetail.fulfilled, (state, action) => { state.isLoading = false; state.currentJob = action.payload; })
            .addCase(fetchDeploymentJobDetail.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(startDeploymentJob.pending, (state) => { state.isStarting = true; state.error = null; })
            .addCase(startDeploymentJob.fulfilled, (state, action) => {
                state.isStarting = false;
                state.currentJob = action.payload;
                const idx = state.jobs.findIndex((j) => j.id === action.payload.id);
                if (idx !== -1) state.jobs[idx] = action.payload;
                state.successMessage =
                    action.payload.status === "success" ? "Deployment succeeded." : `Deployment ended with status: ${action.payload.status}`;
            })
            .addCase(startDeploymentJob.rejected, (state, action) => { state.isStarting = false; state.error = action.payload; })

            .addCase(rollbackDeploymentJob.pending, (state) => { state.isRollingBack = true; state.error = null; })
            .addCase(rollbackDeploymentJob.fulfilled, (state, action) => {
                state.isRollingBack = false;
                state.currentJob = action.payload;
                const idx = state.jobs.findIndex((j) => j.id === action.payload.id);
                if (idx !== -1) state.jobs[idx] = action.payload;
                state.successMessage = action.payload.status === "rolled_back" ? "Rollback succeeded." : "Rollback failed - see output.";
            })
            .addCase(rollbackDeploymentJob.rejected, (state, action) => { state.isRollingBack = false; state.error = action.payload; });
    },
});

export const { clearMessages } = deploymentSlice.actions;
export default deploymentSlice.reducer;
