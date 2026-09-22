import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// =====================
// Thunks
// =====================

export const fetchScheduledJobs = createAsyncThunk(
    "scheduling/fetchJobs",
    async (_, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/scheduling/jobs");
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load scheduled jobs");
        }
    }
);

export const createScheduledJob = createAsyncThunk(
    "scheduling/createJob",
    async (data, { rejectWithValue }) => {
        try {
            const res = await api.post("/api/scheduling/jobs", data);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to create scheduled job");
        }
    }
);

export const updateScheduledJob = createAsyncThunk(
    "scheduling/updateJob",
    async ({ jobId, data }, { rejectWithValue }) => {
        try {
            const res = await api.patch(`/api/scheduling/jobs/${jobId}`, data);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to update scheduled job");
        }
    }
);

export const deleteScheduledJob = createAsyncThunk(
    "scheduling/deleteJob",
    async (jobId, { rejectWithValue }) => {
        try {
            await api.delete(`/api/scheduling/jobs/${jobId}`);
            return jobId;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to delete scheduled job");
        }
    }
);

export const runScheduledJobNow = createAsyncThunk(
    "scheduling/runJobNow",
    async (jobId, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/scheduling/jobs/${jobId}/run`);
            return { jobId, run: res.data };
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to run scheduled job");
        }
    }
);

export const fetchJobRuns = createAsyncThunk(
    "scheduling/fetchJobRuns",
    async (jobId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/scheduling/jobs/${jobId}/runs`);
            return { jobId, runs: res.data };
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load run history");
        }
    }
);

// =====================
// Slice
// =====================

const schedulingSlice = createSlice({
    name: "scheduling",
    initialState: {
        jobs: [],
        runsByJobId: {},
        isLoading: false,
        isSaving: false,
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
            .addCase(fetchScheduledJobs.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchScheduledJobs.fulfilled, (state, action) => { state.isLoading = false; state.jobs = action.payload; })
            .addCase(fetchScheduledJobs.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(createScheduledJob.pending, (state) => { state.isSaving = true; state.error = null; })
            .addCase(createScheduledJob.fulfilled, (state, action) => {
                state.isSaving = false;
                state.jobs.push(action.payload);
                state.successMessage = "Scheduled job created.";
            })
            .addCase(createScheduledJob.rejected, (state, action) => { state.isSaving = false; state.error = action.payload; })

            .addCase(updateScheduledJob.fulfilled, (state, action) => {
                const idx = state.jobs.findIndex((j) => j.id === action.payload.id);
                if (idx !== -1) state.jobs[idx] = action.payload;
                state.successMessage = "Scheduled job updated.";
            })
            .addCase(updateScheduledJob.rejected, (state, action) => { state.error = action.payload; })

            .addCase(deleteScheduledJob.fulfilled, (state, action) => {
                state.jobs = state.jobs.filter((j) => j.id !== action.payload);
                state.successMessage = "Scheduled job deleted.";
            })
            .addCase(deleteScheduledJob.rejected, (state, action) => { state.error = action.payload; })

            .addCase(runScheduledJobNow.fulfilled, (state, action) => {
                state.successMessage = `Run ${action.payload.run.status === "success" ? "succeeded" : "failed"}.`;
            })
            .addCase(runScheduledJobNow.rejected, (state, action) => { state.error = action.payload; })

            .addCase(fetchJobRuns.fulfilled, (state, action) => {
                state.runsByJobId[action.payload.jobId] = action.payload.runs;
            })
            .addCase(fetchJobRuns.rejected, (state, action) => { state.error = action.payload; });
    },
});

export const { clearMessages } = schedulingSlice.actions;
export default schedulingSlice.reducer;
