import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";
import { t } from "../i18n";

const detail = (err, fallback) => err.response?.data?.detail || fallback;

export const fetchCveFindings = createAsyncThunk(
    "cve/fetchFindings",
    async (_, { rejectWithValue }) => {
        try {
            return (await api.get("/api/cve/findings")).data;
        } catch (err) {
            return rejectWithValue(detail(err, t("Could not load CVE findings")));
        }
    }
);

export const fetchCveDbStatus = createAsyncThunk(
    "cve/fetchDbStatus",
    async (_, { rejectWithValue }) => {
        try {
            return (await api.get("/api/cve/db/status")).data;
        } catch (err) {
            return rejectWithValue(detail(err, t("Could not load the CVE database status")));
        }
    }
);

export const fetchCveJobs = createAsyncThunk(
    "cve/fetchJobs",
    async (_, { rejectWithValue }) => {
        try {
            return (await api.get("/api/cve/db/jobs", { params: { limit: 30 } })).data;
        } catch (err) {
            return rejectWithValue(detail(err, t("Could not load the update history")));
        }
    }
);

const cveSlice = createSlice({
    name: "cve",
    initialState: {
        summary: { total: 0, fix_now: 0, affected_assets: 0, critical: 0, high: 0, medium: 0, low: 0 },
        findings: [],
        assets: [],
        databaseLoaded: true,
        isLoading: false,
        loadedOnce: false,
        error: null,
        status: null,
        statusError: null,
        jobs: [],
    },
    reducers: {},
    extraReducers: (builder) => {
        builder
            .addCase(fetchCveFindings.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchCveFindings.fulfilled, (state, action) => {
                state.isLoading = false;
                state.loadedOnce = true;
                state.summary = action.payload.summary;
                state.findings = action.payload.findings;
                state.assets = action.payload.assets;
                state.databaseLoaded = action.payload.database_loaded;
            })
            .addCase(fetchCveFindings.rejected, (state, action) => {
                state.isLoading = false;
                state.loadedOnce = true;
                state.error = action.payload;
            })
            .addCase(fetchCveDbStatus.fulfilled, (state, action) => {
                state.status = action.payload;
                state.statusError = null;
            })
            .addCase(fetchCveDbStatus.rejected, (state, action) => { state.statusError = action.payload; })
            .addCase(fetchCveJobs.fulfilled, (state, action) => { state.jobs = action.payload; });
    },
});

export default cveSlice.reducer;
