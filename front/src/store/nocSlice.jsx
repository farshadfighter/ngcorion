import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// =====================
// Thunks
// =====================

export const fetchHosts = createAsyncThunk(
    "noc/fetchHosts",
    async (_arg, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/noc/hosts");
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load hosts");
        }
    }
);

export const fetchHostDetail = createAsyncThunk(
    "noc/fetchHostDetail",
    async (assetId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/noc/hosts/${assetId}`);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load host");
        }
    }
);

export const setHostCredential = createAsyncThunk(
    "noc/setHostCredential",
    async ({ assetId, payload }, { rejectWithValue }) => {
        try {
            const res = await api.put(`/api/noc/hosts/${assetId}/credential`, payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to save SNMP credential");
        }
    }
);

export const deleteHostCredential = createAsyncThunk(
    "noc/deleteHostCredential",
    async (assetId, { rejectWithValue }) => {
        try {
            await api.delete(`/api/noc/hosts/${assetId}/credential`);
            return assetId;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to remove SNMP credential");
        }
    }
);

export const pollHostNow = createAsyncThunk(
    "noc/pollHostNow",
    async (assetId, { dispatch, rejectWithValue }) => {
        try {
            const res = await api.post(`/api/noc/hosts/${assetId}/poll`);
            await dispatch(fetchHostDetail(assetId));
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Poll failed");
        }
    }
);

export const pollAllNow = createAsyncThunk(
    "noc/pollAllNow",
    async (_arg, { dispatch, rejectWithValue }) => {
        try {
            const res = await api.post("/api/noc/poll-all");
            await dispatch(fetchHosts());
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Poll-all failed");
        }
    }
);

// =====================
// Slice
// =====================

const nocSlice = createSlice({
    name: "noc",
    initialState: {
        hosts: [],
        currentHost: null,
        isLoading: false,
        isPolling: false,
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
            .addCase(fetchHosts.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchHosts.fulfilled, (state, action) => { state.isLoading = false; state.hosts = action.payload; })
            .addCase(fetchHosts.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(fetchHostDetail.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchHostDetail.fulfilled, (state, action) => { state.isLoading = false; state.currentHost = action.payload; })
            .addCase(fetchHostDetail.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(setHostCredential.fulfilled, (state, action) => {
                if (state.currentHost) state.currentHost.credential = action.payload;
                state.successMessage = "SNMP credential saved.";
            })
            .addCase(setHostCredential.rejected, (state, action) => { state.error = action.payload; })

            .addCase(deleteHostCredential.fulfilled, (state) => {
                if (state.currentHost) state.currentHost.credential = null;
                state.successMessage = "SNMP credential removed.";
            })
            .addCase(deleteHostCredential.rejected, (state, action) => { state.error = action.payload; })

            .addCase(pollHostNow.pending, (state) => { state.isPolling = true; })
            .addCase(pollHostNow.fulfilled, (state, action) => {
                state.isPolling = false;
                state.successMessage = action.payload.message;
            })
            .addCase(pollHostNow.rejected, (state, action) => { state.isPolling = false; state.error = action.payload; })

            .addCase(pollAllNow.pending, (state) => { state.isPolling = true; })
            .addCase(pollAllNow.fulfilled, (state, action) => {
                state.isPolling = false;
                state.successMessage = `Polled ${action.payload.polled_count} host(s).`;
            })
            .addCase(pollAllNow.rejected, (state, action) => { state.isPolling = false; state.error = action.payload; });
    },
});

export const { clearMessages } = nocSlice.actions;
export default nocSlice.reducer;
