import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// =====================
// Thunks
// =====================

export const fetchTopology = createAsyncThunk(
    "topology/fetch",
    async (_arg, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/topology/");
            return res.data; // { nodes: [...], links: [...] }
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load topology");
        }
    }
);

export const createTopologyLink = createAsyncThunk(
    "topology/createLink",
    async (payload, { rejectWithValue }) => {
        try {
            const res = await api.post("/api/topology/links", payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to create link");
        }
    }
);

export const updateTopologyLink = createAsyncThunk(
    "topology/updateLink",
    async ({ linkId, changes }, { rejectWithValue }) => {
        try {
            const res = await api.patch(`/api/topology/links/${linkId}`, changes);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to update link");
        }
    }
);

export const deleteTopologyLink = createAsyncThunk(
    "topology/deleteLink",
    async (linkId, { rejectWithValue }) => {
        try {
            await api.delete(`/api/topology/links/${linkId}`);
            return linkId;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to delete link");
        }
    }
);

export const saveNodePosition = createAsyncThunk(
    "topology/savePosition",
    async ({ assetId, posX, posY }, { rejectWithValue }) => {
        try {
            await api.patch(`/api/topology/nodes/${assetId}/position`, { pos_x: posX, pos_y: posY });
            return { assetId, posX, posY };
        } catch (err) {
            // A failed position save shouldn't interrupt the user - the node
            // still visually stays where it was dropped for this session, it
            // just won't be remembered on the next visit.
            return rejectWithValue(err.response?.data?.detail || "Failed to save node position");
        }
    }
);

export const validateTopology = createAsyncThunk(
    "topology/validate",
    async (_arg, { rejectWithValue }) => {
        try {
            const res = await api.post("/api/topology/validate");
            return res.data; // { findings: [...], asset_count, link_count }
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to validate topology");
        }
    }
);

// =====================
// Slice
// =====================

const topologySlice = createSlice({
    name: "topology",
    initialState: {
        nodes: [],
        links: [],
        isLoading: false,
        isMutating: false,
        error: null,
        successMessage: null,
        validation: { findings: [], assetCount: 0, linkCount: 0, isLoading: false, error: null },
    },
    reducers: {
        clearMessages: (state) => {
            state.error = null;
            state.successMessage = null;
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(fetchTopology.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchTopology.fulfilled, (state, action) => {
                state.isLoading = false;
                state.nodes = action.payload.nodes;
                state.links = action.payload.links;
            })
            .addCase(fetchTopology.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(createTopologyLink.pending, (state) => { state.isMutating = true; state.error = null; })
            .addCase(createTopologyLink.fulfilled, (state, action) => {
                state.isMutating = false;
                state.links.push(action.payload);
                state.successMessage = "Link created successfully!";
            })
            .addCase(createTopologyLink.rejected, (state, action) => { state.isMutating = false; state.error = action.payload; })

            .addCase(updateTopologyLink.fulfilled, (state, action) => {
                const idx = state.links.findIndex((l) => l.id === action.payload.id);
                if (idx !== -1) state.links[idx] = action.payload;
                state.successMessage = "Link updated successfully!";
            })
            .addCase(updateTopologyLink.rejected, (state, action) => { state.error = action.payload; })

            .addCase(deleteTopologyLink.fulfilled, (state, action) => {
                state.links = state.links.filter((l) => l.id !== action.payload);
                state.successMessage = "Link deleted successfully!";
            })
            .addCase(deleteTopologyLink.rejected, (state, action) => { state.error = action.payload; })

            .addCase(saveNodePosition.fulfilled, (state, action) => {
                const node = state.nodes.find((n) => n.id === action.payload.assetId);
                if (node) {
                    node.pos_x = action.payload.posX;
                    node.pos_y = action.payload.posY;
                }
            })

            .addCase(validateTopology.pending, (state) => { state.validation.isLoading = true; state.validation.error = null; })
            .addCase(validateTopology.fulfilled, (state, action) => {
                state.validation = {
                    findings: action.payload.findings,
                    assetCount: action.payload.asset_count,
                    linkCount: action.payload.link_count,
                    isLoading: false,
                    error: null,
                };
            })
            .addCase(validateTopology.rejected, (state, action) => {
                state.validation.isLoading = false;
                state.validation.error = action.payload;
            });
    },
});

export const { clearMessages } = topologySlice.actions;
export default topologySlice.reducer;
