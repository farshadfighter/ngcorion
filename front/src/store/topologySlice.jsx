/**
 * Redux slice: topology graph, links, node positions, external networks (clouds) and checks.
 */
import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";
import { t } from "../i18n";
import { apiErrorDetail } from "../utils/apiError.js";

// =====================
// Thunks
// =====================

export const fetchTopology = createAsyncThunk(
    "topology/fetch",
    async (_arg, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/topology/");
            return res.data; // { nodes, links, clouds, cloud_links }
        } catch (err) {
            return rejectWithValue(apiErrorDetail(err, t("Failed to load topology")));
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
            return rejectWithValue(apiErrorDetail(err, t("Failed to create link")));
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
            return rejectWithValue(apiErrorDetail(err, t("Failed to update link")));
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
            return rejectWithValue(apiErrorDetail(err, t("Failed to delete link")));
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
            return rejectWithValue(apiErrorDetail(err, t("Failed to save node position")));
        }
    }
);

// External networks (clouds) and the devices' connections to them: drawn on the map, not assets.
export const createCloud = createAsyncThunk(
    "topology/createCloud",
    async (payload, { rejectWithValue }) => {
        try {
            const res = await api.post("/api/topology/clouds", payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(apiErrorDetail(err, t("Failed to add the external network")));
        }
    }
);

export const updateCloud = createAsyncThunk(
    "topology/updateCloud",
    async ({ cloudId, changes }, { rejectWithValue }) => {
        try {
            const res = await api.patch(`/api/topology/clouds/${cloudId}`, changes);
            return res.data;
        } catch (err) {
            return rejectWithValue(apiErrorDetail(err, t("Failed to save the external network")));
        }
    }
);

export const deleteCloud = createAsyncThunk(
    "topology/deleteCloud",
    async (cloudId, { rejectWithValue }) => {
        try {
            await api.delete(`/api/topology/clouds/${cloudId}`);
            return cloudId;
        } catch (err) {
            return rejectWithValue(apiErrorDetail(err, t("Failed to delete the external network")));
        }
    }
);

export const createCloudLink = createAsyncThunk(
    "topology/createCloudLink",
    async (payload, { rejectWithValue }) => {
        try {
            const res = await api.post("/api/topology/cloud-links", payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(apiErrorDetail(err, t("Failed to create link")));
        }
    }
);

export const updateCloudLink = createAsyncThunk(
    "topology/updateCloudLink",
    async ({ linkId, changes }, { rejectWithValue }) => {
        try {
            const res = await api.patch(`/api/topology/cloud-links/${linkId}`, changes);
            return res.data;
        } catch (err) {
            return rejectWithValue(apiErrorDetail(err, t("Failed to update link")));
        }
    }
);

export const deleteCloudLink = createAsyncThunk(
    "topology/deleteCloudLink",
    async (linkId, { rejectWithValue }) => {
        try {
            await api.delete(`/api/topology/cloud-links/${linkId}`);
            return linkId;
        } catch (err) {
            return rejectWithValue(apiErrorDetail(err, t("Failed to delete link")));
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
            return rejectWithValue(apiErrorDetail(err, t("Failed to validate topology")));
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
        clouds: [],
        cloudLinks: [],
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
                state.clouds = action.payload.clouds || [];
                state.cloudLinks = action.payload.cloud_links || [];
            })
            .addCase(fetchTopology.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(createTopologyLink.pending, (state) => { state.isMutating = true; state.error = null; })
            .addCase(createTopologyLink.fulfilled, (state, action) => {
                state.isMutating = false;
                state.links.push(action.payload);
                state.successMessage = t("Link created successfully!");
            })
            .addCase(createTopologyLink.rejected, (state, action) => { state.isMutating = false; state.error = action.payload; })

            .addCase(updateTopologyLink.fulfilled, (state, action) => {
                const idx = state.links.findIndex((l) => l.id === action.payload.id);
                if (idx !== -1) state.links[idx] = action.payload;
                state.successMessage = t("Link updated successfully!");
            })
            .addCase(updateTopologyLink.rejected, (state, action) => { state.error = action.payload; })

            .addCase(deleteTopologyLink.fulfilled, (state, action) => {
                state.links = state.links.filter((l) => l.id !== action.payload);
                state.successMessage = t("Link deleted successfully!");
            })
            .addCase(deleteTopologyLink.rejected, (state, action) => { state.error = action.payload; })

            .addCase(saveNodePosition.fulfilled, (state, action) => {
                const node = state.nodes.find((n) => n.id === action.payload.assetId);
                if (node) {
                    node.pos_x = action.payload.posX;
                    node.pos_y = action.payload.posY;
                }
            })

            .addCase(createCloud.fulfilled, (state, action) => {
                state.clouds.push(action.payload);
                state.successMessage = t("External network added");
            })
            .addCase(createCloud.rejected, (state, action) => { state.error = action.payload; })
            .addCase(updateCloud.pending, (state, action) => {
                // a drag: keep the new place at once, so a re-render does not jump the cloud back
                const { cloudId, changes } = action.meta.arg;
                const cloud = state.clouds.find((c) => c.id === cloudId);
                if (cloud && "pos_x" in changes) Object.assign(cloud, changes);
            })
            .addCase(updateCloud.fulfilled, (state, action) => {
                const idx = state.clouds.findIndex((c) => c.id === action.payload.id);
                if (idx !== -1) state.clouds[idx] = action.payload;
                if (!("pos_x" in action.meta.arg.changes)) state.successMessage = t("External network saved");
            })
            .addCase(updateCloud.rejected, (state, action) => { state.error = action.payload; })
            .addCase(deleteCloud.fulfilled, (state, action) => {
                state.clouds = state.clouds.filter((c) => c.id !== action.payload);
                state.cloudLinks = state.cloudLinks.filter((l) => l.cloud_id !== action.payload);
                state.successMessage = t("External network deleted");
            })
            .addCase(deleteCloud.rejected, (state, action) => { state.error = action.payload; })
            .addCase(createCloudLink.fulfilled, (state, action) => {
                state.cloudLinks.push(action.payload);
                state.successMessage = t("Link created successfully!");
            })
            .addCase(createCloudLink.rejected, (state, action) => { state.error = action.payload; })
            .addCase(updateCloudLink.fulfilled, (state, action) => {
                const idx = state.cloudLinks.findIndex((l) => l.id === action.payload.id);
                if (idx !== -1) state.cloudLinks[idx] = action.payload;
                state.successMessage = t("Link updated successfully!");
            })
            .addCase(updateCloudLink.rejected, (state, action) => { state.error = action.payload; })
            .addCase(deleteCloudLink.fulfilled, (state, action) => {
                state.cloudLinks = state.cloudLinks.filter((l) => l.id !== action.payload);
                state.successMessage = t("Link deleted successfully!");
            })
            .addCase(deleteCloudLink.rejected, (state, action) => { state.error = action.payload; })

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
