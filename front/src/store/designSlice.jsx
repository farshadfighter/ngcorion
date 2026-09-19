import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// =====================
// Thunks
// =====================

export const fetchDesigns = createAsyncThunk(
    "design/fetchDesigns",
    async (_arg, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/design/");
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load designs");
        }
    }
);

export const createDesign = createAsyncThunk(
    "design/createDesign",
    async (payload, { rejectWithValue }) => {
        try {
            const res = await api.post("/api/design/", payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to create design");
        }
    }
);

export const fetchDesignDetail = createAsyncThunk(
    "design/fetchDesignDetail",
    async (designId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/design/${designId}`);
            return res.data; // { design, versions }
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load design");
        }
    }
);

export const createDesignVersion = createAsyncThunk(
    "design/createVersion",
    async ({ designId, notes, cloneFromVersionId }, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/design/${designId}/versions`, {
                notes: notes || undefined,
                clone_from_version_id: cloneFromVersionId || undefined,
            });
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to create version");
        }
    }
);

export const fetchVersionDetail = createAsyncThunk(
    "design/fetchVersionDetail",
    async (versionId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/design/versions/${versionId}`);
            return res.data; // { version, components, relationships }
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load design version");
        }
    }
);

export const createComponent = createAsyncThunk(
    "design/createComponent",
    async ({ versionId, payload }, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/design/versions/${versionId}/components`, payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to create component");
        }
    }
);

export const updateComponent = createAsyncThunk(
    "design/updateComponent",
    async ({ componentId, changes }, { rejectWithValue }) => {
        try {
            const res = await api.patch(`/api/design/components/${componentId}`, changes);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to update component");
        }
    }
);

export const deleteComponent = createAsyncThunk(
    "design/deleteComponent",
    async (componentId, { rejectWithValue }) => {
        try {
            await api.delete(`/api/design/components/${componentId}`);
            return componentId;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to delete component");
        }
    }
);

export const mapComponentToAsset = createAsyncThunk(
    "design/mapComponent",
    async ({ componentId, assetId }, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/design/components/${componentId}/map`, { asset_id: assetId });
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to map component");
        }
    }
);

export const createRelationship = createAsyncThunk(
    "design/createRelationship",
    async ({ versionId, payload }, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/design/versions/${versionId}/relationships`, payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to create relationship");
        }
    }
);

export const updateRelationship = createAsyncThunk(
    "design/updateRelationship",
    async ({ relationshipId, changes }, { rejectWithValue }) => {
        try {
            const res = await api.patch(`/api/design/relationships/${relationshipId}`, changes);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to update relationship");
        }
    }
);

export const deleteRelationship = createAsyncThunk(
    "design/deleteRelationship",
    async (relationshipId, { rejectWithValue }) => {
        try {
            await api.delete(`/api/design/relationships/${relationshipId}`);
            return relationshipId;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to delete relationship");
        }
    }
);

// =====================
// Slice
// =====================

const designSlice = createSlice({
    name: "design",
    initialState: {
        designs: [],
        currentDesign: null,
        currentVersion: null, // { version, components, relationships }
        isLoading: false,
        isMutating: false,
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
            .addCase(fetchDesigns.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchDesigns.fulfilled, (state, action) => { state.isLoading = false; state.designs = action.payload; })
            .addCase(fetchDesigns.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(createDesign.fulfilled, (state, action) => {
                state.designs.unshift(action.payload);
                state.successMessage = "Design created!";
            })
            .addCase(createDesign.rejected, (state, action) => { state.error = action.payload; })

            .addCase(fetchDesignDetail.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchDesignDetail.fulfilled, (state, action) => { state.isLoading = false; state.currentDesign = action.payload; })
            .addCase(fetchDesignDetail.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(createDesignVersion.fulfilled, (state, action) => {
                if (state.currentDesign) state.currentDesign.versions.push(action.payload);
                state.successMessage = `Version ${action.payload.version_number} created.`;
            })
            .addCase(createDesignVersion.rejected, (state, action) => { state.error = action.payload; })

            .addCase(fetchVersionDetail.pending, (state) => { state.isLoading = true; state.error = null; })
            .addCase(fetchVersionDetail.fulfilled, (state, action) => { state.isLoading = false; state.currentVersion = action.payload; })
            .addCase(fetchVersionDetail.rejected, (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(createComponent.fulfilled, (state, action) => {
                if (state.currentVersion) state.currentVersion.components.push(action.payload);
            })
            .addCase(createComponent.rejected, (state, action) => { state.error = action.payload; })

            .addCase(updateComponent.fulfilled, (state, action) => {
                if (!state.currentVersion) return;
                const idx = state.currentVersion.components.findIndex((c) => c.id === action.payload.id);
                if (idx !== -1) state.currentVersion.components[idx] = action.payload;
            })
            .addCase(updateComponent.rejected, (state, action) => { state.error = action.payload; })

            .addCase(deleteComponent.fulfilled, (state, action) => {
                if (!state.currentVersion) return;
                state.currentVersion.components = state.currentVersion.components.filter((c) => c.id !== action.payload);
                state.currentVersion.relationships = state.currentVersion.relationships.filter(
                    (r) => r.source_component_id !== action.payload && r.destination_component_id !== action.payload
                );
            })
            .addCase(deleteComponent.rejected, (state, action) => { state.error = action.payload; })

            .addCase(mapComponentToAsset.fulfilled, (state, action) => {
                if (!state.currentVersion) return;
                const idx = state.currentVersion.components.findIndex((c) => c.id === action.payload.id);
                if (idx !== -1) state.currentVersion.components[idx] = action.payload;
                state.successMessage = "Component mapped to asset.";
            })
            .addCase(mapComponentToAsset.rejected, (state, action) => { state.error = action.payload; })

            .addCase(createRelationship.fulfilled, (state, action) => {
                if (state.currentVersion) state.currentVersion.relationships.push(action.payload);
            })
            .addCase(createRelationship.rejected, (state, action) => { state.error = action.payload; })

            .addCase(updateRelationship.fulfilled, (state, action) => {
                if (!state.currentVersion) return;
                const idx = state.currentVersion.relationships.findIndex((r) => r.id === action.payload.id);
                if (idx !== -1) state.currentVersion.relationships[idx] = action.payload;
            })
            .addCase(updateRelationship.rejected, (state, action) => { state.error = action.payload; })

            .addCase(deleteRelationship.fulfilled, (state, action) => {
                if (!state.currentVersion) return;
                state.currentVersion.relationships = state.currentVersion.relationships.filter((r) => r.id !== action.payload);
            })
            .addCase(deleteRelationship.rejected, (state, action) => { state.error = action.payload; });
    },
});

export const { clearMessages } = designSlice.actions;
export default designSlice.reducer;
