import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// =====================
// Thunks
// =====================

// Fetch all assets
export const fetchAssets = createAsyncThunk(
    "assets/fetchAll",
    async (_, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/assets/");
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to fetch assets"
            );
        }
    }
);

// Fetch single asset
export const fetchAsset = createAsyncThunk(
    "assets/fetchOne",
    async (assetId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/assets/${assetId}`);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to fetch asset"
            );
        }
    }
);

// Fetch asset types
export const fetchAssetTypes = createAsyncThunk(
    "assets/fetchTypes",
    async (_, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/asset-types/");
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to fetch asset types"
            );
        }
    }
);

// Create asset
export const createAsset = createAsyncThunk(
    "assets/create",
    async (assetData, { rejectWithValue }) => {
        try {
            const res = await api.post("/api/assets/", assetData);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to create asset"
            );
        }
    }
);

// Update asset
export const updateAsset = createAsyncThunk(
    "assets/update",
    async ({ assetId, assetData }, { rejectWithValue }) => {
        try {
            const res = await api.put(`/api/assets/${assetId}`, assetData);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to update asset"
            );
        }
    }
);

// Delete asset
export const deleteAsset = createAsyncThunk(
    "assets/delete",
    async (assetId, { rejectWithValue }) => {
        try {
            await api.delete(`/api/assets/${assetId}`);
            return assetId;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to delete asset"
            );
        }
    }
);

// =====================
// Slice
// =====================
const assetSlice = createSlice({
    name: "assets",
    initialState: {
        assets: [],
        assetTypes: [],
        selectedAsset: null,
        isLoading: false,
        error: null,
        successMessage: null,
    },
    reducers: {
        clearMessages: (state) => {
            state.error = null;
            state.successMessage = null;
        },
        clearSelectedAsset: (state) => {
            state.selectedAsset = null;
        },
    },
    extraReducers: (builder) => {
        builder
            // fetch assets
            .addCase(fetchAssets.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(fetchAssets.fulfilled, (state, action) => {
                state.isLoading = false;
                state.assets = action.payload;
            })
            .addCase(fetchAssets.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            })

            // fetch single asset
            .addCase(fetchAsset.fulfilled, (state, action) => {
                state.selectedAsset = action.payload;
            })

            // fetch asset types
            .addCase(fetchAssetTypes.pending, (state) => {
                state.isLoading = true;
            })
            .addCase(fetchAssetTypes.fulfilled, (state, action) => {
                state.isLoading = false;
                state.assetTypes = action.payload;
            })
            .addCase(fetchAssetTypes.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            })

            // create
            .addCase(createAsset.fulfilled, (state, action) => {
                state.assets.push(action.payload);
                state.successMessage = "Asset created successfully!";
            })

            // update
            .addCase(updateAsset.fulfilled, (state, action) => {
                const idx = state.assets.findIndex(
                    (a) => a.id === action.payload.id
                );
                if (idx !== -1) state.assets[idx] = action.payload;
                state.successMessage = "Asset updated successfully!";
            })

            // delete
            .addCase(deleteAsset.fulfilled, (state, action) => {
                state.assets = state.assets.filter(
                    (a) => a.id !== action.payload
                );
                state.successMessage = "Asset deleted successfully!";
            });
    },
});

export const { clearMessages, clearSelectedAsset } = assetSlice.actions;
export default assetSlice.reducer;
