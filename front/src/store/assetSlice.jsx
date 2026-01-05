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
// Ports Thunks
// =====================

// Fetch asset ports
export const fetchAssetPorts = createAsyncThunk(
    "assets/fetchPorts",
    async (assetId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/discovery/assets/${assetId}/ports`);
            // Handle different response formats
            const data = res.data;

            // If response is already an array, return it
            if (Array.isArray(data)) {
                return data;
            }

            // If response is an object with ports property, return that
            if (data && typeof data === 'object') {
                if (Array.isArray(data.ports)) {
                    return data.ports;
                }
                // If it's an object but not array structure, return empty array
                return [];
            }

            // Default to empty array
            return [];
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to fetch ports"
            );
        }
    }
);

// Create asset port
export const createAssetPort = createAsyncThunk(
    "assets/createPort",
    async ({ assetId, portData }, { rejectWithValue }) => {
        try {
            // API expects: {asset_id, ports: [...]}
            const payload = {
                asset_id: assetId,
                ports: [portData]
            };
            const res = await api.post(`/api/discovery/ports/add`, payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to create port"
            );
        }
    }
);

// Update asset port (delete old + add new)
export const updateAssetPort = createAsyncThunk(
    "assets/updatePort",
    async ({ assetId, portId, portData }, { rejectWithValue }) => {
        try {
            // Since API doesn't have direct update, we delete and re-add
            // First delete the old port
            await api.delete(`/api/discovery/ports/${portId}`);

            // Then add the updated port
            const payload = {
                asset_id: assetId,
                ports: [portData]
            };
            const res = await api.post(`/api/discovery/ports/add`, payload);
            return { portId, newPort: res.data };
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to update port"
            );
        }
    }
);

// Delete asset port
export const deleteAssetPort = createAsyncThunk(
    "assets/deletePort",
    async ({ assetId, portId }, { rejectWithValue }) => {
        try {
            await api.delete(`/api/discovery/ports/${portId}`);
            return portId;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to delete port"
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
        ports: [],
        isLoading: false,
        isLoadingPorts: false,
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
            })

            // fetch ports
            .addCase(fetchAssetPorts.pending, (state) => {
                state.isLoadingPorts = true;
                state.error = null;
            })
            .addCase(fetchAssetPorts.fulfilled, (state, action) => {
                state.isLoadingPorts = false;
                // Ensure ports is always an array
                state.ports = Array.isArray(action.payload) ? action.payload : [];
            })
            .addCase(fetchAssetPorts.rejected, (state, action) => {
                state.isLoadingPorts = false;
                state.error = action.payload;
                state.ports = []; // Reset to empty array on error
            })

            // create port
            .addCase(createAssetPort.fulfilled, (state, action) => {
                // API returns {success, asset_id, ports_added, message}
                // We should refetch ports to get the actual new port data
                state.successMessage = action.payload.message || "Port added successfully!";
            })

            // update port
            .addCase(updateAssetPort.fulfilled, (state, action) => {
                // Remove old port and add new one
                const { portId, newPort } = action.payload;
                state.ports = state.ports.filter(p => p.id !== portId);
                if (newPort && newPort.ports_added > 0) {
                    // Refresh the ports list after update
                    // The actual new port will be fetched in next fetchAssetPorts call
                }
                state.successMessage = "Port updated successfully!";
            })

            // delete port
            .addCase(deleteAssetPort.fulfilled, (state, action) => {
                state.ports = state.ports.filter(p => p.id !== action.payload);
                state.successMessage = "Port deleted successfully!";
            });
    },
});

export const { clearMessages, clearSelectedAsset } = assetSlice.actions;
export default assetSlice.reducer;
