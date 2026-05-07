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

// Create asset - IMPROVED ERROR HANDLING
export const createAsset = createAsyncThunk(
    "assets/create",
    async (assetData, { rejectWithValue }) => {
        try {
            const res = await api.post("/api/assets/", assetData);
            return res.data;
        } catch (err) {
            // Enhanced error handling for different error types
            if (err.response) {
                const { status, data } = err.response;

                // Handle 500 errors (like unique constraint violations)
                if (status === 500) {
                    // Try to extract meaningful error from data
                    if (data && typeof data === 'object') {
                        if (data.detail) {
                            return rejectWithValue(data.detail);
                        }
                        // Sometimes error is in other fields
                        if (data.message) {
                            return rejectWithValue(data.message);
                        }
                    }
                    // Fallback: check error message
                    if (err.message && err.message.includes('500')) {
                        return rejectWithValue("Server error: Please check if the data is unique (serial number, IP, MAC)");
                    }
                    return rejectWithValue("Internal server error occurred");
                }

                // Handle 422 validation errors
                if (status === 422 && data.detail) {
                    return rejectWithValue(data.detail);
                }

                // Handle 400 bad request
                if (status === 400 && data.detail) {
                    return rejectWithValue(data.detail);
                }

                // Generic error with detail
                if (data && data.detail) {
                    return rejectWithValue(data.detail);
                }
            }

            // Network or other errors
            return rejectWithValue(
                err.message || "Failed to create asset"
            );
        }
    }
);

// Update asset - IMPROVED ERROR HANDLING
export const updateAsset = createAsyncThunk(
    "assets/update",
    async ({ assetId, assetData }, { rejectWithValue }) => {
        try {
            const res = await api.put(`/api/assets/${assetId}`, assetData);
            return res.data;
        } catch (err) {
            // Enhanced error handling
            if (err.response) {
                const { status, data } = err.response;

                if (status === 500) {
                    if (data && data.detail) {
                        return rejectWithValue(data.detail);
                    }
                    return rejectWithValue("Internal server error occurred");
                }

                if (data && data.detail) {
                    return rejectWithValue(data.detail);
                }
            }

            return rejectWithValue(
                err.message || "Failed to update asset"
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
            const data = res.data;
            if (Array.isArray(data)) return data;
            if (data && typeof data === 'object' && Array.isArray(data.ports)) return data.ports;
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
            const payload = { asset_id: assetId, ports: [portData] };
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
            await api.delete(`/api/discovery/ports/${portId}`);
            const payload = { asset_id: assetId, ports: [portData] };
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
                    (a) => a.asset_id === action.payload.asset_id
                );
                if (idx !== -1) state.assets[idx] = action.payload;
                state.successMessage = "Asset updated successfully!";
            })

            // delete
            .addCase(deleteAsset.fulfilled, (state, action) => {
                state.assets = state.assets.filter(
                    (a) => a.asset_id !== action.payload
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
                state.ports = Array.isArray(action.payload) ? action.payload : [];
            })
            .addCase(fetchAssetPorts.rejected, (state, action) => {
                state.isLoadingPorts = false;
                state.error = action.payload;
                state.ports = [];
            })

            // create port
            .addCase(createAssetPort.fulfilled, (state, action) => {
                state.successMessage = action.payload.message || "Port added successfully!";
            })

            // update port
            .addCase(updateAssetPort.fulfilled, (state, action) => {
                const { portId, newPort } = action.payload;
                state.ports = state.ports.filter(p => p.id !== portId);
                if (newPort && newPort.ports_added > 0) {
                    // Refresh the ports list after update
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