import { createSlice, createAsyncThunk, isAnyOf } from "@reduxjs/toolkit";
import api from "../config/api";

// ==================== ASSET TYPES ====================
export const fetchAssetTypes = createAsyncThunk("requirements/fetchAssetTypes", async (_, { rejectWithValue }) => {
    try {
        const response = await api.get("/api/asset-types/");
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to fetch asset types");
    }
});

export const createAssetType = createAsyncThunk("requirements/createAssetType", async (data, { rejectWithValue }) => {
    try {
        const response = await api.post("/api/asset-types/", data);
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to create asset type");
    }
});

export const updateAssetType = createAsyncThunk("requirements/updateAssetType", async ({ id, data }, { rejectWithValue }) => {
    try {
        const response = await api.put(`/api/asset-types/${id}`, data);
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to update asset type");
    }
});

export const deleteAssetType = createAsyncThunk("requirements/deleteAssetType", async (id, { rejectWithValue }) => {
    try {
        await api.delete(`/api/asset-types/${id}`);
        return id;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to delete asset type");
    }
});

// ==================== OWNERS ====================
export const fetchOwners = createAsyncThunk("requirements/fetchOwners", async (_, { rejectWithValue }) => {
    try {
        const response = await api.get("/api/owners/");
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to fetch owners");
    }
});

export const createOwner = createAsyncThunk("requirements/createOwner", async (data, { rejectWithValue }) => {
    try {
        const response = await api.post("/api/owners/", data);
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to create owner");
    }
});

export const updateOwner = createAsyncThunk("requirements/updateOwner", async ({ id, data }, { rejectWithValue }) => {
    try {
        const response = await api.put(`/api/owners/${id}`, data);
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to update owner");
    }
});

export const deleteOwner = createAsyncThunk("requirements/deleteOwner", async (id, { rejectWithValue }) => {
    try {
        await api.delete(`/api/owners/${id}`);
        return id;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to delete owner");
    }
});

// ==================== LOCATIONS ====================
export const fetchLocations = createAsyncThunk("requirements/fetchLocations", async (_, { rejectWithValue }) => {
    try {
        const response = await api.get("/api/locations/");
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to fetch locations");
    }
});

export const createLocation = createAsyncThunk("requirements/createLocation", async (data, { rejectWithValue }) => {
    try {
        const response = await api.post("/api/locations/", data);
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to create location");
    }
});

export const updateLocation = createAsyncThunk("requirements/updateLocation", async ({ id, data }, { rejectWithValue }) => {
    try {
        const response = await api.put(`/api/locations/${id}`, data);
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to update location");
    }
});

export const deleteLocation = createAsyncThunk("requirements/deleteLocation", async (id, { rejectWithValue }) => {
    try {
        await api.delete(`/api/locations/${id}`);
        return id;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to delete location");
    }
});

// ==================== ZONES ====================
export const fetchZones = createAsyncThunk("requirements/fetchZones", async (_, { rejectWithValue }) => {
    try {
        const response = await api.get("/api/zones/");
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to fetch zones");
    }
});

export const createZone = createAsyncThunk("requirements/createZone", async (data, { rejectWithValue }) => {
    try {
        const response = await api.post("/api/zones/", data);
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to create zone");
    }
});

export const deleteZone = createAsyncThunk("requirements/deleteZone", async (id, { rejectWithValue }) => {
    try {
        await api.delete(`/api/zones/${id}`);
        return id;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to delete zone");
    }
});
export const updateZone = createAsyncThunk("requirements/updateZone", async ({ id, data }, { rejectWithValue }) => {
    try {
        const response = await api.put(`/api/zones/${id}`, data);
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to update zone");
    }
});


// ==================== OS CATALOG ====================
export const fetchOSCatalog = createAsyncThunk("requirements/fetchOSCatalog", async (_, { rejectWithValue }) => {
    try {
        const response = await api.get("/api/os-catalog/");
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to fetch OS catalog");
    }
});

export const createOS = createAsyncThunk("requirements/createOS", async (data, { rejectWithValue }) => {
    try {
        const response = await api.post("/api/os-catalog/", data);
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to create OS");
    }
});

export const deleteOS = createAsyncThunk("requirements/deleteOS", async (id, { rejectWithValue }) => {
    try {
        await api.delete(`/api/os-catalog/${id}`);
        return id;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to delete OS");
    }
});

// ==================== VENDORS ====================
export const fetchVendors = createAsyncThunk("requirements/fetchVendors", async (_, { rejectWithValue }) => {
    try {
        const response = await api.get("/api/vendors/");
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to fetch vendors");
    }
});

export const createVendor = createAsyncThunk("requirements/createVendor", async (data, { rejectWithValue }) => {
    try {
        const response = await api.post("/api/vendors/", data);
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to create vendor");
    }
});

export const deleteVendor = createAsyncThunk("requirements/deleteVendor", async (id, { rejectWithValue }) => {
    try {
        await api.delete(`/api/vendors/${id}`);
        return id;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to delete vendor");
    }
});

// ==================== DEPENDENCIES ====================
export const fetchDependencies = createAsyncThunk("requirements/fetchDependencies", async (assetId, { rejectWithValue }) => {
    try {
        const url = assetId ? `/api/dependencies/asset/${assetId}` : "/api/dependencies/";
        const response = await api.get(url);
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to fetch dependencies");
    }
});

export const createDependency = createAsyncThunk("requirements/createDependency", async (data, { rejectWithValue }) => {
    try {
        const response = await api.post("/api/dependencies/", data);
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to create dependency");
    }
});

export const deleteDependency = createAsyncThunk("requirements/deleteDependency", async (id, { rejectWithValue }) => {
    try {
        await api.delete(`/api/dependencies/${id}`);
        return id;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to delete dependency");
    }
});

// ==================== ENUMS ====================
export const fetchEnums = createAsyncThunk("requirements/fetchEnums", async (_, { rejectWithValue }) => {
    try {
        const response = await api.get("/api/enums/all");
        return response.data;
    } catch (err) {
        return rejectWithValue(err.response?.data?.detail || "Failed to fetch enums");
    }
});

// ==================== SLICE ====================
const requirementSlice = createSlice({
    name: "requirements",
    initialState: {
        assetTypes: [],
        owners: [],
        locations: [],
        zones: [],
        osCatalog: [],
        vendors: [],
        dependencies: [],
        enums: {
            status: [],
            confidentiality: [],
            risk: [],
            relationTypes: []
        },
        isLoading: false,
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
        // Asset Types
        builder
            .addCase(fetchAssetTypes.pending, (state) => { state.isLoading = true; })
            .addCase(fetchAssetTypes.fulfilled, (state, action) => {
                state.isLoading = false;
                state.assetTypes = action.payload;
            })
            .addCase(fetchAssetTypes.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            })
            .addCase(createAssetType.fulfilled, (state, action) => {
                state.assetTypes.push(action.payload);
                state.successMessage = "Asset type created successfully";
            })
            .addCase(updateAssetType.fulfilled, (state, action) => {
                const index = state.assetTypes.findIndex(item => item.id === action.payload.id);
                if (index !== -1) state.assetTypes[index] = action.payload;
                state.successMessage = "Asset type updated successfully";
            })
            .addCase(deleteAssetType.fulfilled, (state, action) => {
                state.assetTypes = state.assetTypes.filter(item => item.id !== action.payload);
                state.successMessage = "Asset type deleted successfully";
            });

        // Owners
        builder
            .addCase(fetchOwners.fulfilled, (state, action) => { state.owners = action.payload; })
            .addCase(createOwner.fulfilled, (state, action) => {
                state.owners.push(action.payload);
                state.successMessage = "Owner created successfully";
            })
            .addCase(updateOwner.fulfilled, (state, action) => {
                const index = state.owners.findIndex(item => item.id === action.payload.id);
                if (index !== -1) state.owners[index] = action.payload;
                state.successMessage = "Owner updated successfully";
            })
            .addCase(deleteOwner.fulfilled, (state, action) => {
                state.owners = state.owners.filter(item => item.id !== action.payload);
                state.successMessage = "Owner deleted successfully";
            });

        // Locations
        builder
            .addCase(fetchLocations.fulfilled, (state, action) => { state.locations = action.payload; })
            .addCase(createLocation.fulfilled, (state, action) => {
                state.locations.push(action.payload);
                state.successMessage = "Location created successfully";
            })
            .addCase(updateLocation.fulfilled, (state, action) => {
                const index = state.locations.findIndex(item => item.id === action.payload.id);
                if (index !== -1) state.locations[index] = action.payload;
                state.successMessage = "Location updated successfully";
            })
            .addCase(deleteLocation.fulfilled, (state, action) => {
                state.locations = state.locations.filter(item => item.id !== action.payload);
                state.successMessage = "Location deleted successfully";
            });

        // Zones
        // Zones
        builder
            .addCase(fetchZones.fulfilled, (state, action) => { state.zones = action.payload; })
            .addCase(createZone.fulfilled, (state, action) => {
                state.zones.push(action.payload);
                state.successMessage = "Zone created successfully";
            })
            
            .addCase(updateZone.fulfilled, (state, action) => {
                const index = state.zones.findIndex(item => item.id === action.payload.id);
                if (index !== -1) state.zones[index] = action.payload;
                state.successMessage = "Zone updated successfully";
            })
            // ---------------------------------
            .addCase(deleteZone.fulfilled, (state, action) => {
                state.zones = state.zones.filter(item => item.id !== action.payload);
                state.successMessage = "Zone deleted successfully";
            });


        // OS Catalog
        builder
            .addCase(fetchOSCatalog.fulfilled, (state, action) => { state.osCatalog = action.payload; })
            .addCase(createOS.fulfilled, (state, action) => {
                state.osCatalog.push(action.payload);
                state.successMessage = "OS created successfully";
            })
            .addCase(deleteOS.fulfilled, (state, action) => {
                state.osCatalog = state.osCatalog.filter(item => item.id !== action.payload);
                state.successMessage = "OS deleted successfully";
            });

        // Vendors
        builder
            .addCase(fetchVendors.fulfilled, (state, action) => { state.vendors = action.payload; })
            .addCase(createVendor.fulfilled, (state, action) => {
                state.vendors.push(action.payload);
                state.successMessage = "Vendor created successfully";
            })
            .addCase(deleteVendor.fulfilled, (state, action) => {
                state.vendors = state.vendors.filter(item => item.id !== action.payload);
                state.successMessage = "Vendor deleted successfully";
            });

        // Dependencies
        builder
            .addCase(fetchDependencies.fulfilled, (state, action) => { state.dependencies = action.payload; })
            .addCase(createDependency.fulfilled, (state, action) => {
                state.dependencies.push(action.payload);
                state.successMessage = "Dependency created successfully";
            })
            .addCase(deleteDependency.fulfilled, (state, action) => {
                state.dependencies = state.dependencies.filter(item => item.id !== action.payload);
                state.successMessage = "Dependency deleted successfully";
            });

        // Enums
        builder
            .addCase(fetchEnums.fulfilled, (state, action) => {
                state.enums = action.payload;
            })
            .addMatcher(
                isAnyOf(
                    createAssetType.rejected,
                    updateAssetType.rejected,
                    deleteAssetType.rejected,
                    createOwner.rejected,
                    updateOwner.rejected,
                    deleteOwner.rejected,
                    createLocation.rejected,
                    updateLocation.rejected,
                    deleteLocation.rejected,
                    createZone.rejected,
                    deleteZone.rejected,
                    createOS.rejected,
                    deleteOS.rejected,
                    createVendor.rejected,
                    deleteVendor.rejected,
                    createDependency.rejected,
                    deleteDependency.rejected,
                    fetchEnums.rejected
                ),
                (state, action) => {
                    state.error = action.payload || "Request failed";
                    state.successMessage = null;
                }
            );
    },
});

export const { clearMessages } = requirementSlice.actions;
export default requirementSlice.reducer;
