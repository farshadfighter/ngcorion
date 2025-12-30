/* ==========================================
   NGCORION - Assets Slice
   ========================================== */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../api/axios';

// Initial state
const initialState = {
  assets: [],
  assetTypes: [],
  selectedAsset: null,
  currentView: 'overview', // overview, network, location, ports, security
  loading: false,
  error: null,
};

// Async thunks
export const fetchAssets = createAsyncThunk(
  'assets/fetchAll',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/assets/');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch assets');
    }
  }
);

export const fetchAsset = createAsyncThunk(
  'assets/fetchOne',
  async (assetId, { rejectWithValue }) => {
    try {
      const response = await api.get(`/api/assets/${assetId}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch asset');
    }
  }
);
export const fetchAssetTypes = createAsyncThunk(
  'assets/fetchTypes',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/asset-types/');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail);
    }
  }
);


export const createAsset = createAsyncThunk(
  'assets/create',
  async (assetData, { rejectWithValue }) => {
    try {
      const response = await api.post('/api/assets/', assetData);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to create asset');
    }
  }
);

export const updateAsset = createAsyncThunk(
  'assets/update',
  async ({ assetId, assetData }, { rejectWithValue }) => {
    try {
      const response = await api.put(`/api/assets/${assetId}`, assetData);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to update asset');
    }
  }
);

export const deleteAsset = createAsyncThunk(
  'assets/delete',
  async (assetId, { rejectWithValue }) => {
    try {
      await api.delete(`/api/assets/${assetId}`);
      return assetId;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to delete asset');
    }
  }
);

// Fetch views
export const fetchOverviewView = createAsyncThunk(
  'assets/fetchOverview',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/asset-views/overview');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch overview');
    }
  }
);

export const fetchNetworkView = createAsyncThunk(
  'assets/fetchNetwork',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/asset-views/network-system');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch network view');
    }
  }
);

export const fetchLocationView = createAsyncThunk(
  'assets/fetchLocation',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/asset-views/location-ownership');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch location view');
    }
  }
);

export const fetchSecurityView = createAsyncThunk(
  'assets/fetchSecurity',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/asset-views/security-audit');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch security view');
    }
  }
);

// Slice
const assetsSlice = createSlice({
  name: 'assets',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    clearSelectedAsset: (state) => {
      state.selectedAsset = null;
    },
    setCurrentView: (state, action) => {
      state.currentView = action.payload;
    },
  },
  extraReducers: (builder) => {
    builder
      // Fetch all assets
      .addCase(fetchAssets.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchAssets.fulfilled, (state, action) => {
        state.loading = false;
        state.assets = action.payload;
      })
      .addCase(fetchAssets.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      // Fetch one asset
      .addCase(fetchAsset.fulfilled, (state, action) => {
        state.selectedAsset = action.payload;
      })
      // Create asset
      .addCase(createAsset.fulfilled, (state, action) => {
        state.assets.push(action.payload);
      })
      // Update asset
      .addCase(updateAsset.fulfilled, (state, action) => {
        const payloadId = action.payload.id || action.payload.asset_id;
        const index = state.assets.findIndex((a) => (a.id || a.asset_id) === payloadId);
        if (index !== -1) {
          state.assets[index] = action.payload;
        }
      })
      // Delete asset
      .addCase(deleteAsset.fulfilled, (state, action) => {
        state.assets = state.assets.filter((a) => (a.id || a.asset_id) !== action.payload);
      })
      // View fetches
      .addCase(fetchOverviewView.fulfilled, (state, action) => {
        state.assets = action.payload;
      })
      .addCase(fetchNetworkView.fulfilled, (state, action) => {
        state.assets = action.payload;
      })
      .addCase(fetchLocationView.fulfilled, (state, action) => {
        state.assets = action.payload;
      })
      .addCase(fetchSecurityView.fulfilled, (state, action) => {
        state.assets = action.payload;
      })
      .addCase(fetchAssetTypes.fulfilled, (state, action) => {
        state.assetTypes = action.payload;
      });
  },
});

export const { clearError, clearSelectedAsset, setCurrentView } = assetsSlice.actions;
export default assetsSlice.reducer;
