/* ==========================================
   NGCORION - Asset Dependencies Slice
   ========================================== */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../api/axios';

const initialState = {
  items: [],
  loading: false,
  error: null,
};

export const fetchDependencies = createAsyncThunk(
  'dependencies/fetchAll',
  async (assetId, { rejectWithValue }) => {
    try {
      const response = await api.get(`/api/dependencies/asset/${assetId}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch');
    }
  }
);

export const fetchAllDependencies = createAsyncThunk(
  'dependencies/fetchAllDeps',
  async (_, { rejectWithValue }) => {
    try {
      // Fetch all assets first to get all dependencies
      const assetsResponse = await api.get('/api/assets/');
      const assets = assetsResponse.data;

      // Collect all dependencies for all assets
      const allDeps = [];
      for (const asset of assets) {
        try {
          const depsResponse = await api.get(`/api/dependencies/asset/${asset.id}`);
          allDeps.push(...depsResponse.data);
        } catch (err) {
          // Skip if asset has no dependencies
          continue;
        }
      }

      // Remove duplicates based on id
      const uniqueDeps = Array.from(new Map(allDeps.map(dep => [dep.id, dep])).values());
      return uniqueDeps;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch all dependencies');
    }
  }
);

export const createDependency = createAsyncThunk(
  'dependencies/create',
  async (data, { rejectWithValue }) => {
    try {
      const response = await api.post('/api/dependencies/', data);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to create');
    }
  }
);

export const deleteDependency = createAsyncThunk(
  'dependencies/delete',
  async (id, { rejectWithValue }) => {
    try {
      await api.delete(`/api/dependencies/${id}`);
      return id;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to delete');
    }
  }
);

const dependenciesSlice = createSlice({
  name: 'dependencies',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    clearDependencies: (state) => {
      state.items = [];
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchDependencies.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchDependencies.fulfilled, (state, action) => {
        state.loading = false;
        state.items = action.payload;
      })
      .addCase(fetchDependencies.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      .addCase(fetchAllDependencies.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchAllDependencies.fulfilled, (state, action) => {
        state.loading = false;
        state.items = action.payload;
      })
      .addCase(fetchAllDependencies.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      .addCase(createDependency.fulfilled, (state, action) => {
        state.items.push(action.payload);
      })
      .addCase(deleteDependency.fulfilled, (state, action) => {
        state.items = state.items.filter((i) => i.id !== action.payload);
      });
  },
});

export const { clearError, clearDependencies } = dependenciesSlice.actions;
export default dependenciesSlice.reducer;
