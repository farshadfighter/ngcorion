/* ==========================================
   NGCORION - Asset Types Slice
   ========================================== */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../api/axios';

const initialState = {
  items: [],
  loading: false,
  error: null,
};

export const fetchAssetTypes = createAsyncThunk(
  'assetTypes/fetchAll',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/asset-types/');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch');
    }
  }
);

export const createAssetType = createAsyncThunk(
  'assetTypes/create',
  async (data, { rejectWithValue }) => {
    try {
      const response = await api.post('/api/asset-types/', data);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to create');
    }
  }
);

export const updateAssetType = createAsyncThunk(
  'assetTypes/update',
  async ({ id, data }, { rejectWithValue }) => {
    try {
      const response = await api.put(`/api/asset-types/${id}`, data);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to update');
    }
  }
);

export const deleteAssetType = createAsyncThunk(
  'assetTypes/delete',
  async (id, { rejectWithValue }) => {
    try {
      await api.delete(`/api/asset-types/${id}`);
      return id;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to delete');
    }
  }
);

const assetTypesSlice = createSlice({
  name: 'assetTypes',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchAssetTypes.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchAssetTypes.fulfilled, (state, action) => {
        state.loading = false;
        state.items = action.payload;
      })
      .addCase(fetchAssetTypes.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      .addCase(createAssetType.fulfilled, (state, action) => {
        state.items.push(action.payload);
      })
      .addCase(updateAssetType.fulfilled, (state, action) => {
        const index = state.items.findIndex((i) => i.id === action.payload.id);
        if (index !== -1) state.items[index] = action.payload;
      })
      .addCase(deleteAssetType.fulfilled, (state, action) => {
        state.items = state.items.filter((i) => i.id !== action.payload);
      });
  },
});

export const { clearError } = assetTypesSlice.actions;
export default assetTypesSlice.reducer;
