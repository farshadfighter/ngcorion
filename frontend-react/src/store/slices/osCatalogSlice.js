/* ==========================================
   NGCORION - OS Catalog Slice
   ========================================== */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../api/axios';

const initialState = {
  items: [],
  loading: false,
  error: null,
};

export const fetchOSCatalog = createAsyncThunk(
  'osCatalog/fetchAll',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/os-catalog/');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch');
    }
  }
);

export const createOS = createAsyncThunk(
  'osCatalog/create',
  async (data, { rejectWithValue }) => {
    try {
      const response = await api.post('/api/os-catalog/', data);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to create');
    }
  }
);

export const deleteOS = createAsyncThunk(
  'osCatalog/delete',
  async (id, { rejectWithValue }) => {
    try {
      await api.delete(`/api/os-catalog/${id}`);
      return id;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to delete');
    }
  }
);

const osCatalogSlice = createSlice({
  name: 'osCatalog',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchOSCatalog.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchOSCatalog.fulfilled, (state, action) => {
        state.loading = false;
        state.items = action.payload;
      })
      .addCase(fetchOSCatalog.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      .addCase(createOS.fulfilled, (state, action) => {
        state.items.push(action.payload);
      })
      .addCase(deleteOS.fulfilled, (state, action) => {
        state.items = state.items.filter((i) => i.id !== action.payload);
      });
  },
});

export const { clearError } = osCatalogSlice.actions;
export default osCatalogSlice.reducer;
