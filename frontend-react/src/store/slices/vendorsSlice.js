/* ==========================================
   NGCORION - Vendors Slice
   ========================================== */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../api/axios';

const initialState = {
  items: [],
  loading: false,
  error: null,
};

export const fetchVendors = createAsyncThunk(
  'vendors/fetchAll',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/vendors/');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch');
    }
  }
);

export const createVendor = createAsyncThunk(
  'vendors/create',
  async (data, { rejectWithValue }) => {
    try {
      const response = await api.post('/api/vendors/', data);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to create');
    }
  }
);

export const deleteVendor = createAsyncThunk(
  'vendors/delete',
  async (id, { rejectWithValue }) => {
    try {
      await api.delete(`/api/vendors/${id}`);
      return id;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to delete');
    }
  }
);

const vendorsSlice = createSlice({
  name: 'vendors',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchVendors.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchVendors.fulfilled, (state, action) => {
        state.loading = false;
        state.items = action.payload;
      })
      .addCase(fetchVendors.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      .addCase(createVendor.fulfilled, (state, action) => {
        state.items.push(action.payload);
      })
      .addCase(deleteVendor.fulfilled, (state, action) => {
        state.items = state.items.filter((i) => i.id !== action.payload);
      });
  },
});

export const { clearError } = vendorsSlice.actions;
export default vendorsSlice.reducer;
