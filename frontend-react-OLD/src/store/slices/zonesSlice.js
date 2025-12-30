/* ==========================================
   NGCORION - Network Zones Slice
   ========================================== */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../api/axios';

const initialState = {
  items: [],
  loading: false,
  error: null,
};

export const fetchZones = createAsyncThunk(
  'zones/fetchAll',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/zones/');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch');
    }
  }
);

export const createZone = createAsyncThunk(
  'zones/create',
  async (data, { rejectWithValue }) => {
    try {
      const response = await api.post('/api/zones/', data);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to create');
    }
  }
);

export const deleteZone = createAsyncThunk(
  'zones/delete',
  async (id, { rejectWithValue }) => {
    try {
      await api.delete(`/api/zones/${id}`);
      return id;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to delete');
    }
  }
);

const zonesSlice = createSlice({
  name: 'zones',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchZones.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchZones.fulfilled, (state, action) => {
        state.loading = false;
        state.items = action.payload;
      })
      .addCase(fetchZones.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      .addCase(createZone.fulfilled, (state, action) => {
        state.items.push(action.payload);
      })
      .addCase(deleteZone.fulfilled, (state, action) => {
        state.items = state.items.filter((i) => i.id !== action.payload);
      });
  },
});

export const { clearError } = zonesSlice.actions;
export default zonesSlice.reducer;
