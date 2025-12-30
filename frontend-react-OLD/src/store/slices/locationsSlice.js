/* ==========================================
   NGCORION - Locations Slice
   ========================================== */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../api/axios';

const initialState = {
  items: [],
  loading: false,
  error: null,
};

export const fetchLocations = createAsyncThunk(
  'locations/fetchAll',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/locations/');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch');
    }
  }
);

export const createLocation = createAsyncThunk(
  'locations/create',
  async (data, { rejectWithValue }) => {
    try {
      const response = await api.post('/api/locations/', data);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to create');
    }
  }
);

export const updateLocation = createAsyncThunk(
  'locations/update',
  async ({ id, data }, { rejectWithValue }) => {
    try {
      const response = await api.put(`/api/locations/${id}`, data);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to update');
    }
  }
);

export const deleteLocation = createAsyncThunk(
  'locations/delete',
  async (id, { rejectWithValue }) => {
    try {
      await api.delete(`/api/locations/${id}`);
      return id;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to delete');
    }
  }
);

const locationsSlice = createSlice({
  name: 'locations',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchLocations.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchLocations.fulfilled, (state, action) => {
        state.loading = false;
        state.items = action.payload;
      })
      .addCase(fetchLocations.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      .addCase(createLocation.fulfilled, (state, action) => {
        state.items.push(action.payload);
      })
      .addCase(updateLocation.fulfilled, (state, action) => {
        const index = state.items.findIndex((i) => i.id === action.payload.id);
        if (index !== -1) state.items[index] = action.payload;
      })
      .addCase(deleteLocation.fulfilled, (state, action) => {
        state.items = state.items.filter((i) => i.id !== action.payload);
      });
  },
});

export const { clearError } = locationsSlice.actions;
export default locationsSlice.reducer;
