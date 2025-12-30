/* ==========================================
   NGCORION - Owners Slice
   ========================================== */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../api/axios';

const initialState = {
  items: [],
  loading: false,
  error: null,
};

export const fetchOwners = createAsyncThunk(
  'owners/fetchAll',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/owners/');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch');
    }
  }
);

export const createOwner = createAsyncThunk(
  'owners/create',
  async (data, { rejectWithValue }) => {
    try {
      const response = await api.post('/api/owners/', data);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to create');
    }
  }
);

export const updateOwner = createAsyncThunk(
  'owners/update',
  async ({ id, data }, { rejectWithValue }) => {
    try {
      const response = await api.put(`/api/owners/${id}`, data);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to update');
    }
  }
);

export const deleteOwner = createAsyncThunk(
  'owners/delete',
  async (id, { rejectWithValue }) => {
    try {
      await api.delete(`/api/owners/${id}`);
      return id;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to delete');
    }
  }
);

const ownersSlice = createSlice({
  name: 'owners',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchOwners.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchOwners.fulfilled, (state, action) => {
        state.loading = false;
        state.items = action.payload;
      })
      .addCase(fetchOwners.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      .addCase(createOwner.fulfilled, (state, action) => {
        state.items.push(action.payload);
      })
      .addCase(updateOwner.fulfilled, (state, action) => {
        const index = state.items.findIndex((i) => i.id === action.payload.id);
        if (index !== -1) state.items[index] = action.payload;
      })
      .addCase(deleteOwner.fulfilled, (state, action) => {
        state.items = state.items.filter((i) => i.id !== action.payload);
      });
  },
});

export const { clearError } = ownersSlice.actions;
export default ownersSlice.reducer;
