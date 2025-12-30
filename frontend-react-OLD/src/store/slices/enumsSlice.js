/* ==========================================
   NGCORION - Enums Slice
   ========================================== */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../api/axios';

const initialState = {
  status: [],
  confidentiality: [],
  risk: [],
  relationTypes: [],
  loading: false,
  error: null,
};

export const fetchAllEnums = createAsyncThunk(
  'enums/fetchAll',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/enums/all');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch enums');
    }
  }
);

const enumsSlice = createSlice({
  name: 'enums',
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(fetchAllEnums.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchAllEnums.fulfilled, (state, action) => {
        state.loading = false;
        state.status = action.payload.status || [];
        state.confidentiality = action.payload.confidentiality || [];
        state.risk = action.payload.risk || [];
        state.relationTypes = action.payload.relation_types || [];
      })
      .addCase(fetchAllEnums.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      });
  },
});

export default enumsSlice.reducer;
