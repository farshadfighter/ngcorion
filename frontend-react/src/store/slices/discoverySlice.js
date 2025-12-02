/* ==========================================
   NGCORION - Discovery Slice
   Redux state management for Auto Discovery
   ========================================== */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../api/axios';

// Initial state
const initialState = {
  // Scan state
  currentScan: null,
  scanHistory: [],
  
  // Loading states
  isScanning: false,
  isLoadingScans: false,
  isApplying: false,
  
  // Results
  discoveredHosts: [],
  matchedAsset: null,
  
  // Errors
  error: null,
};

// ==================== Async Thunks ====================

// Start a new scan
export const startScan = createAsyncThunk(
  'discovery/startScan',
  async ({ target, scanType = 'basic' }, { rejectWithValue }) => {
    try {
      const response = await api.post('/api/discovery/scan', {
        target,
        scan_type: scanType,
      });
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.detail || 'Failed to start scan'
      );
    }
  }
);

// Check scan status
export const checkScanStatus = createAsyncThunk(
  'discovery/checkStatus',
  async (scanId, { rejectWithValue }) => {
    try {
      const response = await api.get(`/api/discovery/scan/${scanId}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.detail || 'Failed to check scan status'
      );
    }
  }
);

// Get all scans
export const fetchAllScans = createAsyncThunk(
  'discovery/fetchAllScans',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/discovery/scans');
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.detail || 'Failed to load scans'
      );
    }
  }
);

// Match IP to existing asset
export const matchIpToAsset = createAsyncThunk(
  'discovery/matchIp',
  async (ipAddress, { rejectWithValue }) => {
    try {
      const response = await api.get(`/api/discovery/match/${ipAddress}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.detail || 'Failed to match IP'
      );
    }
  }
);

// Apply discovery results to asset
export const applyDiscovery = createAsyncThunk(
  'discovery/apply',
  async ({ scanId, assetId, ipAddress, fieldsToApply }, { rejectWithValue }) => {
    try {
      const response = await api.post(
        `/api/discovery/apply?scan_id=${scanId}`,
        {
          asset_id: assetId,
          ip_address: ipAddress,
          fields_to_apply: fieldsToApply,
        }
      );
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.detail || 'Failed to apply discovery'
      );
    }
  }
);

// Create asset from discovery
export const createAssetFromDiscovery = createAsyncThunk(
  'discovery/createAsset',
  async ({ discoveredHost, assetName, assetTypeId }, { rejectWithValue }) => {
    try {
      const response = await api.post('/api/discovery/create-asset', {
        discovered_host: discoveredHost,
        asset_name: assetName,
        asset_type_id: assetTypeId,
      });
      return response.data;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.detail || 'Failed to create asset'
      );
    }
  }
);

// Delete a scan
export const deleteScan = createAsyncThunk(
  'discovery/deleteScan',
  async (scanId, { rejectWithValue }) => {
    try {
      await api.delete(`/api/discovery/scan/${scanId}`);
      return scanId;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.detail || 'Failed to delete scan'
      );
    }
  }
);

// ==================== Slice ====================

const discoverySlice = createSlice({
  name: 'discovery',
  initialState,
  reducers: {
    // Clear error
    clearError: (state) => {
      state.error = null;
    },
    
    // Clear current scan
    clearCurrentScan: (state) => {
      state.currentScan = null;
      state.discoveredHosts = [];
    },
    
    // Clear matched asset
    clearMatchedAsset: (state) => {
      state.matchedAsset = null;
    },
    
    // Update discovered hosts from current scan
    setDiscoveredHosts: (state, action) => {
      state.discoveredHosts = action.payload;
    },
  },
  
  extraReducers: (builder) => {
    builder
      // ===== Start Scan =====
      .addCase(startScan.pending, (state) => {
        state.isScanning = true;
        state.error = null;
        state.currentScan = null;
        state.discoveredHosts = [];
      })
      .addCase(startScan.fulfilled, (state, action) => {
        state.currentScan = action.payload;
        // Still scanning until status is 'completed'
      })
      .addCase(startScan.rejected, (state, action) => {
        state.isScanning = false;
        state.error = action.payload;
      })
      
      // ===== Check Status =====
      .addCase(checkScanStatus.fulfilled, (state, action) => {
        state.currentScan = action.payload;
        
        if (action.payload.status === 'completed') {
          state.isScanning = false;
          state.discoveredHosts = action.payload.hosts || [];
        } else if (action.payload.status === 'failed') {
          state.isScanning = false;
          state.error = action.payload.error || 'Scan failed';
        }
      })
      .addCase(checkScanStatus.rejected, (state, action) => {
        state.isScanning = false;
        state.error = action.payload;
      })
      
      // ===== Fetch All Scans =====
      .addCase(fetchAllScans.pending, (state) => {
        state.isLoadingScans = true;
      })
      .addCase(fetchAllScans.fulfilled, (state, action) => {
        state.isLoadingScans = false;
        state.scanHistory = action.payload;
      })
      .addCase(fetchAllScans.rejected, (state, action) => {
        state.isLoadingScans = false;
        state.error = action.payload;
      })
      
      // ===== Match IP =====
      .addCase(matchIpToAsset.fulfilled, (state, action) => {
        state.matchedAsset = action.payload;
      })
      .addCase(matchIpToAsset.rejected, (state, action) => {
        state.error = action.payload;
      })
      
      // ===== Apply Discovery =====
      .addCase(applyDiscovery.pending, (state) => {
        state.isApplying = true;
      })
      .addCase(applyDiscovery.fulfilled, (state) => {
        state.isApplying = false;
      })
      .addCase(applyDiscovery.rejected, (state, action) => {
        state.isApplying = false;
        state.error = action.payload;
      })
      
      // ===== Create Asset =====
      .addCase(createAssetFromDiscovery.pending, (state) => {
        state.isApplying = true;
      })
      .addCase(createAssetFromDiscovery.fulfilled, (state) => {
        state.isApplying = false;
      })
      .addCase(createAssetFromDiscovery.rejected, (state, action) => {
        state.isApplying = false;
        state.error = action.payload;
      })
      
      // ===== Delete Scan =====
      .addCase(deleteScan.fulfilled, (state, action) => {
        state.scanHistory = state.scanHistory.filter(
          (scan) => scan.scan_id !== action.payload
        );
      });
  },
});

export const { 
  clearError, 
  clearCurrentScan, 
  clearMatchedAsset,
  setDiscoveredHosts 
} = discoverySlice.actions;

export default discoverySlice.reducer;
