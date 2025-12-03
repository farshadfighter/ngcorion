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
  
  // Activity Log
  activityLog: [],
  
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

// Clear all scan history
export const clearAllScans = createAsyncThunk(
  'discovery/clearAll',
  async (_, { getState, dispatch, rejectWithValue }) => {
    try {
      const { scanHistory } = getState().discovery;
      // Delete all scans one by one
      for (const scan of scanHistory) {
        await api.delete(`/api/discovery/scan/${scan.scan_id}`);
      }
      return true;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.detail || 'Failed to clear history'
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
    
    // Stop scanning (client-side only)
    stopScanning: (state) => {
      state.isScanning = false;
      if (state.currentScan) {
        state.currentScan.status = 'stopped';
      }
      state.activityLog.unshift({
        id: Date.now(),
        type: 'warning',
        message: 'Scan stopped by user',
        timestamp: new Date().toISOString(),
      });
    },
    
    // Add log entry
    addLogEntry: (state, action) => {
      state.activityLog.unshift({
        id: Date.now(),
        ...action.payload,
        timestamp: new Date().toISOString(),
      });
      // Keep only last 100 logs
      if (state.activityLog.length > 100) {
        state.activityLog = state.activityLog.slice(0, 100);
      }
    },
    
    // Clear activity log
    clearActivityLog: (state) => {
      state.activityLog = [];
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
        state.activityLog.unshift({
          id: Date.now(),
          type: 'info',
          message: 'Starting network scan...',
          timestamp: new Date().toISOString(),
        });
      })
      .addCase(startScan.fulfilled, (state, action) => {
        state.currentScan = action.payload;
        state.activityLog.unshift({
          id: Date.now(),
          type: 'success',
          message: `Scan started: ${action.payload.target} (${action.payload.scan_type})`,
          details: `Scan ID: ${action.payload.scan_id}`,
          timestamp: new Date().toISOString(),
        });
      })
      .addCase(startScan.rejected, (state, action) => {
        state.isScanning = false;
        state.error = action.payload;
        state.activityLog.unshift({
          id: Date.now(),
          type: 'error',
          message: `Scan failed to start: ${action.payload}`,
          timestamp: new Date().toISOString(),
        });
      })
      
      // ===== Check Status =====
      .addCase(checkScanStatus.fulfilled, (state, action) => {
        const prevStatus = state.currentScan?.status;
        state.currentScan = action.payload;
        
        if (action.payload.status === 'completed' && prevStatus === 'running') {
          state.isScanning = false;
          state.discoveredHosts = action.payload.hosts || [];
          state.activityLog.unshift({
            id: Date.now(),
            type: 'success',
            message: `Scan completed: Found ${action.payload.hosts_up} hosts`,
            details: action.payload.hosts?.map(h => h.ip_address).join(', '),
            timestamp: new Date().toISOString(),
          });
          // Log each discovered host
          action.payload.hosts?.forEach(host => {
            state.activityLog.unshift({
              id: Date.now() + Math.random(),
              type: 'host',
              message: `Host discovered: ${host.ip_address}`,
              details: `${host.hostname || 'No hostname'} | ${host.os_name || 'Unknown OS'} | ${host.ports?.length || 0} ports`,
              timestamp: new Date().toISOString(),
            });
          });
        } else if (action.payload.status === 'failed') {
          state.isScanning = false;
          state.error = action.payload.error || 'Scan failed';
          state.activityLog.unshift({
            id: Date.now(),
            type: 'error',
            message: `Scan failed: ${action.payload.error || 'Unknown error'}`,
            timestamp: new Date().toISOString(),
          });
        }
      })
      .addCase(checkScanStatus.rejected, (state, action) => {
        state.isScanning = false;
        state.error = action.payload;
        state.activityLog.unshift({
          id: Date.now(),
          type: 'error',
          message: `Failed to check scan status: ${action.payload}`,
          timestamp: new Date().toISOString(),
        });
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
        state.activityLog.unshift({
          id: Date.now(),
          type: 'info',
          message: 'Applying discovery data to asset...',
          timestamp: new Date().toISOString(),
        });
      })
      .addCase(applyDiscovery.fulfilled, (state, action) => {
        state.isApplying = false;
        state.activityLog.unshift({
          id: Date.now(),
          type: 'success',
          message: `Applied to asset #${action.payload.asset_id}`,
          details: `Updated: ${action.payload.updated_fields?.join(', ') || 'none'}`,
          timestamp: new Date().toISOString(),
        });
      })
      .addCase(applyDiscovery.rejected, (state, action) => {
        state.isApplying = false;
        state.error = action.payload;
        state.activityLog.unshift({
          id: Date.now(),
          type: 'error',
          message: `Failed to apply: ${action.payload}`,
          timestamp: new Date().toISOString(),
        });
      })
      
      // ===== Create Asset =====
      .addCase(createAssetFromDiscovery.pending, (state) => {
        state.isApplying = true;
        state.activityLog.unshift({
          id: Date.now(),
          type: 'info',
          message: 'Creating new asset from discovery...',
          timestamp: new Date().toISOString(),
        });
      })
      .addCase(createAssetFromDiscovery.fulfilled, (state, action) => {
        state.isApplying = false;
        state.activityLog.unshift({
          id: Date.now(),
          type: 'success',
          message: `Asset created: ${action.payload.asset_name}`,
          details: `Asset ID: ${action.payload.asset_id}`,
          timestamp: new Date().toISOString(),
        });
      })
      .addCase(createAssetFromDiscovery.rejected, (state, action) => {
        state.isApplying = false;
        state.error = action.payload;
        state.activityLog.unshift({
          id: Date.now(),
          type: 'error',
          message: `Failed to create asset: ${action.payload}`,
          timestamp: new Date().toISOString(),
        });
      })
      
      // ===== Delete Scan =====
      .addCase(deleteScan.fulfilled, (state, action) => {
        state.scanHistory = state.scanHistory.filter(
          (scan) => scan.scan_id !== action.payload
        );
      })
      
      // ===== Clear All Scans =====
      .addCase(clearAllScans.pending, (state) => {
        state.isLoadingScans = true;
      })
      .addCase(clearAllScans.fulfilled, (state) => {
        state.isLoadingScans = false;
        state.scanHistory = [];
      })
      .addCase(clearAllScans.rejected, (state, action) => {
        state.isLoadingScans = false;
        state.error = action.payload;
      });
  },
});

export const { 
  clearError, 
  clearCurrentScan, 
  clearMatchedAsset,
  setDiscoveredHosts,
  stopScanning,
  addLogEntry,
  clearActivityLog,
} = discoverySlice.actions;

export default discoverySlice.reducer;
