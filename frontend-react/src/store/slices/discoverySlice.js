/**
 * Discovery Slice - Redux state management for Auto Discovery
 * Handles network scanning, pending hosts, and asset creation
 */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../api/axios';

// ============================================
// Initial State
// ============================================
const initialState = {
  // Scan state
  currentScan: null,
  scanHistory: [],

  // Pending hosts awaiting approval
  pendingHosts: [],
  selectedHost: null,
  matchResults: null,

  // Preview state for apply modes
  previewData: null,

  // Loading states
  loading: {
    scan: false,
    history: false,
    pending: false,
    approve: false,
    matches: false,
    preview: false,
    applyMode: false,
  },

  // Error state
  error: null,
};

// ============================================
// Async Thunks - API Calls
// ============================================

/**
 * Start a new network scan
 */
export const startScan = createAsyncThunk(
  'discovery/startScan',
  async (scanData, { rejectWithValue }) => {
    try {
      const response = await api.post('/api/discovery/scan', scanData);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to start scan');
    }
  }
);

/**
 * Check scan status (poll for results)
 */
export const checkScanStatus = createAsyncThunk(
  'discovery/checkStatus',
  async (scanId, { rejectWithValue }) => {
    try {
      const response = await api.get(`/api/discovery/scan/${scanId}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to check scan status');
    }
  }
);

/**
 * Fetch all scan history
 */
export const fetchScanHistory = createAsyncThunk(
  'discovery/fetchHistory',
  async (_, { rejectWithValue }) => {
    try {
      const response = await api.get('/api/discovery/scans');
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to load scan history');
    }
  }
);

/**
 * Delete a scan from history
 */
export const deleteScan = createAsyncThunk(
  'discovery/deleteScan',
  async (scanId, { rejectWithValue }) => {
    try {
      await api.delete(`/api/discovery/scan/${scanId}`);
      return scanId;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to delete scan');
    }
  }
);

/**
 * Fetch pending hosts awaiting approval
 */
export const fetchPendingHosts = createAsyncThunk(
  'discovery/fetchPending',
  async (scanId = null, { rejectWithValue }) => {
    try {
      const url = scanId ? `/api/discovery/pending?scan_id=${scanId}` : '/api/discovery/pending';
      const response = await api.get(url);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch pending hosts');
    }
  }
);

/**
 * Check for matching assets for a host
 */
export const checkHostMatches = createAsyncThunk(
  'discovery/checkMatches',
  async (hostId, { rejectWithValue }) => {
    try {
      const response = await api.get(`/api/discovery/hosts/${hostId}/check-matches`);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to check matches');
    }
  }
);

/**
 * Match IP to existing asset (for scan modal)
 */
export const matchIpToAsset = createAsyncThunk(
  'discovery/matchIp',
  async (ipAddress, { rejectWithValue }) => {
    try {
      const response = await api.get(`/api/discovery/match/${ipAddress}`);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to match IP');
    }
  }
);

/**
 * Approve a discovered host (create new or merge)
 */
export const approveHost = createAsyncThunk(
  'discovery/approveHost',
  async ({ hostId, action, assetId, assetData }, { rejectWithValue }) => {
    try {
      const requestBody = { action };
      if (action === 'merge_with_existing' && assetId) {
        requestBody.asset_id = assetId;
      }
      if (action === 'create_new' && assetData) {
        requestBody.asset_data = assetData;
      }
      const response = await api.post(`/api/discovery/hosts/${hostId}/approve`, requestBody);
      return { ...response.data, hostId };
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to approve host');
    }
  }
);

/**
 * Reject a discovered host
 */
export const rejectHost = createAsyncThunk(
  'discovery/rejectHost',
  async (hostId, { rejectWithValue }) => {
    try {
      const response = await api.post(`/api/discovery/hosts/${hostId}/reject`);
      return { ...response.data, hostId };
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to reject host');
    }
  }
);

/**
 * Preview discovery application (compare with existing asset)
 */
export const previewDiscoveryApplication = createAsyncThunk(
  'discovery/previewApplication',
  async ({ hostId, assetId }, { rejectWithValue }) => {
    try {
      let url = `/api/discovery/hosts/${hostId}/preview`;
      if (assetId) {
        url += `?asset_id=${assetId}`;
      }
      const response = await api.get(url);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to preview application');
    }
  }
);

/**
 * Apply discovery with mode (overwrite, merge, create_new)
 */
export const applyDiscoveryWithMode = createAsyncThunk(
  'discovery/applyWithMode',
  async ({ hostId, mode, assetId, assetName, assetTypeId, locationId, ownerId }, { rejectWithValue }) => {
    try {
      const requestBody = {
        mode,
        host_id: hostId,
      };

      if (mode === 'create_new') {
        requestBody.asset_name = assetName;
        requestBody.asset_type_id = assetTypeId;
        if (locationId) requestBody.location_id = locationId;
        if (ownerId) requestBody.owner_id = ownerId;
      } else {
        requestBody.asset_id = assetId;
      }

      const response = await api.post(`/api/discovery/hosts/${hostId}/apply`, requestBody);
      return { ...response.data, hostId };
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to apply discovery');
    }
  }
);

/**
 * Bulk approve multiple hosts
 */
export const bulkApproveHosts = createAsyncThunk(
  'discovery/bulkApprove',
  async ({ hostIds, defaultAssetTypeId, defaultLocationId, defaultOwnerId }, { rejectWithValue }) => {
    try {
      const requestBody = {
        host_ids: hostIds,
        default_asset_type_id: defaultAssetTypeId,
      };
      if (defaultLocationId) requestBody.default_location_id = defaultLocationId;
      if (defaultOwnerId) requestBody.default_owner_id = defaultOwnerId;

      const response = await api.post('/api/discovery/bulk-approve', requestBody);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to bulk approve');
    }
  }
);

// ============================================
// Slice Definition
// ============================================
const discoverySlice = createSlice({
  name: 'discovery',
  initialState,
  reducers: {
    // Clear error state
    clearError: (state) => {
      state.error = null;
    },

    // Clear current scan
    clearCurrentScan: (state) => {
      state.currentScan = null;
    },

    // Set selected host for details/approval
    setSelectedHost: (state, action) => {
      state.selectedHost = action.payload;
    },

    // Clear selected host
    clearSelectedHost: (state) => {
      state.selectedHost = null;
      state.matchResults = null;
    },

    // Clear match results
    clearMatchResults: (state) => {
      state.matchResults = null;
    },

    // Clear preview data
    clearPreviewData: (state) => {
      state.previewData = null;
    },

    // Stop scanning (client-side)
    stopScanning: (state) => {
      state.loading.scan = false;
      if (state.currentScan) {
        state.currentScan.status = 'stopped';
      }
    },
  },

  extraReducers: (builder) => {
    builder
      // ===== Start Scan =====
      .addCase(startScan.pending, (state) => {
        state.loading.scan = true;
        state.error = null;
        state.currentScan = null;
      })
      .addCase(startScan.fulfilled, (state, action) => {
        state.currentScan = action.payload;
      })
      .addCase(startScan.rejected, (state, action) => {
        state.loading.scan = false;
        state.error = action.payload;
      })

      // ===== Check Scan Status =====
      .addCase(checkScanStatus.fulfilled, (state, action) => {
        state.currentScan = action.payload;
        if (action.payload.status === 'completed' || action.payload.status === 'failed') {
          state.loading.scan = false;
        }
      })
      .addCase(checkScanStatus.rejected, (state, action) => {
        state.loading.scan = false;
        state.error = action.payload;
      })

      // ===== Fetch Scan History =====
      .addCase(fetchScanHistory.pending, (state) => {
        state.loading.history = true;
      })
      .addCase(fetchScanHistory.fulfilled, (state, action) => {
        state.loading.history = false;
        state.scanHistory = action.payload;
      })
      .addCase(fetchScanHistory.rejected, (state, action) => {
        state.loading.history = false;
        state.error = action.payload;
      })

      // ===== Delete Scan =====
      .addCase(deleteScan.fulfilled, (state, action) => {
        state.scanHistory = state.scanHistory.filter(s => s.scan_id !== action.payload);
      })

      // ===== Fetch Pending Hosts =====
      .addCase(fetchPendingHosts.pending, (state) => {
        state.loading.pending = true;
      })
      .addCase(fetchPendingHosts.fulfilled, (state, action) => {
        state.loading.pending = false;
        state.pendingHosts = action.payload.pending || [];
      })
      .addCase(fetchPendingHosts.rejected, (state, action) => {
        state.loading.pending = false;
        state.error = action.payload;
      })

      // ===== Check Host Matches =====
      .addCase(checkHostMatches.pending, (state) => {
        state.loading.matches = true;
      })
      .addCase(checkHostMatches.fulfilled, (state, action) => {
        state.loading.matches = false;
        state.matchResults = action.payload;
      })
      .addCase(checkHostMatches.rejected, (state, action) => {
        state.loading.matches = false;
        state.error = action.payload;
      })

      // ===== Approve Host =====
      .addCase(approveHost.pending, (state) => {
        state.loading.approve = true;
      })
      .addCase(approveHost.fulfilled, (state, action) => {
        state.loading.approve = false;
        // Remove from pending list
        state.pendingHosts = state.pendingHosts.filter(h => h.id !== action.payload.hostId);
        state.selectedHost = null;
        state.matchResults = null;
      })
      .addCase(approveHost.rejected, (state, action) => {
        state.loading.approve = false;
        state.error = action.payload;
      })

      // ===== Reject Host =====
      .addCase(rejectHost.pending, (state) => {
        state.loading.approve = true;
      })
      .addCase(rejectHost.fulfilled, (state, action) => {
        state.loading.approve = false;
        state.pendingHosts = state.pendingHosts.filter(h => h.id !== action.payload.hostId);
      })
      .addCase(rejectHost.rejected, (state, action) => {
        state.loading.approve = false;
        state.error = action.payload;
      })

      // ===== Bulk Approve =====
      .addCase(bulkApproveHosts.pending, (state) => {
        state.loading.approve = true;
      })
      .addCase(bulkApproveHosts.fulfilled, (state, action) => {
        state.loading.approve = false;
        // Refresh will be handled by component
      })
      .addCase(bulkApproveHosts.rejected, (state, action) => {
        state.loading.approve = false;
        state.error = action.payload;
      });
  },
});

export const {
  clearError,
  clearCurrentScan,
  setSelectedHost,
  clearSelectedHost,
  clearMatchResults,
  stopScanning,
} = discoverySlice.actions;

export default discoverySlice.reducer;
