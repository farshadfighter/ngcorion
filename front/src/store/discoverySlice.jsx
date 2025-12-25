/**
 * Discovery Slice - Redux state management for Auto Discovery
 * Handles network scanning, pending hosts, and asset creation
 */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from "../config/api.js";

// ============================================
// LocalStorage Persistence Helpers
// ============================================
const STORAGE_KEY = 'discovery_currentScan';

const loadScanFromStorage = () => {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const parsed = JSON.parse(saved);
      // Only restore if scan was running (not completed/failed)
      if (parsed && parsed.status === 'running') {
        return parsed;
      }
    }
  } catch (e) {
    console.warn('Failed to load scan from localStorage:', e);
  }
  return null;
};

const saveScanToStorage = (scan) => {
  try {
    if (scan && scan.status === 'running') {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(scan));
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch (e) {
    console.warn('Failed to save scan to localStorage:', e);
  }
};

const clearScanFromStorage = () => {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (e) {
    console.warn('Failed to clear scan from localStorage:', e);
  }
};

// ============================================
// Initial State
// ============================================
const initialState = {
  // Scan state - try to restore from localStorage
  currentScan: loadScanFromStorage(),
  scanHistory: [],

  // Pending hosts awaiting approval
  pendingHosts: [],
  selectedHost: null,
  matchResults: null,

  // Preview state for apply modes
  previewData: null,

  // Asset ports state
  assetPorts: [],

  // Loading states
  loading: {
    scan: false,
    history: false,
    pending: false,
    approve: false,
    matches: false,
    preview: false,
    applyMode: false,
    ports: false,
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

/**
 * Add ports to an asset (non-destructive merge)
 */
export const addPortsToAsset = createAsyncThunk(
  'discovery/addPorts',
  async ({ assetId, ports, scanId }, { rejectWithValue }) => {
    try {
      const requestBody = {
        asset_id: assetId,
        ports,
      };
      if (scanId) requestBody.scan_id = scanId;

      const response = await api.post('/api/discovery/ports/add', requestBody);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to add ports');
    }
  }
);

/**
 * Overwrite all ports for an asset (destructive)
 */
export const overwriteAssetPorts = createAsyncThunk(
  'discovery/overwritePorts',
  async ({ assetId, ports, scanId }, { rejectWithValue }) => {
    try {
      const requestBody = {
        asset_id: assetId,
        ports,
      };
      if (scanId) requestBody.scan_id = scanId;

      const response = await api.post('/api/discovery/ports/overwrite', requestBody);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to overwrite ports');
    }
  }
);

/**
 * Get all ports for an asset
 */
export const fetchAssetPorts = createAsyncThunk(
  'discovery/fetchAssetPorts',
  async (assetId, { rejectWithValue }) => {
    try {
      const response = await api.get(`/api/discovery/assets/${assetId}/ports`);
      return response.data;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to fetch asset ports');
    }
  }
);

/**
 * Delete a specific port
 */
export const deletePort = createAsyncThunk(
  'discovery/deletePort',
  async (portId, { rejectWithValue }) => {
    try {
      await api.delete(`/api/discovery/ports/${portId}`);
      return portId;
    } catch (error) {
      return rejectWithValue(error.response?.data?.detail || 'Failed to delete port');
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
      clearScanFromStorage();
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
      clearScanFromStorage();
    },
  },

  extraReducers: (builder) => {
    builder
      // ===== Start Scan =====
      .addCase(startScan.pending, (state) => {
        state.loading.scan = true;
        state.error = null;
        state.currentScan = null;
        clearScanFromStorage();
      })
      .addCase(startScan.fulfilled, (state, action) => {
        state.currentScan = action.payload;
        saveScanToStorage(action.payload);
      })
      .addCase(startScan.rejected, (state, action) => {
        state.loading.scan = false;
        state.error = action.payload;
        clearScanFromStorage();
      })

      // ===== Check Scan Status =====
      .addCase(checkScanStatus.fulfilled, (state, action) => {
        state.currentScan = action.payload;
        if (action.payload.status === 'completed' || action.payload.status === 'failed') {
          state.loading.scan = false;
          clearScanFromStorage();
        } else {
          saveScanToStorage(action.payload);
        }
      })
      .addCase(checkScanStatus.rejected, (state, action) => {
        state.loading.scan = false;
        state.error = action.payload;
        clearScanFromStorage();
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
      })

      // ===== Preview Discovery Application =====
      .addCase(previewDiscoveryApplication.pending, (state) => {
        state.loading.preview = true;
        state.previewData = null;
      })
      .addCase(previewDiscoveryApplication.fulfilled, (state, action) => {
        state.loading.preview = false;
        state.previewData = action.payload;
      })
      .addCase(previewDiscoveryApplication.rejected, (state, action) => {
        state.loading.preview = false;
        state.error = action.payload;
      })

      // ===== Apply Discovery With Mode =====
      .addCase(applyDiscoveryWithMode.pending, (state) => {
        state.loading.applyMode = true;
      })
      .addCase(applyDiscoveryWithMode.fulfilled, (state, action) => {
        state.loading.applyMode = false;
        // Remove from pending list
        state.pendingHosts = state.pendingHosts.filter(h => h.id !== action.payload.hostId);
        state.selectedHost = null;
        state.matchResults = null;
        state.previewData = null;
      })
      .addCase(applyDiscoveryWithMode.rejected, (state, action) => {
        state.loading.applyMode = false;
        state.error = action.payload;
      })

      // ===== Add Ports to Asset =====
      .addCase(addPortsToAsset.pending, (state) => {
        state.loading.ports = true;
      })
      .addCase(addPortsToAsset.fulfilled, (state) => {
        state.loading.ports = false;
      })
      .addCase(addPortsToAsset.rejected, (state, action) => {
        state.loading.ports = false;
        state.error = action.payload;
      })

      // ===== Overwrite Asset Ports =====
      .addCase(overwriteAssetPorts.pending, (state) => {
        state.loading.ports = true;
      })
      .addCase(overwriteAssetPorts.fulfilled, (state) => {
        state.loading.ports = false;
      })
      .addCase(overwriteAssetPorts.rejected, (state, action) => {
        state.loading.ports = false;
        state.error = action.payload;
      })

      // ===== Fetch Asset Ports =====
      .addCase(fetchAssetPorts.pending, (state) => {
        state.loading.ports = true;
        state.assetPorts = [];
      })
      .addCase(fetchAssetPorts.fulfilled, (state, action) => {
        state.loading.ports = false;
        state.assetPorts = action.payload.ports || [];
      })
      .addCase(fetchAssetPorts.rejected, (state, action) => {
        state.loading.ports = false;
        state.error = action.payload;
      })

      // ===== Delete Port =====
      .addCase(deletePort.pending, (state) => {
        state.loading.ports = true;
      })
      .addCase(deletePort.fulfilled, (state, action) => {
        state.loading.ports = false;
        // Remove deleted port from assetPorts array
        state.assetPorts = state.assetPorts.filter(p => p.id !== action.payload);
      })
      .addCase(deletePort.rejected, (state, action) => {
        state.loading.ports = false;
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
  clearPreviewData,
  stopScanning,
} = discoverySlice.actions;

export default discoverySlice.reducer;
