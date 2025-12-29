/**
 * Discovery Slice - با Tracking برای Assets ساخته‌شده از Discovery
 * ✅ همه endpointها با OpenAPI مطابقت دارند
 * ✅ tracking برای assetهای ساخته‌شده از discovery اضافه شد
 */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from "../config/api.js";

// ============================================
// LocalStorage Helpers
// ============================================
const STORAGE_KEY_SCAN = 'discovery_currentScan';
const STORAGE_KEY_ASSETS = 'discoveryCreatedAssetIds';

// Load current scan
const loadScanFromStorage = () => {
    try {
        const saved = localStorage.getItem(STORAGE_KEY_SCAN);
        if (saved) {
            const parsed = JSON.parse(saved);
            if (parsed && parsed.status === 'running') {
                return parsed;
            }
        }
    } catch (e) {
        console.warn('Failed to load scan from localStorage:', e);
    }
    return null;
};

// Save current scan
const saveScanToStorage = (scan) => {
    try {
        if (scan && scan.status === 'running') {
            localStorage.setItem(STORAGE_KEY_SCAN, JSON.stringify(scan));
        } else {
            localStorage.removeItem(STORAGE_KEY_SCAN);
        }
    } catch (e) {
        console.warn('Failed to save scan to localStorage:', e);
    }
};

// Clear current scan
const clearScanFromStorage = () => {
    try {
        localStorage.removeItem(STORAGE_KEY_SCAN);
    } catch (e) {
        console.warn('Failed to clear scan from localStorage:', e);
    }
};

// Load discovery created asset IDs
const loadDiscoveryAssetsFromStorage = () => {
    try {
        const saved = localStorage.getItem(STORAGE_KEY_ASSETS);
        return saved ? JSON.parse(saved) : [];
    } catch (e) {
        console.warn('Failed to load discovery assets from localStorage:', e);
        return [];
    }
};

// Save discovery created asset IDs
const saveDiscoveryAssetsToStorage = (assetIds) => {
    try {
        localStorage.setItem(STORAGE_KEY_ASSETS, JSON.stringify(assetIds));
    } catch (e) {
        console.warn('Failed to save discovery assets to localStorage:', e);
    }
};

// ============================================
// Initial State
// ============================================
const initialState = {
    // Scan state
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

    // 🔥 NEW: Track assets created via discovery
    discoveryCreatedAssetIds: loadDiscoveryAssetsFromStorage(),

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
// Async Thunks
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
 * Check scan status
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
 * Delete a scan
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
 * Fetch pending hosts
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
 * Check for matching assets
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
 * Approve a discovered host
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

            return {
                ...response.data,
                hostId,
                createdAsset: action === 'create_new' ? response.data.asset_id : null
            };
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
 * Preview discovery application
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
 * Apply discovery with mode
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

            return {
                ...response.data,
                hostId,
                createdAsset: mode === 'create_new' ? response.data.asset_id : null
            };
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to apply discovery');
        }
    }
);

/**
 * Bulk approve hosts
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
 * Add ports to asset
 */
export const addPortsToAsset = createAsyncThunk(
    'discovery/addPorts',
    async ({ assetId, ports, scanId }, { rejectWithValue }) => {
        try {
            const requestBody = { asset_id: assetId, ports };
            if (scanId) requestBody.scan_id = scanId;
            const response = await api.post('/api/discovery/ports/add', requestBody);
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to add ports');
        }
    }
);

/**
 * Overwrite asset ports
 */
export const overwriteAssetPorts = createAsyncThunk(
    'discovery/overwritePorts',
    async ({ assetId, ports, scanId }, { rejectWithValue }) => {
        try {
            const requestBody = { asset_id: assetId, ports };
            if (scanId) requestBody.scan_id = scanId;
            const response = await api.post('/api/discovery/ports/overwrite', requestBody);
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to overwrite ports');
        }
    }
);

/**
 * Fetch asset ports
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
 * Delete a port
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
// Slice
// ============================================
const discoverySlice = createSlice({
    name: 'discovery',
    initialState,
    reducers: {
        clearError: (state) => {
            state.error = null;
        },

        clearCurrentScan: (state) => {
            state.currentScan = null;
            clearScanFromStorage();
        },

        setSelectedHost: (state, action) => {
            state.selectedHost = action.payload;
        },

        clearSelectedHost: (state) => {
            state.selectedHost = null;
            state.matchResults = null;
        },

        clearMatchResults: (state) => {
            state.matchResults = null;
        },

        clearPreviewData: (state) => {
            state.previewData = null;
        },

        stopScanning: (state) => {
            state.loading.scan = false;
            if (state.currentScan) {
                state.currentScan.status = 'stopped';
            }
            clearScanFromStorage();
        },

        // 🔥 NEW: Add asset to discovery tracking
        addDiscoveryCreatedAsset: (state, action) => {
            const assetId = action.payload;
            if (!state.discoveryCreatedAssetIds.includes(assetId)) {
                state.discoveryCreatedAssetIds.push(assetId);
                saveDiscoveryAssetsToStorage(state.discoveryCreatedAssetIds);
            }
        },

        // 🔥 NEW: Remove asset from discovery tracking
        removeDiscoveryCreatedAsset: (state, action) => {
            const assetId = action.payload;
            state.discoveryCreatedAssetIds = state.discoveryCreatedAssetIds.filter(
                id => id !== assetId
            );
            saveDiscoveryAssetsToStorage(state.discoveryCreatedAssetIds);
        },

        // 🔥 NEW: Clear all discovery assets
        clearDiscoveryCreatedAssets: (state) => {
            state.discoveryCreatedAssetIds = [];
            localStorage.removeItem(STORAGE_KEY_ASSETS);
        },
    },

    extraReducers: (builder) => {
        builder
            // Start Scan
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

            // Check Scan Status
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

            // Fetch Scan History
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

            // Delete Scan
            .addCase(deleteScan.fulfilled, (state, action) => {
                state.scanHistory = state.scanHistory.filter(s => s.scan_id !== action.payload);
            })

            // Fetch Pending Hosts
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

            // Check Host Matches
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

            // Approve Host - با tracking
            .addCase(approveHost.pending, (state) => {
                state.loading.approve = true;
            })
            .addCase(approveHost.fulfilled, (state, action) => {
                state.loading.approve = false;

                // 🔥 اگر asset جدید ساخته شد، track کن
                if (action.payload.createdAsset) {
                    if (!state.discoveryCreatedAssetIds.includes(action.payload.createdAsset)) {
                        state.discoveryCreatedAssetIds.push(action.payload.createdAsset);
                        saveDiscoveryAssetsToStorage(state.discoveryCreatedAssetIds);
                    }
                }

                // Remove from pending
                state.pendingHosts = state.pendingHosts.filter(h => h.id !== action.payload.hostId);
                state.selectedHost = null;
                state.matchResults = null;
            })
            .addCase(approveHost.rejected, (state, action) => {
                state.loading.approve = false;
                state.error = action.payload;
            })

            // Reject Host
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

            // Bulk Approve
            .addCase(bulkApproveHosts.pending, (state) => {
                state.loading.approve = true;
            })
            .addCase(bulkApproveHosts.fulfilled, (state) => {
                state.loading.approve = false;
            })
            .addCase(bulkApproveHosts.rejected, (state, action) => {
                state.loading.approve = false;
                state.error = action.payload;
            })

            // Preview Discovery
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

            // Apply Discovery - با tracking
            .addCase(applyDiscoveryWithMode.pending, (state) => {
                state.loading.applyMode = true;
            })
            .addCase(applyDiscoveryWithMode.fulfilled, (state, action) => {
                state.loading.applyMode = false;

                // 🔥 اگر asset جدید ساخته شد، track کن
                if (action.payload.createdAsset) {
                    if (!state.discoveryCreatedAssetIds.includes(action.payload.createdAsset)) {
                        state.discoveryCreatedAssetIds.push(action.payload.createdAsset);
                        saveDiscoveryAssetsToStorage(state.discoveryCreatedAssetIds);
                    }
                }

                // Remove from pending
                state.pendingHosts = state.pendingHosts.filter(h => h.id !== action.payload.hostId);
                state.selectedHost = null;
                state.matchResults = null;
                state.previewData = null;
            })
            .addCase(applyDiscoveryWithMode.rejected, (state, action) => {
                state.loading.applyMode = false;
                state.error = action.payload;
            })

            // Port Management
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

            .addCase(deletePort.pending, (state) => {
                state.loading.ports = true;
            })
            .addCase(deletePort.fulfilled, (state, action) => {
                state.loading.ports = false;
                state.assetPorts = state.assetPorts.filter(p => p.id !== action.payload);
            })
            .addCase(deletePort.rejected, (state, action) => {
                state.loading.ports = false;
                state.error = action.payload;
            });
    },
});

// ============================================
// Exports
// ============================================
export const {
    clearError,
    clearCurrentScan,
    setSelectedHost,
    clearSelectedHost,
    clearMatchResults,
    clearPreviewData,
    stopScanning,
    addDiscoveryCreatedAsset,
    removeDiscoveryCreatedAsset,
    clearDiscoveryCreatedAssets,
} = discoverySlice.actions;

export default discoverySlice.reducer;

// 🔥 NEW: Selectors
export const selectDiscoveryCreatedAssetIds = (state) =>
    state.discovery.discoveryCreatedAssetIds;

export const selectIsDiscoveryCreatedAsset = (state, assetId) =>
    state.discovery.discoveryCreatedAssetIds.includes(assetId);