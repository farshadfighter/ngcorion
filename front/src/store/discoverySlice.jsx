/**
 * Discovery Slice - با Tracking برای Assets ساخته‌شده از Discovery
 */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from "../config/api.js";

const STORAGE_KEY_SCAN = 'discovery_currentScan';
const STORAGE_KEY_ASSETS = 'discoveryCreatedAssetIds';

const loadScanFromStorage = () => {
    try {
        const saved = localStorage.getItem(STORAGE_KEY_SCAN);
        if (saved) {
            const parsed = JSON.parse(saved);
            // pending هم ذخیره میشه
            if (parsed && (parsed.status === 'running' || parsed.status === 'pending')) {
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
        // pending و running هر دو ذخیره میشن
        if (scan && (scan.status === 'running' || scan.status === 'pending')) {
            localStorage.setItem(STORAGE_KEY_SCAN, JSON.stringify(scan));
        } else {
            localStorage.removeItem(STORAGE_KEY_SCAN);
        }
    } catch (e) {
        console.warn('Failed to save scan to localStorage:', e);
    }
};

const clearScanFromStorage = () => {
    try {
        localStorage.removeItem(STORAGE_KEY_SCAN);
    } catch (e) {
        console.warn('Failed to clear scan from localStorage:', e);
    }
};

const loadDiscoveryAssetsFromStorage = () => {
    try {
        const saved = localStorage.getItem(STORAGE_KEY_ASSETS);
        return saved ? JSON.parse(saved) : [];
    } catch (e) {
        console.warn('Failed to load discovery assets from localStorage:', e);
        return [];
    }
};

const saveDiscoveryAssetsToStorage = (assetIds) => {
    try {
        localStorage.setItem(STORAGE_KEY_ASSETS, JSON.stringify(assetIds));
    } catch (e) {
        console.warn('Failed to save discovery assets to localStorage:', e);
    }
};

const initialState = {
    currentScan: loadScanFromStorage(),
    scanHistory: [],
    scanLogs: [],
    pendingHosts: [],
    selectedHost: null,
    matchResults: null,
    previewData: null,
    assetPorts: [],
    discoveryCreatedAssetIds: loadDiscoveryAssetsFromStorage(),
    loading: {
        scan: false,
        history: false,
        pending: false,
        approve: false,
        matches: false,
        preview: false,
        applyMode: false,
        ports: false,
        logs: false,
    },
    error: null,
};

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

export const approveHost = createAsyncThunk(
    'discovery/approveHost',
    async ({ hostId, action, assetId, assetData }, { rejectWithValue }) => {
        try {
            const requestBody = { action };
            if (action === 'merge_with_existing' && assetId) requestBody.asset_id = assetId;
            if (action === 'create_new' && assetData) requestBody.asset_data = assetData;
            const response = await api.post(`/api/discovery/hosts/${hostId}/approve`, requestBody);
            return { ...response.data, hostId, createdAsset: action === 'create_new' ? response.data.asset_id : null };
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to approve host');
        }
    }
);

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

export const previewDiscoveryApplication = createAsyncThunk(
    'discovery/previewApplication',
    async ({ hostId, assetId }, { rejectWithValue }) => {
        try {
            let url = `/api/discovery/hosts/${hostId}/preview`;
            if (assetId) url += `?asset_id=${assetId}`;
            const response = await api.get(url);
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to preview application');
        }
    }
);

export const applyDiscoveryWithMode = createAsyncThunk(
    'discovery/applyWithMode',
    async ({ hostId, mode, assetId, assetName, assetTypeId, locationId, ownerId }, { rejectWithValue }) => {
        try {
            const requestBody = { mode, host_id: hostId };
            if (mode === 'create_new') {
                requestBody.asset_name = assetName;
                requestBody.asset_type_id = assetTypeId;
                if (locationId) requestBody.location_id = locationId;
                if (ownerId) requestBody.owner_id = ownerId;
            } else {
                requestBody.asset_id = assetId;
            }
            const response = await api.post(`/api/discovery/hosts/${hostId}/apply`, requestBody);
            return { ...response.data, hostId, createdAsset: mode === 'create_new' ? response.data.asset_id : null };
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to apply discovery');
        }
    }
);

export const bulkApproveHosts = createAsyncThunk(
    'discovery/bulkApprove',
    async ({ hostIds, defaultAssetTypeId, defaultLocationId, defaultOwnerId }, { rejectWithValue }) => {
        try {
            const requestBody = { host_ids: hostIds, default_asset_type_id: defaultAssetTypeId };
            if (defaultLocationId) requestBody.default_location_id = defaultLocationId;
            if (defaultOwnerId) requestBody.default_owner_id = defaultOwnerId;
            const response = await api.post('/api/discovery/bulk-approve', requestBody);
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to bulk approve');
        }
    }
);

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

export const fetchScanLogs = createAsyncThunk(
    'discovery/fetchScanLogs',
    async (scanId, { rejectWithValue }) => {
        try {
            const response = await api.get(`/api/discovery-logs/scan/${scanId}?limit=100`);
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to fetch scan logs');
        }
    }
);

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

const discoverySlice = createSlice({
    name: 'discovery',
    initialState,
    reducers: {
        clearError: (state) => { state.error = null; },
        clearCurrentScan: (state) => { state.currentScan = null; clearScanFromStorage(); },
        setSelectedHost: (state, action) => { state.selectedHost = action.payload; },
        clearSelectedHost: (state) => { state.selectedHost = null; state.matchResults = null; },
        clearMatchResults: (state) => { state.matchResults = null; },
        clearPreviewData: (state) => { state.previewData = null; },
        stopScanning: (state) => {
            state.loading.scan = false;
            if (state.currentScan) state.currentScan.status = 'stopped';
            clearScanFromStorage();
        },
        addDiscoveryCreatedAsset: (state, action) => {
            const assetId = action.payload;
            if (!state.discoveryCreatedAssetIds.includes(assetId)) {
                state.discoveryCreatedAssetIds.push(assetId);
                saveDiscoveryAssetsToStorage(state.discoveryCreatedAssetIds);
            }
        },
        removeDiscoveryCreatedAsset: (state, action) => {
            state.discoveryCreatedAssetIds = state.discoveryCreatedAssetIds.filter(id => id !== action.payload);
            saveDiscoveryAssetsToStorage(state.discoveryCreatedAssetIds);
        },
        clearDiscoveryCreatedAssets: (state) => {
            state.discoveryCreatedAssetIds = [];
            localStorage.removeItem(STORAGE_KEY_ASSETS);
        },
        clearScanLogs: (state) => { state.scanLogs = []; },
    },

    extraReducers: (builder) => {
        builder
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

            // FIX: pending و running هر دو ذخیره میشن، completed/failed/cancelled پاک میکنن
            .addCase(checkScanStatus.fulfilled, (state, action) => {
                state.currentScan = action.payload;
                if (
                    action.payload.status === 'completed' ||
                    action.payload.status === 'failed' ||
                    action.payload.status === 'cancelled'
                ) {
                    state.loading.scan = false;
                    clearScanFromStorage();
                    // آپدیت scanHistory تا انیمیشن بلافاصله بره
                    state.scanHistory = state.scanHistory.map(s =>
                        s.scan_id === action.payload.scan_id ? action.payload : s
                    );
                } else {
                    // pending یا running
                    saveScanToStorage(action.payload);
                }
            })
            .addCase(checkScanStatus.rejected, (state, action) => {
                state.loading.scan = false;
                state.error = action.payload;
                clearScanFromStorage();
            })

            .addCase(fetchScanHistory.pending, (state) => { state.loading.history = true; })
            .addCase(fetchScanHistory.fulfilled, (state, action) => {
                state.loading.history = false;
                state.scanHistory = action.payload;
            })
            .addCase(fetchScanHistory.rejected, (state, action) => {
                state.loading.history = false;
                state.error = action.payload;
            })

            .addCase(deleteScan.fulfilled, (state, action) => {
                state.scanHistory = state.scanHistory.filter(s => s.scan_id !== action.payload);
            })

            .addCase(fetchPendingHosts.pending, (state) => { state.loading.pending = true; })
            .addCase(fetchPendingHosts.fulfilled, (state, action) => {
                state.loading.pending = false;
                state.pendingHosts = action.payload.pending || [];
            })
            .addCase(fetchPendingHosts.rejected, (state, action) => {
                state.loading.pending = false;
                state.error = action.payload;
            })

            .addCase(checkHostMatches.pending, (state) => { state.loading.matches = true; })
            .addCase(checkHostMatches.fulfilled, (state, action) => {
                state.loading.matches = false;
                state.matchResults = action.payload;
            })
            .addCase(checkHostMatches.rejected, (state, action) => {
                state.loading.matches = false;
                state.error = action.payload;
            })

            .addCase(approveHost.pending, (state) => { state.loading.approve = true; })
            .addCase(approveHost.fulfilled, (state, action) => {
                state.loading.approve = false;
                if (action.payload.createdAsset) {
                    if (!state.discoveryCreatedAssetIds.includes(action.payload.createdAsset)) {
                        state.discoveryCreatedAssetIds.push(action.payload.createdAsset);
                        saveDiscoveryAssetsToStorage(state.discoveryCreatedAssetIds);
                    }
                }
                state.pendingHosts = state.pendingHosts.filter(h => h.id !== action.payload.hostId);
                state.selectedHost = null;
                state.matchResults = null;
            })
            .addCase(approveHost.rejected, (state, action) => {
                state.loading.approve = false;
                state.error = action.payload;
            })

            .addCase(rejectHost.pending, (state) => { state.loading.approve = true; })
            .addCase(rejectHost.fulfilled, (state, action) => {
                state.loading.approve = false;
                state.pendingHosts = state.pendingHosts.filter(h => h.id !== action.payload.hostId);
            })
            .addCase(rejectHost.rejected, (state, action) => {
                state.loading.approve = false;
                state.error = action.payload;
            })

            .addCase(bulkApproveHosts.pending, (state) => { state.loading.approve = true; })
            .addCase(bulkApproveHosts.fulfilled, (state) => { state.loading.approve = false; })
            .addCase(bulkApproveHosts.rejected, (state, action) => {
                state.loading.approve = false;
                state.error = action.payload;
            })

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

            .addCase(applyDiscoveryWithMode.pending, (state) => { state.loading.applyMode = true; })
            .addCase(applyDiscoveryWithMode.fulfilled, (state, action) => {
                state.loading.applyMode = false;
                if (action.payload.createdAsset) {
                    if (!state.discoveryCreatedAssetIds.includes(action.payload.createdAsset)) {
                        state.discoveryCreatedAssetIds.push(action.payload.createdAsset);
                        saveDiscoveryAssetsToStorage(state.discoveryCreatedAssetIds);
                    }
                }
                state.pendingHosts = state.pendingHosts.filter(h => h.id !== action.payload.hostId);
                state.selectedHost = null;
                state.matchResults = null;
                state.previewData = null;
            })
            .addCase(applyDiscoveryWithMode.rejected, (state, action) => {
                state.loading.applyMode = false;
                state.error = action.payload;
            })

            .addCase(addPortsToAsset.pending, (state) => { state.loading.ports = true; })
            .addCase(addPortsToAsset.fulfilled, (state) => { state.loading.ports = false; })
            .addCase(addPortsToAsset.rejected, (state, action) => {
                state.loading.ports = false;
                state.error = action.payload;
            })

            .addCase(overwriteAssetPorts.pending, (state) => { state.loading.ports = true; })
            .addCase(overwriteAssetPorts.fulfilled, (state) => { state.loading.ports = false; })
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

            .addCase(deletePort.pending, (state) => { state.loading.ports = true; })
            .addCase(deletePort.fulfilled, (state, action) => {
                state.loading.ports = false;
                state.assetPorts = state.assetPorts.filter(p => p.id !== action.payload);
            })
            .addCase(deletePort.rejected, (state, action) => {
                state.loading.ports = false;
                state.error = action.payload;
            })

            .addCase(fetchScanLogs.pending, (state) => { state.loading.logs = true; })
            .addCase(fetchScanLogs.fulfilled, (state, action) => {
                state.loading.logs = false;
                state.scanLogs = [...action.payload].reverse();
            })
            .addCase(fetchScanLogs.rejected, (state) => { state.loading.logs = false; });
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
    addDiscoveryCreatedAsset,
    removeDiscoveryCreatedAsset,
    clearDiscoveryCreatedAssets,
    clearScanLogs,
} = discoverySlice.actions;

export default discoverySlice.reducer;

export const selectDiscoveryCreatedAssetIds = (state) => state.discovery.discoveryCreatedAssetIds;
export const selectIsDiscoveryCreatedAsset = (state, assetId) => state.discovery.discoveryCreatedAssetIds.includes(assetId);