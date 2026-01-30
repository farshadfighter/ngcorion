/**
 * Hardening Slice - Redux state management for Cisco hardening operations
 *
 * Supports three hardening modes:
 * 1. Fix Single - Fix individual failed checks
 * 2. Fix All - Batch fix selected checks with user-provided parameters
 * 3. Automatic - Apply CIS defaults without user input
 */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from "../config/api.js";

// ============================================
// Initial State
// ============================================
const initialState = {
    // Audit sessions for selection
    auditSessions: [],
    selectedSession: null,

    // Audit results for the selected session
    auditResults: [],
    failedChecks: [],

    // Selection state for Fix All mode
    selectedCheckIds: [],

    // Parameter collection (Fix All mode)
    sessionParameters: null,  // From GET /session/{id}/parameters
    userParameters: {},       // User-entered values

    // Automatic mode preview
    autoHardenPreview: null,

    // Single check state
    selectedCheck: null,
    singlePreview: null,

    // Execution results
    executionResult: null,
    batchResult: null,

    // Hardening history
    hardeningHistory: [],

    // Loading states
    loading: {
        sessions: false,
        results: false,
        parameters: false,
        preview: false,
        execute: false,
        batch: false,
        autoPreview: false,
        autoExecute: false,
        history: false,
    },

    // Error/success messages
    error: null,
    successMessage: null,
};

// ============================================
// Async Thunks
// ============================================

/**
 * Fetch all audit sessions
 */
export const fetchAuditSessions = createAsyncThunk(
    'hardening/fetchAuditSessions',
    async (_, { rejectWithValue }) => {
        try {
            const response = await api.get('/api/audit/sessions');
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to fetch audit sessions');
        }
    }
);

/**
 * Fetch audit results for a session
 */
export const fetchSessionResults = createAsyncThunk(
    'hardening/fetchSessionResults',
    async (sessionId, { rejectWithValue }) => {
        try {
            const response = await api.get(`/api/audit/sessions/${sessionId}/results`);
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to fetch session results');
        }
    }
);

/**
 * Get aggregated parameters for session (Fix All mode)
 */
export const fetchSessionParameters = createAsyncThunk(
    'hardening/fetchSessionParameters',
    async ({ sessionId, checkIds = null }, { rejectWithValue }) => {
        try {
            let url = `/api/hardening/session/${sessionId}/parameters`;
            if (checkIds && checkIds.length > 0) {
                url += `?check_ids=${checkIds.join(',')}`;
            }
            const response = await api.get(url);
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to fetch session parameters');
        }
    }
);

/**
 * Preview single check hardening
 */
export const previewSingleCheck = createAsyncThunk(
    'hardening/previewSingleCheck',
    async ({ auditResultId, parameters = {} }, { rejectWithValue }) => {
        try {
            const response = await api.post('/api/hardening/preview', {
                audit_result_id: auditResultId,
                parameters
            });
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Preview failed');
        }
    }
);

/**
 * Execute single check hardening
 */
export const executeSingleCheck = createAsyncThunk(
    'hardening/executeSingleCheck',
    async ({ actionId, sshCredentials, parameters = {} }, { rejectWithValue }) => {
        try {
            const response = await api.post('/api/hardening/execute', {
                action_id: actionId,
                ssh_username: sshCredentials.username,
                ssh_password: sshCredentials.password,
                ssh_secret: sshCredentials.secret || null,
                parameters,
                skip_backup: false
            });
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Execution failed');
        }
    }
);

/**
 * Get automatic hardening preview
 */
export const fetchAutoHardenPreview = createAsyncThunk(
    'hardening/fetchAutoHardenPreview',
    async (sessionId, { rejectWithValue }) => {
        try {
            const response = await api.get(`/api/hardening/session/${sessionId}/auto-preview`);
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to fetch auto-harden preview');
        }
    }
);

/**
 * Execute automatic hardening with CIS defaults
 */
export const executeAutoHarden = createAsyncThunk(
    'hardening/executeAutoHarden',
    async ({ sessionId, sshCredentials, skipBackup = false }, { rejectWithValue }) => {
        try {
            const response = await api.post('/api/hardening/auto-harden-defaults', {
                audit_session_id: sessionId,
                ssh_username: sshCredentials.username,
                ssh_password: sshCredentials.password,
                ssh_secret: sshCredentials.secret || null,
                confirmed: true,
                skip_backup: skipBackup
            });
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Auto-harden failed');
        }
    }
);

/**
 * Execute batch hardening for selected checks (Fix All mode)
 */
export const executeBatchHarden = createAsyncThunk(
    'hardening/executeBatchHarden',
    async ({ sessionId, checkIds, parameters, sshCredentials, skipBackup = false }, { rejectWithValue }) => {
        try {
            const response = await api.post('/api/hardening/batch-execute', {
                audit_session_id: sessionId,
                check_ids: checkIds,
                parameters,
                ssh_username: sshCredentials.username,
                ssh_password: sshCredentials.password,
                ssh_secret: sshCredentials.secret || null,
                skip_backup: skipBackup
            });
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Batch execution failed');
        }
    }
);

/**
 * Fetch hardening action history
 */
export const fetchHardeningHistory = createAsyncThunk(
    'hardening/fetchHistory',
    async ({ assetId = null, limit = 50, offset = 0 } = {}, { rejectWithValue }) => {
        try {
            const params = new URLSearchParams();
            if (assetId) params.append('asset_id', assetId);
            params.append('limit', limit);
            params.append('offset', offset);

            const response = await api.get(`/api/hardening/actions?${params}`);
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to fetch hardening history');
        }
    }
);

/**
 * Get hardening action details
 */
export const fetchActionDetails = createAsyncThunk(
    'hardening/fetchActionDetails',
    async (actionId, { rejectWithValue }) => {
        try {
            const response = await api.get(`/api/hardening/actions/${actionId}`);
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to fetch action details');
        }
    }
);

// ============================================
// Slice
// ============================================
const hardeningSlice = createSlice({
    name: 'hardening',
    initialState,
    reducers: {
        // Session selection
        setSelectedSession: (state, action) => {
            state.selectedSession = action.payload;
            state.auditResults = [];
            state.failedChecks = [];
            state.selectedCheckIds = [];
            state.sessionParameters = null;
            state.userParameters = {};
            state.autoHardenPreview = null;
        },

        clearSelectedSession: (state) => {
            state.selectedSession = null;
            state.auditResults = [];
            state.failedChecks = [];
            state.selectedCheckIds = [];
            state.sessionParameters = null;
            state.userParameters = {};
        },

        // Check selection for Fix All mode
        toggleCheckSelection: (state, action) => {
            const checkId = action.payload;
            const index = state.selectedCheckIds.indexOf(checkId);
            if (index === -1) {
                state.selectedCheckIds.push(checkId);
            } else {
                state.selectedCheckIds.splice(index, 1);
            }
        },

        selectAllFailedChecks: (state) => {
            state.selectedCheckIds = state.failedChecks.map(c => c.id);
        },

        deselectAllChecks: (state) => {
            state.selectedCheckIds = [];
        },

        // Parameter management
        updateUserParameter: (state, action) => {
            const { paramName, value } = action.payload;
            state.userParameters[paramName] = value;
        },

        clearUserParameters: (state) => {
            state.userParameters = {};
        },

        // Single check selection
        setSelectedCheck: (state, action) => {
            state.selectedCheck = action.payload;
        },

        clearSelectedCheck: (state) => {
            state.selectedCheck = null;
            state.singlePreview = null;
        },

        // Clear results
        clearExecutionResult: (state) => {
            state.executionResult = null;
        },

        clearBatchResult: (state) => {
            state.batchResult = null;
        },

        clearPreview: (state) => {
            state.singlePreview = null;
        },

        clearAutoHardenPreview: (state) => {
            state.autoHardenPreview = null;
        },

        // Messages
        clearError: (state) => {
            state.error = null;
        },

        clearSuccessMessage: (state) => {
            state.successMessage = null;
        },

        setSuccessMessage: (state, action) => {
            state.successMessage = action.payload;
        },
    },

    extraReducers: (builder) => {
        builder
            // Fetch Audit Sessions
            .addCase(fetchAuditSessions.pending, (state) => {
                state.loading.sessions = true;
                state.error = null;
            })
            .addCase(fetchAuditSessions.fulfilled, (state, action) => {
                state.loading.sessions = false;
                state.auditSessions = action.payload;
            })
            .addCase(fetchAuditSessions.rejected, (state, action) => {
                state.loading.sessions = false;
                state.error = action.payload;
            })

            // Fetch Session Results
            .addCase(fetchSessionResults.pending, (state) => {
                state.loading.results = true;
                state.error = null;
            })
            .addCase(fetchSessionResults.fulfilled, (state, action) => {
                state.loading.results = false;
                state.auditResults = action.payload;
                // Filter to failed checks only
                state.failedChecks = action.payload.filter(r => r.status === 'FAIL');
            })
            .addCase(fetchSessionResults.rejected, (state, action) => {
                state.loading.results = false;
                state.error = action.payload;
            })

            // Fetch Session Parameters
            .addCase(fetchSessionParameters.pending, (state) => {
                state.loading.parameters = true;
                state.error = null;
            })
            .addCase(fetchSessionParameters.fulfilled, (state, action) => {
                state.loading.parameters = false;
                state.sessionParameters = action.payload;
            })
            .addCase(fetchSessionParameters.rejected, (state, action) => {
                state.loading.parameters = false;
                state.error = action.payload;
            })

            // Preview Single Check
            .addCase(previewSingleCheck.pending, (state) => {
                state.loading.preview = true;
                state.error = null;
            })
            .addCase(previewSingleCheck.fulfilled, (state, action) => {
                state.loading.preview = false;
                state.singlePreview = action.payload;
            })
            .addCase(previewSingleCheck.rejected, (state, action) => {
                state.loading.preview = false;
                state.error = action.payload;
            })

            // Execute Single Check
            .addCase(executeSingleCheck.pending, (state) => {
                state.loading.execute = true;
                state.error = null;
            })
            .addCase(executeSingleCheck.fulfilled, (state, action) => {
                state.loading.execute = false;
                state.executionResult = action.payload;
                state.successMessage = action.payload.verification_passed
                    ? 'Check fixed and verified successfully!'
                    : 'Fix applied but verification failed.';
            })
            .addCase(executeSingleCheck.rejected, (state, action) => {
                state.loading.execute = false;
                state.error = action.payload;
            })

            // Fetch Auto-Harden Preview
            .addCase(fetchAutoHardenPreview.pending, (state) => {
                state.loading.autoPreview = true;
                state.error = null;
            })
            .addCase(fetchAutoHardenPreview.fulfilled, (state, action) => {
                state.loading.autoPreview = false;
                state.autoHardenPreview = action.payload;
            })
            .addCase(fetchAutoHardenPreview.rejected, (state, action) => {
                state.loading.autoPreview = false;
                state.error = action.payload;
            })

            // Execute Auto-Harden
            .addCase(executeAutoHarden.pending, (state) => {
                state.loading.autoExecute = true;
                state.error = null;
            })
            .addCase(executeAutoHarden.fulfilled, (state, action) => {
                state.loading.autoExecute = false;
                state.batchResult = action.payload;
                state.successMessage = `Auto-hardening complete: ${action.payload.fixed_count} fixed, ${action.payload.skipped_count} skipped.`;
            })
            .addCase(executeAutoHarden.rejected, (state, action) => {
                state.loading.autoExecute = false;
                state.error = action.payload;
            })

            // Execute Batch Harden
            .addCase(executeBatchHarden.pending, (state) => {
                state.loading.batch = true;
                state.error = null;
            })
            .addCase(executeBatchHarden.fulfilled, (state, action) => {
                state.loading.batch = false;
                state.batchResult = action.payload;
                state.successMessage = `Batch hardening complete: ${action.payload.fixed_count} fixed, ${action.payload.failed_count} failed.`;
            })
            .addCase(executeBatchHarden.rejected, (state, action) => {
                state.loading.batch = false;
                state.error = action.payload;
            })

            // Fetch Hardening History
            .addCase(fetchHardeningHistory.pending, (state) => {
                state.loading.history = true;
                state.error = null;
            })
            .addCase(fetchHardeningHistory.fulfilled, (state, action) => {
                state.loading.history = false;
                state.hardeningHistory = action.payload;
            })
            .addCase(fetchHardeningHistory.rejected, (state, action) => {
                state.loading.history = false;
                state.error = action.payload;
            });
    },
});

// ============================================
// Exports
// ============================================
export const {
    setSelectedSession,
    clearSelectedSession,
    toggleCheckSelection,
    selectAllFailedChecks,
    deselectAllChecks,
    updateUserParameter,
    clearUserParameters,
    setSelectedCheck,
    clearSelectedCheck,
    clearExecutionResult,
    clearBatchResult,
    clearPreview,
    clearAutoHardenPreview,
    clearError,
    clearSuccessMessage,
    setSuccessMessage,
} = hardeningSlice.actions;

export default hardeningSlice.reducer;

// ============================================
// Selectors
// ============================================
export const selectAuditSessions = (state) => state.hardening.auditSessions;
export const selectSelectedSession = (state) => state.hardening.selectedSession;
export const selectAuditResults = (state) => state.hardening.auditResults;
export const selectFailedChecks = (state) => state.hardening.failedChecks;
export const selectSelectedCheckIds = (state) => state.hardening.selectedCheckIds;
export const selectSessionParameters = (state) => state.hardening.sessionParameters;
export const selectUserParameters = (state) => state.hardening.userParameters;
export const selectAutoHardenPreview = (state) => state.hardening.autoHardenPreview;
export const selectSinglePreview = (state) => state.hardening.singlePreview;
export const selectExecutionResult = (state) => state.hardening.executionResult;
export const selectBatchResult = (state) => state.hardening.batchResult;
export const selectHardeningHistory = (state) => state.hardening.hardeningHistory;
export const selectLoading = (state) => state.hardening.loading;
export const selectError = (state) => state.hardening.error;
export const selectSuccessMessage = (state) => state.hardening.successMessage;

// Computed selectors
export const selectSelectedChecksCount = (state) => state.hardening.selectedCheckIds.length;
export const selectFailedChecksCount = (state) => state.hardening.failedChecks.length;
export const selectAllFailedSelected = (state) =>
    state.hardening.failedChecks.length > 0 &&
    state.hardening.selectedCheckIds.length === state.hardening.failedChecks.length;
