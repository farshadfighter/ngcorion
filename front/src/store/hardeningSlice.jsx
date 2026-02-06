/**
 * Hardening Slice - Redux state management for multi-device hardening operations
 *
 * Supports multiple device types:
 * - Cisco IOS routers/switches
 * - FortiGate firewalls
 * - (Future) Linux, Windows, Apache
 *
 * Supports three hardening modes:
 * 1. Fix Single - Fix individual failed checks
 * 2. Fix All - Batch fix selected checks with user-provided parameters
 * 3. Automatic - Apply CIS defaults without user input
 */

import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from "../config/api.js";

// ============================================
// Device Type API Path Helper
// ============================================

/**
 * Get the API base path for a device type
 * @param {string} deviceType - Device type (cisco, fortinet, linux, windows, apache)
 * @param {string} endpoint - API endpoint (e.g., '/preview', '/execute')
 * @returns {string} Full API path
 */
const getHardeningApiPath = (deviceType, endpoint) => {
    const prefixes = {
        cisco: '/api/hardening',
        fortinet: '/api/hardening/fortinet',
        linux: '/api/hardening/linux',      // Future
        windows: '/api/hardening/windows',  // Future
        apache: '/api/hardening/apache',    // Future
    };
    return `${prefixes[deviceType] || prefixes.cisco}${endpoint}`;
};

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

    // ============================================
    // Schema-driven Wizard State (NEW)
    // ============================================
    formSchema: null,           // Control definitions from backend
    sharedFields: [],           // Shared field definitions
    controlStates: {},          // { control_id: { state: "APPLY", inputs: {...} } }
    sharedFieldValues: {},      // Values for shared fields
    validationErrors: {},       // { control_id: { field_id: message } }
    hardeningMode: null,        // 'post_audit' | 'full'
    wizardExecutionResult: null, // Result from schema-driven execution

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
        // Schema wizard loading states
        form: false,
        validate: false,
        wizardExecute: false,
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
    async ({ sessionId, checkIds = null, deviceType = 'cisco' }, { rejectWithValue }) => {
        try {
            const basePath = getHardeningApiPath(deviceType, `/session/${sessionId}/parameters`);
            let url = basePath;
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
    async ({ auditResultId, parameters = {}, deviceType = 'cisco' }, { rejectWithValue }) => {
        try {
            const url = getHardeningApiPath(deviceType, '/preview');
            const response = await api.post(url, {
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
    async ({ actionId, sshCredentials, parameters = {}, deviceType = 'cisco', vdom = null }, { rejectWithValue }) => {
        try {
            const url = getHardeningApiPath(deviceType, '/execute');
            const payload = {
                action_id: actionId,
                ssh_username: sshCredentials.username,
                ssh_password: sshCredentials.password,
                ssh_secret: sshCredentials.secret || null,
                parameters,
                skip_backup: false
            };
            // Add VDOM for FortiGate devices
            if (deviceType === 'fortinet' && vdom) {
                payload.vdom = vdom;
            }
            const response = await api.post(url, payload);
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
    async ({ sessionId, deviceType = 'cisco' }, { rejectWithValue }) => {
        try {
            const url = getHardeningApiPath(deviceType, `/session/${sessionId}/auto-preview`);
            const response = await api.get(url);
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
    async ({ sessionId, sshCredentials, skipBackup = false, deviceType = 'cisco', vdom = null }, { rejectWithValue }) => {
        try {
            const url = getHardeningApiPath(deviceType, '/auto-harden-defaults');
            const payload = {
                audit_session_id: sessionId,
                ssh_username: sshCredentials.username,
                ssh_password: sshCredentials.password,
                ssh_secret: sshCredentials.secret || null,
                confirmed: true,
                skip_backup: skipBackup
            };
            // Add VDOM for FortiGate devices
            if (deviceType === 'fortinet' && vdom) {
                payload.vdom = vdom;
            }
            const response = await api.post(url, payload);
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
    async ({ sessionId, checkIds, parameters, sshCredentials, skipBackup = false, deviceType = 'cisco', vdom = null }, { rejectWithValue }) => {
        try {
            const url = getHardeningApiPath(deviceType, '/batch-execute');
            const payload = {
                audit_session_id: sessionId,
                check_ids: checkIds,
                parameters,
                ssh_username: sshCredentials.username,
                ssh_password: sshCredentials.password,
                ssh_secret: sshCredentials.secret || null,
                skip_backup: skipBackup
            };
            // Add VDOM for FortiGate devices
            if (deviceType === 'fortinet' && vdom) {
                payload.vdom = vdom;
            }
            const response = await api.post(url, payload);
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
    async ({ assetId = null, limit = 50, offset = 0, deviceType = 'cisco' } = {}, { rejectWithValue }) => {
        try {
            const params = new URLSearchParams();
            if (assetId) params.append('asset_id', assetId);
            params.append('limit', limit);
            params.append('offset', offset);

            const url = getHardeningApiPath(deviceType, `/actions?${params}`);
            const response = await api.get(url);
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
    async ({ actionId, deviceType = 'cisco' }, { rejectWithValue }) => {
        try {
            const url = getHardeningApiPath(deviceType, `/actions/${actionId}`);
            const response = await api.get(url);
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to fetch action details');
        }
    }
);

// ============================================
// Schema-driven Wizard Thunks (NEW)
// ============================================

/**
 * Fetch hardening form schema for a device type
 */
export const fetchHardeningForm = createAsyncThunk(
    'hardening/fetchHardeningForm',
    async ({ deviceType, mode, sessionId = null, checkNumbers = null }, { rejectWithValue }) => {
        try {
            const response = await api.post('/api/hardening/schema/form', {
                device_type: deviceType,
                mode,
                session_id: sessionId,
                check_numbers: checkNumbers,
            });
            return { ...response.data, mode };
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Failed to fetch hardening form');
        }
    }
);

/**
 * Validate hardening inputs against schema
 */
export const validateHardeningInputs = createAsyncThunk(
    'hardening/validateHardeningInputs',
    async ({ deviceType, controlStates, sharedFields }, { rejectWithValue }) => {
        try {
            const response = await api.post('/api/hardening/schema/validate', {
                device_type: deviceType,
                control_states: controlStates,
                shared_fields: sharedFields,
            });
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Validation failed');
        }
    }
);

/**
 * Execute hardening controls via schema-driven API
 */
export const executeHardeningControls = createAsyncThunk(
    'hardening/executeHardeningControls',
    async ({
        deviceType,
        deviceIp,
        sessionId,
        controlStates,
        sharedFields,
        sshCredentials,
        skipBackup = false
    }, { rejectWithValue }) => {
        try {
            const response = await api.post('/api/hardening/schema/execute', {
                device_type: deviceType,
                device_ip: deviceIp,
                session_id: sessionId,
                control_states: controlStates,
                shared_fields: sharedFields,
                ssh_credentials: {
                    username: sshCredentials.username,
                    password: sshCredentials.password,
                    secret: sshCredentials.secret || null,
                },
                skip_backup: skipBackup,
            });
            return response.data;
        } catch (error) {
            return rejectWithValue(error.response?.data?.detail || 'Execution failed');
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

        // ============================================
        // Schema-driven Wizard Reducers (NEW)
        // ============================================

        // Set control state (SKIP/AUDIT/APPLY)
        setControlState: (state, action) => {
            const { controlId, state: newState } = action.payload;
            if (!state.controlStates[controlId]) {
                state.controlStates[controlId] = { state: 'AUDIT', inputs: {} };
            }
            state.controlStates[controlId].state = newState;
            // Clear validation errors for this control when state changes
            delete state.validationErrors[controlId];
        },

        // Set control input value
        setControlInput: (state, action) => {
            const { controlId, inputName, value } = action.payload;
            if (!state.controlStates[controlId]) {
                state.controlStates[controlId] = { state: 'AUDIT', inputs: {} };
            }
            state.controlStates[controlId].inputs[inputName] = value;
        },

        // Set shared field value
        setSharedFieldValue: (state, action) => {
            const { fieldName, value } = action.payload;
            state.sharedFieldValues[fieldName] = value;
        },

        // Clear all wizard state
        clearWizardState: (state) => {
            state.formSchema = null;
            state.sharedFields = [];
            state.controlStates = {};
            state.sharedFieldValues = {};
            state.validationErrors = {};
            state.hardeningMode = null;
            state.wizardExecutionResult = null;
        },

        // Clear validation errors
        clearValidationErrors: (state) => {
            state.validationErrors = {};
        },

        // Set validation errors
        setValidationErrors: (state, action) => {
            state.validationErrors = action.payload;
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
            })

            // ============================================
            // Schema-driven Wizard Extra Reducers (NEW)
            // ============================================

            // Fetch Hardening Form
            .addCase(fetchHardeningForm.pending, (state) => {
                state.loading.form = true;
                state.error = null;
            })
            .addCase(fetchHardeningForm.fulfilled, (state, action) => {
                state.loading.form = false;
                state.formSchema = action.payload;
                state.sharedFields = action.payload.shared_fields || [];
                state.hardeningMode = action.payload.mode;

                // Initialize control states with default state
                const defaultState = action.payload.defaults?.state || 'AUDIT';
                state.controlStates = {};
                action.payload.controls.forEach(control => {
                    state.controlStates[control.control_id] = {
                        state: defaultState,
                        inputs: {},
                    };
                    // Set default values for inputs
                    control.inputs.forEach(input => {
                        if (input.default !== undefined && input.default !== null) {
                            state.controlStates[control.control_id].inputs[input.name] = input.default;
                        }
                    });
                });

                // Initialize shared field values with defaults
                state.sharedFieldValues = {};
                (action.payload.shared_fields || []).forEach(field => {
                    if (field.default !== undefined && field.default !== null) {
                        state.sharedFieldValues[field.name] = field.default;
                    }
                });
            })
            .addCase(fetchHardeningForm.rejected, (state, action) => {
                state.loading.form = false;
                state.error = action.payload;
            })

            // Validate Hardening Inputs
            .addCase(validateHardeningInputs.pending, (state) => {
                state.loading.validate = true;
                state.validationErrors = {};
            })
            .addCase(validateHardeningInputs.fulfilled, (state, action) => {
                state.loading.validate = false;
                if (!action.payload.valid) {
                    // Convert errors to field-keyed format for each control
                    const errors = {};
                    Object.entries(action.payload.errors || {}).forEach(([controlId, controlErrors]) => {
                        errors[controlId] = {};
                        controlErrors.forEach(err => {
                            errors[controlId][err.field] = err.message;
                        });
                    });
                    state.validationErrors = errors;
                } else {
                    state.validationErrors = {};
                }
            })
            .addCase(validateHardeningInputs.rejected, (state, action) => {
                state.loading.validate = false;
                state.error = action.payload;
            })

            // Execute Hardening Controls
            .addCase(executeHardeningControls.pending, (state) => {
                state.loading.wizardExecute = true;
                state.error = null;
            })
            .addCase(executeHardeningControls.fulfilled, (state, action) => {
                state.loading.wizardExecute = false;
                state.wizardExecutionResult = action.payload;
                state.successMessage = `Hardening complete: ${action.payload.applied_count} applied, ${action.payload.skipped_count} skipped.`;
            })
            .addCase(executeHardeningControls.rejected, (state, action) => {
                state.loading.wizardExecute = false;
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
    // Schema-driven wizard actions
    setControlState,
    setControlInput,
    setSharedFieldValue,
    clearWizardState,
    clearValidationErrors,
    setValidationErrors,
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

// Device type selector - extracts device type from selected session
export const selectDeviceType = (state) => {
    const session = state.hardening.selectedSession;
    if (!session) return 'cisco';
    // Check for device_type field first, then fallback based on session properties
    if (session.device_type) return session.device_type;
    // Infer from session type or default to cisco
    if (session.session_type === 'fortinet' || session.target_type === 'fortinet') return 'fortinet';
    return 'cisco';
};

// Computed selectors
export const selectSelectedChecksCount = (state) => state.hardening.selectedCheckIds.length;
export const selectFailedChecksCount = (state) => state.hardening.failedChecks.length;
export const selectAllFailedSelected = (state) =>
    state.hardening.failedChecks.length > 0 &&
    state.hardening.selectedCheckIds.length === state.hardening.failedChecks.length;

// Schema-driven wizard selectors
export const selectFormSchema = (state) => state.hardening.formSchema;
export const selectSharedFields = (state) => state.hardening.sharedFields;
export const selectControlStates = (state) => state.hardening.controlStates;
export const selectSharedFieldValues = (state) => state.hardening.sharedFieldValues;
export const selectValidationErrors = (state) => state.hardening.validationErrors;
export const selectHardeningMode = (state) => state.hardening.hardeningMode;
export const selectWizardExecutionResult = (state) => state.hardening.wizardExecutionResult;
export const selectWizardLoading = (state) => ({
    form: state.hardening.loading.form,
    validate: state.hardening.loading.validate,
    execute: state.hardening.loading.wizardExecute,
});
export const selectWizardError = (state) => state.hardening.error;
