import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// ===========================
// HELPER FUNCTIONS
// ===========================

/**
 * Maps device type to API path
 * Linux variants (linux-ubuntu-22.04, linux-ubuntu-24.04, linux-rocky-8) → 'linux'
 * Others (cisco, fortinet, apache) → same as device type
 */
const getDeviceApiPath = (deviceType) => {
    if (!deviceType) return 'cisco'; // Default fallback
    if (deviceType.startsWith('linux-')) return 'linux';
    return deviceType; // cisco, fortinet, apache
};

/**
 * Get human-readable device name
 */
export const getDeviceName = (deviceType) => {
    const names = {
        'cisco': 'Cisco Router/Switch',
        'fortinet': 'FortiGate Firewall',
        'linux-ubuntu-22.04': 'Linux - Ubuntu 22.04 LTS',
        'linux-ubuntu-24.04': 'Linux - Ubuntu 24.04 LTS',
        'linux-rocky-8': 'Linux - Rocky Linux 8',
        'apache': 'Apache Web Server'
    };
    return names[deviceType] || deviceType;
};

// ===========================
// ASYNC THUNKS
// ===========================

/**
 * Fix All Flow - Step 1: Execute audit with device type
 * POST /api/audit/{device}/execute
 */
export const executeAuditWithDevice = createAsyncThunk(
    "hardening/executeAudit",
    async ({ deviceType, assetId, credentials }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const endpoint = `/api/audit/${apiPath}/execute`;

            const payload = {
                asset_id: assetId,
                ssh_username: credentials.ssh_username,
                ssh_password: credentials.ssh_password,
            };

            // Add device-specific fields
            if (deviceType === 'cisco' && credentials.ssh_secret) {
                payload.ssh_secret = credentials.ssh_secret;
            }
            if (deviceType === 'fortinet' && credentials.vdom) {
                payload.vdom = credentials.vdom;
            }
            if ((deviceType.startsWith('linux-') || deviceType === 'apache') && credentials.sudo_password) {
                payload.sudo_password = credentials.sudo_password;
            }

            const response = await api.post(endpoint, payload);
            return { ...response.data, device_type: deviceType }; // Include device type in response
        } catch (error) {
            return rejectWithValue(
                error.response?.data?.detail || "Failed to start audit"
            );
        }
    }
);

/**
 * Fix All Flow - Step 2: Check session status (polling)
 * GET /api/audit/{device}/sessions/{id}
 */
export const checkHardeningSessionStatus = createAsyncThunk(
    "hardening/checkSessionStatus",
    async ({ sessionId, deviceType }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const response = await api.get(`/api/audit/${apiPath}/sessions/${sessionId}`);
            return response.data;
        } catch (error) {
            return rejectWithValue(
                error.response?.data?.detail || "Failed to check session status"
            );
        }
    }
);

/**
 * Fix Unsuccessful Flow - Fetch audit sessions by device type
 * GET /api/audit/{device}/sessions
 */
export const fetchAuditSessions = createAsyncThunk(
    "hardening/fetchAuditSessions",
    async (deviceType, { rejectWithValue }) => {
        try {
            // Fetch sessions from all device types and merge
            const deviceTypes = ['cisco', 'fortinet', 'linux', 'apache'];
            const allSessions = [];

            for (const device of deviceTypes) {
                try {
                    const response = await api.get(`/api/audit/${device}/sessions`);
                    if (response.data && Array.isArray(response.data)) {
                        allSessions.push(...response.data);
                    }
                } catch (err) {
                    console.warn(`Failed to fetch ${device} sessions:`, err.message);
                    // Continue with other devices
                }
            }

            return allSessions;
        } catch (error) {
            return rejectWithValue(
                error.response?.data?.detail || "Failed to fetch audit sessions"
            );
        }
    }
);

/**
 * Fix Unsuccessful Flow - Fetch audit results
 * GET /api/audit/{device}/sessions/{id}/results
 */
export const fetchAuditResults = createAsyncThunk(
    "hardening/fetchAuditResults",
    async ({ sessionId, deviceType }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const response = await api.get(`/api/audit/${apiPath}/sessions/${sessionId}/results`);
            return response.data;
        } catch (error) {
            return rejectWithValue(
                error.response?.data?.detail || "Failed to fetch audit results"
            );
        }
    }
);

/**
 * Fix Single - Preview hardening for a single check
 * POST /api/hardening/{device}/preview
 */
export const previewHardenCheck = createAsyncThunk(
    "hardening/previewCheck",
    async ({ auditResultId, deviceType, parameters }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const res = await api.post(`/api/hardening/${apiPath}/preview`, {
                audit_result_id: auditResultId,
                parameters: parameters || {}
            });
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to preview hardening"
            );
        }
    }
);

/**
 * Fix Single - Execute hardening for a single check
 * POST /api/hardening/{device}/execute (Cisco/Fortinet)
 * POST /api/hardening/{device}/execute-single (Linux/Apache)
 */
export const executeHardenCheck = createAsyncThunk(
    "hardening/executeCheck",
    async ({ actionId, deviceType, credentials, parameters }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);

            // Linux and Apache use execute-single endpoint
            const endpoint = (deviceType.startsWith('linux-') || deviceType === 'apache')
                ? `/api/hardening/${apiPath}/execute-single`
                : `/api/hardening/${apiPath}/execute`;

            const payload = {
                action_id: actionId,
                ssh_username: credentials.ssh_username,
                ssh_password: credentials.ssh_password,
                parameters: parameters || {},
                skip_backup: false
            };

            // Add device-specific credentials
            if (deviceType === 'cisco' && credentials.ssh_secret) {
                payload.ssh_secret = credentials.ssh_secret;
            }
            if (deviceType === 'fortinet' && credentials.vdom) {
                payload.vdom = credentials.vdom;
            }
            if ((deviceType.startsWith('linux-') || deviceType === 'apache') && credentials.sudo_password) {
                payload.sudo_password = credentials.sudo_password;
            }

            const res = await api.post(endpoint, payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to execute hardening"
            );
        }
    }
);

/**
 * Harden All - Get required parameters
 * GET /api/hardening/{device}/session/{id}/parameters
 */
export const fetchRequiredParameters = createAsyncThunk(
    "hardening/fetchParameters",
    async ({ sessionId, deviceType }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const response = await api.get(`/api/hardening/${apiPath}/session/${sessionId}/parameters`);
            return response.data;
        } catch (error) {
            return rejectWithValue(
                error.response?.data?.detail || "Failed to fetch parameters"
            );
        }
    }
);

/**
 * Harden All - Auto harden with defaults
 * POST /api/hardening/{device}/auto-harden-defaults
 */
export const autoHardenWithDefaults = createAsyncThunk(
    "hardening/autoHardenDefaults",
    async ({ sessionId, deviceType, credentials }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);

            const payload = {
                audit_session_id: sessionId,
                confirmed: true,
                ssh_username: credentials.ssh_username,
                ssh_password: credentials.ssh_password,
                skip_backup: false
            };

            // Add device-specific credentials
            if (deviceType === 'cisco' && credentials.ssh_secret) {
                payload.ssh_secret = credentials.ssh_secret;
            }
            if (deviceType === 'fortinet' && credentials.vdom) {
                payload.vdom = credentials.vdom;
            }
            if ((deviceType.startsWith('linux-') || deviceType === 'apache') && credentials.sudo_password) {
                payload.sudo_password = credentials.sudo_password;
            }

            const response = await api.post(
                `/api/hardening/${apiPath}/auto-harden-defaults`,
                payload
            );
            return response.data;
        } catch (error) {
            return rejectWithValue(
                error.response?.data?.detail || "Failed to auto harden"
            );
        }
    }
);

/**
 * Harden All - Batch execute selected checks
 * POST /api/hardening/{device}/batch-execute
 */
export const batchExecuteChecks = createAsyncThunk(
    "hardening/batchExecute",
    async ({ sessionId, deviceType, credentials, checkIds, parameters }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);

            const payload = {
                audit_session_id: sessionId,
                check_ids: checkIds,
                parameters: parameters || {},
                ssh_username: credentials.ssh_username,
                ssh_password: credentials.ssh_password,
                skip_backup: false
            };

            // Add device-specific credentials
            if (deviceType === 'cisco' && credentials.ssh_secret) {
                payload.ssh_secret = credentials.ssh_secret;
            }
            if (deviceType === 'fortinet' && credentials.vdom) {
                payload.vdom = credentials.vdom;
            }
            if ((deviceType.startsWith('linux-') || deviceType === 'apache') && credentials.sudo_password) {
                payload.sudo_password = credentials.sudo_password;
            }

            const response = await api.post(
                `/api/hardening/${apiPath}/batch-execute`,
                payload
            );
            return response.data;
        } catch (error) {
            return rejectWithValue(
                error.response?.data?.detail || "Failed to batch execute"
            );
        }
    }
);

// ===========================
// INITIAL STATE
// ===========================

const initialState = {
    // Session Management
    sessions: [],
    auditSessions: [],
    activeSessionId: null,
    currentSession: null,

    // Device Type
    deviceType: null, // 'cisco', 'fortinet', 'linux-ubuntu-22.04', etc.

    // Wizard State
    wizardMode: null, // 'fix-all' | 'fix-unsuccessful'
    wizardStep: 1,
    pollingActive: false,

    // Data
    cisChecks: [],
    failedChecks: [],
    requiredParameters: null,
    previewData: null,

    // Loading States
    isLoading: false,
    isExecuting: false,
    isFetchingParams: false,

    // Messages
    error: null,
    successMessage: null,
};

// ===========================
// SLICE
// ===========================

const hardeningSlice = createSlice({
    name: "hardening",
    initialState,
    reducers: {
        // Clear messages
        clearMessages: (state) => {
            state.error = null;
            state.successMessage = null;
        },

        // Clear current session
        clearCurrentSession: (state) => {
            state.currentSession = null;
            state.cisChecks = [];
            state.failedChecks = [];
        },

        // Set active session
        setActiveSession: (state, action) => {
            state.activeSessionId = action.payload;
        },

        // Clear active session
        clearActiveSession: (state) => {
            state.activeSessionId = null;
        },

        // Set polling state
        setPollingActive: (state, action) => {
            state.pollingActive = action.payload;
        },

        // Set device type
        setDeviceType: (state, action) => {
            state.deviceType = action.payload;
        },

        // Clear device type
        clearDeviceType: (state) => {
            state.deviceType = null;
        },

        // Wizard management
        setWizardMode: (state, action) => {
            state.wizardMode = action.payload;
            state.wizardStep = 1;
        },

        setWizardStep: (state, action) => {
            state.wizardStep = action.payload;
        },

        resetWizard: (state) => {
            state.wizardMode = null;
            state.wizardStep = 1;
            state.currentSession = null;
            state.cisChecks = [];
            state.failedChecks = [];
            state.requiredParameters = null;
            state.deviceType = null;
            state.error = null;
            state.successMessage = null;
        },

        // Clear parameters
        clearRequiredParameters: (state) => {
            state.requiredParameters = null;
        },

        // Clear preview data
        clearPreviewData: (state) => {
            state.previewData = null;
        },
    },

    extraReducers: (builder) => {
        // ===========================
        // EXECUTE AUDIT WITH DEVICE
        // ===========================
        builder
            .addCase(executeAuditWithDevice.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(executeAuditWithDevice.fulfilled, (state, action) => {
                state.isLoading = false;
                state.currentSession = action.payload;
                state.activeSessionId = action.payload.session_id;
                state.deviceType = action.payload.device_type;
                state.pollingActive = true;
            })
            .addCase(executeAuditWithDevice.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            });

        // ===========================
        // CHECK SESSION STATUS
        // ===========================
        builder
            .addCase(checkHardeningSessionStatus.pending, (state) => {
                state.isLoading = true;
            })
            .addCase(checkHardeningSessionStatus.fulfilled, (state, action) => {
                state.isLoading = false;
                state.currentSession = action.payload;

                // Stop polling if completed or failed
                if (
                    action.payload.status === "completed" ||
                    action.payload.status === "failed"
                ) {
                    state.pollingActive = false;
                }
            })
            .addCase(checkHardeningSessionStatus.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
                state.pollingActive = false;
            });

        // ===========================
        // FETCH REQUIRED PARAMETERS
        // ===========================
        builder
            .addCase(fetchRequiredParameters.pending, (state) => {
                state.isFetchingParams = true;
                state.error = null;
            })
            .addCase(fetchRequiredParameters.fulfilled, (state, action) => {
                state.isFetchingParams = false;
                state.requiredParameters = action.payload;
            })
            .addCase(fetchRequiredParameters.rejected, (state, action) => {
                state.isFetchingParams = false;
                state.error = action.payload;
            });

        // ===========================
        // AUTO HARDEN WITH DEFAULTS
        // ===========================
        builder
            .addCase(autoHardenWithDefaults.pending, (state) => {
                state.isExecuting = true;
                state.error = null;
            })
            .addCase(autoHardenWithDefaults.fulfilled, (state, action) => {
                state.isExecuting = false;
                state.successMessage = "Hardening applied successfully!";
            })
            .addCase(autoHardenWithDefaults.rejected, (state, action) => {
                state.isExecuting = false;
                state.error = action.payload;
            });

        // ===========================
        // BATCH EXECUTE
        // ===========================
        builder
            .addCase(batchExecuteChecks.pending, (state) => {
                state.isExecuting = true;
                state.error = null;
            })
            .addCase(batchExecuteChecks.fulfilled, (state, action) => {
                state.isExecuting = false;
                state.successMessage = "Batch hardening completed!";
            })
            .addCase(batchExecuteChecks.rejected, (state, action) => {
                state.isExecuting = false;
                state.error = action.payload;
            });

        // ===========================
        // FETCH AUDIT SESSIONS
        // ===========================
        builder
            .addCase(fetchAuditSessions.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(fetchAuditSessions.fulfilled, (state, action) => {
                state.isLoading = false;
                state.auditSessions = action.payload;
            })
            .addCase(fetchAuditSessions.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            });

        // ===========================
        // FETCH AUDIT RESULTS
        // ===========================
        builder
            .addCase(fetchAuditResults.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(fetchAuditResults.fulfilled, (state, action) => {
                state.isLoading = false;
                state.cisChecks = action.payload;
                // Filter failed checks
                state.failedChecks = action.payload.filter(
                    (check) => check.status?.toString().toUpperCase() === "FAIL"
                );
            })
            .addCase(fetchAuditResults.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            });

        // ===========================
        // PREVIEW HARDEN CHECK
        // ===========================
        builder
            .addCase(previewHardenCheck.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(previewHardenCheck.fulfilled, (state, action) => {
                state.isLoading = false;
                state.previewData = action.payload;
            })
            .addCase(previewHardenCheck.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            });

        // ===========================
        // EXECUTE HARDEN CHECK
        // ===========================
        builder
            .addCase(executeHardenCheck.pending, (state) => {
                state.isExecuting = true;
                state.error = null;
            })
            .addCase(executeHardenCheck.fulfilled, (state, action) => {
                state.isExecuting = false;
                state.successMessage = "Check hardened successfully!";
            })
            .addCase(executeHardenCheck.rejected, (state, action) => {
                state.isExecuting = false;
                state.error = action.payload;
            });
    },
});

// ===========================
// EXPORTS
// ===========================

export const {
    clearMessages,
    clearCurrentSession,
    setActiveSession,
    clearActiveSession,
    setPollingActive,
    setDeviceType,
    clearDeviceType,
    setWizardMode,
    setWizardStep,
    resetWizard,
    clearRequiredParameters,
    clearPreviewData,
} = hardeningSlice.actions;

export default hardeningSlice.reducer;