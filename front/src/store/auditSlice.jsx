import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// =====================
// HELPER FUNCTION
// =====================

/**
 * Maps device type to API path
 * Linux variants → 'linux'
 * MongoDB        → 'mongodb'
 * MSSQL variants → 'mssql'
 * Windows variants → 'windows'
 * Others (cisco, fortinet, apache) → same as device type
 */
const getDeviceApiPath = (deviceType) => {
    if (!deviceType) return 'cisco';
    if (deviceType.startsWith('linux-'))   return 'linux';
    if (deviceType.startsWith('mssql-'))   return 'mssql';
    if (deviceType.startsWith('windows-')) return 'windows';
    if (deviceType === 'mongodb')          return 'mongodb';
    return deviceType; // cisco, fortinet, apache
};

// =====================
// Thunks
// =====================

// Execute audit (Start new audit)
export const executeAudit = createAsyncThunk(
    "audit/execute",
    async ({ deviceType, formData }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const endpoint = `/api/audit/${apiPath}/execute`;

            const payload = {
                asset_id: formData.asset_id,
                profile: "L1"
            };

            if (formData.job_name) payload.job_name = formData.job_name;

            // SSH-based devices
            if (formData.ssh_username) payload.ssh_username = formData.ssh_username;
            if (formData.ssh_password) payload.ssh_password = formData.ssh_password;
            if (formData.ssh_secret)   payload.ssh_secret   = formData.ssh_secret;
            if (formData.vdom)         payload.vdom         = formData.vdom;
            if (formData.sudo_password) payload.sudo_password = formData.sudo_password;

            // MongoDB extra
            if (formData.mongo_username) payload.mongo_username = formData.mongo_username;
            if (formData.mongo_password) payload.mongo_password = formData.mongo_password;
            if (formData.mongo_port)     payload.mongo_port     = parseInt(formData.mongo_port);

            // MSSQL
            if (formData.mssql_username) payload.mssql_username = formData.mssql_username;
            if (formData.mssql_password) payload.mssql_password = formData.mssql_password;
            if (formData.mssql_port)     payload.mssql_port     = parseInt(formData.mssql_port);

            // Windows
            if (formData.windows_username) payload.windows_username = formData.windows_username;
            if (formData.windows_password) payload.windows_password = formData.windows_password;
            if (formData.winrm_port)       payload.winrm_port       = parseInt(formData.winrm_port);
            if (formData.transport)        payload.transport        = formData.transport;

            const res = await api.post(endpoint, payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to start audit"
            );
        }
    }
);

// Fetch all audit sessions (for main list) - from all 7 families in parallel
export const fetchAuditSessions = createAsyncThunk(
    "audit/fetchSessions",
    async ({ limit = 50, offset = 0 } = {}, { rejectWithValue }) => {
        try {
            const families = ["cisco", "fortinet", "linux", "apache", "mongodb", "mssql", "windows"];

            const results = await Promise.allSettled(
                families.map((family) =>
                    api.get(`/api/audit/${family}/sessions`, {
                        params: { limit, offset }
                    })
                )
            );

            const allSessions = [];
            results.forEach((result, idx) => {
                if (result.status === "fulfilled") {
                    const data = result.value.data;
                    if (Array.isArray(data)) {
                        allSessions.push(...data);
                    }
                } else {
                    console.warn(
                        `Failed to fetch ${families[idx]} sessions:`,
                        result.reason?.message
                    );
                }
            });

            return allSessions;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to fetch audit sessions"
            );
        }
    }
);

// Fetch single audit session (for checking status)
export const fetchAuditSession = createAsyncThunk(
    "audit/fetchSession",
    async (sessionId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/audit/sessions/${sessionId}`);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to fetch audit session"
            );
        }
    }
);

// Fetch audit results (detailed results)
export const fetchAuditResults = createAsyncThunk(
    "audit/fetchResults",
    async (sessionId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/audit/sessions/${sessionId}/results`);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to fetch audit results"
            );
        }
    }
);

// Delete audit session
export const deleteAuditSession = createAsyncThunk(
    "audit/delete",
    async (sessionId, { rejectWithValue }) => {
        try {
            await api.delete(`/api/audit/sessions/${sessionId}`);
            return sessionId;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to delete audit session"
            );
        }
    }
);

// Check audit status (for polling)
export const checkAuditStatus = createAsyncThunk(
    "audit/checkStatus",
    async (sessionId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/audit/sessions/${sessionId}`);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to check audit status"
            );
        }
    }
);

// Fetch audit sessions count
export const fetchAuditSessionsCount = createAsyncThunk(
    "audit/fetchCount",
    async (_, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/audit/sessions/count");
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to fetch sessions count"
            );
        }
    }
);

// =====================
// Slice
// =====================
const auditSlice = createSlice({
    name: "audit",
    initialState: {
        sessions: [],
        currentSession: null,
        results: [],
        totalCount: 0,
        isLoading: false,
        isLoadingResults: false,
        isExecuting: false,
        error: null,
        successMessage: null,
        // For wizard flow
        activeSessionId: null,
        pollingActive: false,
    },
    reducers: {
        clearMessages: (state) => {
            state.error = null;
            state.successMessage = null;
        },
        clearCurrentSession: (state) => {
            state.currentSession = null;
            state.results = [];
        },
        setActiveSession: (state, action) => {
            state.activeSessionId = action.payload;
        },
        clearActiveSession: (state) => {
            state.activeSessionId = null;
            state.currentSession = null;
            state.results = [];
        },
        setPollingActive: (state, action) => {
            state.pollingActive = action.payload;
        },
    },
    extraReducers: (builder) => {
        builder
            // Execute audit
            .addCase(executeAudit.pending, (state) => {
                state.isExecuting = true;
                state.error = null;
            })
            .addCase(executeAudit.fulfilled, (state, action) => {
                state.isExecuting = false;
                state.currentSession = action.payload;
                state.activeSessionId = action.payload.session_id;
                state.successMessage = "Audit started successfully!";
            })
            .addCase(executeAudit.rejected, (state, action) => {
                state.isExecuting = false;
                state.error = action.payload;
            })

            // Fetch sessions
            .addCase(fetchAuditSessions.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(fetchAuditSessions.fulfilled, (state, action) => {
                state.isLoading = false;
                state.sessions = action.payload;
            })
            .addCase(fetchAuditSessions.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            })

            // Fetch single session
            .addCase(fetchAuditSession.fulfilled, (state, action) => {
                state.currentSession = action.payload;
            })
            .addCase(fetchAuditSession.rejected, (state, action) => {
                state.error = action.payload;
            })

            // Fetch results
            .addCase(fetchAuditResults.pending, (state) => {
                state.isLoadingResults = true;
                state.error = null;
            })
            .addCase(fetchAuditResults.fulfilled, (state, action) => {
                state.isLoadingResults = false;
                state.results = action.payload;
            })
            .addCase(fetchAuditResults.rejected, (state, action) => {
                state.isLoadingResults = false;
                state.error = action.payload;
            })

            // Delete session
            .addCase(deleteAuditSession.fulfilled, (state, action) => {
                state.sessions = state.sessions.filter(
                    (s) => s.session_id !== action.payload
                );
                state.successMessage = "Audit session deleted successfully!";
            })
            .addCase(deleteAuditSession.rejected, (state, action) => {
                state.error = action.payload;
            })

            // Check status (polling)
            .addCase(checkAuditStatus.fulfilled, (state, action) => {
                state.currentSession = action.payload;
                if (action.payload.status === "completed" || action.payload.status === "failed") {
                    state.pollingActive = false;
                }
            })

            // Fetch count
            .addCase(fetchAuditSessionsCount.fulfilled, (state, action) => {
                state.totalCount = action.payload.total || 0;
            });
    },
});

export const {
    clearMessages,
    clearCurrentSession,
    setActiveSession,
    clearActiveSession,
    setPollingActive,
} = auditSlice.actions;

export default auditSlice.reducer;