import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// =====================
// HELPER FUNCTION
// =====================

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

// =====================
// Thunks
// =====================

// Execute audit (Start new audit)
export const executeAudit = createAsyncThunk(
    "audit/execute",
    async ({ deviceType, formData }, { rejectWithValue }) => {
        try {
            // ✅ FIX: Use consistent endpoint pattern for ALL devices
            const apiPath = getDeviceApiPath(deviceType);
            const endpoint = `/api/audit/${apiPath}/execute`;

            const payload = {
                asset_id: formData.asset_id,
                ssh_username: formData.ssh_username,
                ssh_password: formData.ssh_password,
                profile: "L1"
            };

            // Add device-specific fields
            if (formData.ssh_secret) payload.ssh_secret = formData.ssh_secret;
            if (formData.vdom) payload.vdom = formData.vdom;
            if (formData.sudo_password) payload.sudo_password = formData.sudo_password;

            const res = await api.post(endpoint, payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || "Failed to start audit"
            );
        }
    }
);

// Fetch all audit sessions (for main list) - queries all device types
export const fetchAuditSessions = createAsyncThunk(
    "audit/fetchSessions",
    async ({ limit = 50, offset = 0 } = {}, { rejectWithValue }) => {
        try {
            const deviceTypes = ['cisco', 'fortinet', 'linux', 'apache'];
            const allSessions = [];
            for (const device of deviceTypes) {
                try {
                    const res = await api.get(`/api/audit/${device}/sessions`, {
                        params: { limit, offset }
                    });
                    if (res.data && Array.isArray(res.data)) {
                        allSessions.push(...res.data);
                    }
                } catch (err) {
                    console.warn(`Failed to fetch ${device} sessions:`, err.message);
                }
            }
            // Sort by started_at descending
            allSessions.sort((a, b) =>
                new Date(b.started_at || 0) - new Date(a.started_at || 0)
            );
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
    async ({ sessionId, deviceType }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const res = await api.get(`/api/audit/${apiPath}/sessions/${sessionId}`);
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
    async ({ sessionId, deviceType }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const res = await api.get(`/api/audit/${apiPath}/sessions/${sessionId}/results`);
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
    async ({ sessionId, deviceType }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            await api.delete(`/api/audit/${apiPath}/sessions/${sessionId}`);
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
    async ({ sessionId, deviceType }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const res = await api.get(`/api/audit/${apiPath}/sessions/${sessionId}`);
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
                // If completed or failed, stop polling
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