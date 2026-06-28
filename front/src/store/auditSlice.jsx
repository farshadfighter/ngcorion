import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// =====================
// HELPER FUNCTION
// =====================

const getDeviceApiPath = (deviceType) => {
    if (!deviceType) return 'cisco';
    if (deviceType.startsWith('linux-'))   return 'linux';
    if (deviceType.startsWith('mssql-'))   return 'mssql';
    if (deviceType.startsWith('windows-')) return 'windows';
    if (deviceType === 'mongodb')          return 'mongodb';
    return deviceType;
};

// =====================
// Thunks
// =====================

export const executeAudit = createAsyncThunk(
    "audit/execute",
    async ({ deviceType, formData }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const endpoint = `/api/audit/${apiPath}/execute`;

            const payload = { asset_id: formData.asset_id, profile: "FULL" };

            if (formData.job_name)      payload.job_name      = formData.job_name;
            if (formData.ssh_username)  payload.ssh_username  = formData.ssh_username;
            if (formData.ssh_password)  payload.ssh_password  = formData.ssh_password;
            if (formData.ssh_port)      payload.ssh_port      = parseInt(formData.ssh_port) || 22;
            if (formData.ssh_secret)    payload.ssh_secret    = formData.ssh_secret;
            if (formData.vdom)          payload.vdom          = formData.vdom;
            if (formData.sudo_password) payload.sudo_password = formData.sudo_password;
            if (formData.mongo_username) payload.mongo_username = formData.mongo_username;
            if (formData.mongo_password) payload.mongo_password = formData.mongo_password;
            if (formData.mongo_port)     payload.mongo_port     = parseInt(formData.mongo_port);
            if (formData.mssql_username) payload.mssql_username = formData.mssql_username;
            if (formData.mssql_password) payload.mssql_password = formData.mssql_password;
            if (formData.mssql_port)     payload.mssql_port     = parseInt(formData.mssql_port);
            if (formData.windows_username) payload.windows_username = formData.windows_username;
            if (formData.windows_password) payload.windows_password = formData.windows_password;
            if (formData.winrm_port)       payload.winrm_port       = parseInt(formData.winrm_port);
            if (formData.transport)        payload.transport        = formData.transport;
            if (apiPath === 'linux' && deviceType?.startsWith('linux-')) payload.sub_device_type = deviceType;

            const res = await api.post(endpoint, payload);
            return res.data;
        } catch (err) {
            // Extract error message from various possible formats
            const detail = err.response?.data?.detail;
            let errorMessage = "Failed to start audit";
            
            if (typeof detail === "string") {
                errorMessage = detail;
            } else if (detail && typeof detail === "object") {
                // Handle structured error objects from SSH/device errors
                errorMessage = detail.message || detail.error_type || "Authentication failed";
            } else if (err.message) {
                errorMessage = err.message;
            }
            
            return rejectWithValue(errorMessage);
        }
    }
);

export const fetchAuditSessions = createAsyncThunk(
    "audit/fetchSessions",
    async ({ limit = 50, offset = 0 } = {}, { rejectWithValue }) => {
        try {
            const families = ["cisco", "fortinet", "linux", "apache", "mongodb", "mssql", "windows"];
            const results = await Promise.allSettled(
                families.map((family) =>
                    api.get(`/api/audit/${family}/sessions`, { params: { limit, offset } })
                )
            );
            const allSessions = [];
            results.forEach((result, idx) => {
                if (result.status === "fulfilled") {
                    const data = result.value.data;
                    if (Array.isArray(data)) allSessions.push(...data);
                } else {
                    console.warn(`Failed to fetch ${families[idx]} sessions:`, result.reason?.message);
                }
            });
            return allSessions;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to fetch audit sessions");
        }
    }
);

export const fetchAuditSession = createAsyncThunk(
    "audit/fetchSession",
    async (sessionId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/audit/sessions/${sessionId}`);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to fetch audit session");
        }
    }
);

export const fetchAuditResults = createAsyncThunk(
    "audit/fetchResults",
    async (sessionId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/audit/sessions/${sessionId}/results`);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to fetch audit results");
        }
    }
);

export const deleteAuditSession = createAsyncThunk(
    "audit/delete",
    async (sessionId, { rejectWithValue }) => {
        try {
            await api.delete(`/api/audit/sessions/${sessionId}`);
            return sessionId;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to delete audit session");
        }
    }
);

// ── Clear History: همه sessions همه family ها رو حذف میکنه ──────────────────
export const clearAllAuditSessions = createAsyncThunk(
    "audit/clearAll",
    async (_, { getState, rejectWithValue }) => {
        try {
            const sessions = getState().audit.sessions;

            // هر session رو با session_id و device_type پیدا میکنیم
            // چون endpoint به device family نیاز داره
            const families = ["cisco", "fortinet", "linux", "apache", "mongodb", "mssql", "windows"];

            // تلاش میکنیم DELETE /api/audit/{family}/sessions/clear رو صدا بزنیم
            // اگه backend این endpoint رو نداره، به صورت موازی همه رو یکی‌یکی حذف میکنیم
            const results = await Promise.allSettled(
                families.map((family) =>
                    api.delete(`/api/audit/${family}/sessions/clear`)
                )
            );

            // اگه حداقل یکی موفق شد، OK
            const anySuccess = results.some((r) => r.status === "fulfilled");
            if (!anySuccess) {
                // fallback: یکی‌یکی حذف کن
                await Promise.allSettled(
                    sessions.map((s) =>
                        api.delete(`/api/audit/sessions/${s.session_id}`)
                    )
                );
            }

            return true;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to clear history");
        }
    }
);

export const fetchFortinetBenchmark = createAsyncThunk(
    "audit/fetchFortinetBenchmark",
    async (_arg, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/audit/fortinet/benchmark");
            return res.data; // { version, total, automated, manual, controls: [...] }
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to load CIS benchmark");
        }
    }
);

export const checkAuditStatus = createAsyncThunk(
    "audit/checkStatus",
    async (sessionId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/audit/sessions/${sessionId}`);
            return res.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to check audit status");
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
        isLoading: false,
        isLoadingResults: false,
        isExecuting: false,
        isClearing: false,
        error: null,
        successMessage: null,
        benchmark: { data: null, isLoading: false, error: null },
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
    },
    extraReducers: (builder) => {
        builder
            .addCase(executeAudit.pending,    (state) => { state.isExecuting = true;  state.error = null; })
            .addCase(executeAudit.fulfilled,  (state, action) => {
                state.isExecuting    = false;
                state.currentSession = action.payload;
                state.successMessage = "Audit started successfully!";
            })
            .addCase(executeAudit.rejected,   (state, action) => { state.isExecuting = false; state.error = action.payload; })

            .addCase(fetchAuditSessions.pending,   (state) => { state.isLoading = true;  state.error = null; })
            .addCase(fetchAuditSessions.fulfilled, (state, action) => { state.isLoading = false; state.sessions = action.payload; })
            .addCase(fetchAuditSessions.rejected,  (state, action) => { state.isLoading = false; state.error = action.payload; })

            .addCase(fetchAuditSession.fulfilled,  (state, action) => { state.currentSession = action.payload; })
            .addCase(fetchAuditSession.rejected,   (state, action) => { state.error = action.payload; })

            .addCase(fetchAuditResults.pending,    (state) => { state.isLoadingResults = true;  state.error = null; })
            .addCase(fetchAuditResults.fulfilled,  (state, action) => { state.isLoadingResults = false; state.results = action.payload; })
            .addCase(fetchAuditResults.rejected,   (state, action) => { state.isLoadingResults = false; state.error = action.payload; })

            .addCase(deleteAuditSession.fulfilled, (state, action) => {
                state.sessions = state.sessions.filter((s) => s.session_id !== action.payload);
                state.successMessage = "Audit session deleted successfully!";
            })
            .addCase(deleteAuditSession.rejected,  (state, action) => { state.error = action.payload; })

            .addCase(clearAllAuditSessions.pending,   (state) => { state.isClearing = true;  state.error = null; })
            .addCase(clearAllAuditSessions.fulfilled, (state) => {
                state.isClearing     = false;
                state.sessions       = [];
                state.successMessage = "History cleared successfully!";
            })
            .addCase(clearAllAuditSessions.rejected,  (state, action) => { state.isClearing = false; state.error = action.payload; })

            .addCase(checkAuditStatus.fulfilled, (state, action) => {
                state.currentSession = action.payload;
            })

            .addCase(fetchFortinetBenchmark.pending,   (state) => { state.benchmark = { data: null, isLoading: true, error: null }; })
            .addCase(fetchFortinetBenchmark.fulfilled, (state, action) => { state.benchmark = { data: action.payload, isLoading: false, error: null }; })
            .addCase(fetchFortinetBenchmark.rejected,  (state, action) => { state.benchmark = { data: null, isLoading: false, error: action.payload }; });
    },
});

export const { clearMessages, clearCurrentSession } = auditSlice.actions;

export default auditSlice.reducer;
