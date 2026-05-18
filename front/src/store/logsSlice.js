import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";

const API_BASE = "/api";

export const fetchAllLogs = createAsyncThunk("logs/fetchAll", async (_, { getState, rejectWithValue }) => {
    const token = getState().auth.token;
    const headers = { Authorization: `Bearer ${token}` };

    try {
        const [loginRes, assetRes, assetReqRes, auditRes, discoveryRes, hardeningRes] = await Promise.allSettled([
            fetch(`${API_BASE}/logs/?limit=200`, { headers }),
            fetch(`${API_BASE}/asset-logs/?limit=200`, { headers }),
            fetch(`${API_BASE}/asset-requirement-logs/?limit=200`, { headers }),
            fetch(`${API_BASE}/audit-logs/?limit=200`, { headers }),
            fetch(`${API_BASE}/discovery-logs/?limit=200`, { headers }),
            fetch(`${API_BASE}/hardening-logs/?limit=200`, { headers }),
        ]);

        const parse = async (result, section, mapFn) => {
            if (result.status === "fulfilled" && result.value.ok) {
                const data = await result.value.json();
                return data.map(mapFn(section));
            }
            return [];
        };

        const loginLogs = await parse(loginRes, "Login", (section) => (item) => ({
            id: `login-${item.id}`,
            username: item.username,
            action: "Login",
            asset_name: "-",
            section,
            status: item.success ? "success" : "failed",
            timestamp: item.timestamp,
        }));

        const assetLogs = await parse(assetRes, "Asset Management", (section) => (item) => ({
            id: `asset-${item.id}`,
            username: item.username,
            action: item.action,
            asset_name: item.asset_name || "-",
            section,
            status: item.status || "unknown",
            timestamp: item.timestamp,
        }));

        const assetReqLogs = await parse(assetReqRes, "Asset Requirement", (section) => (item) => ({
            id: `asset-req-${item.id}`,
            username: item.username,
            action: item.action,
            asset_name: item.entity_type || "-",
            section,
            status: item.status || "unknown",
            timestamp: item.timestamp,
        }));

        const auditLogs = await parse(auditRes, "Auditing", (section) => (item) => ({
            id: `audit-${item.id}`,
            username: item.username,
            action: item.action,
            asset_name: item.asset_name || "-",
            section,
            status: item.status || "unknown",
            timestamp: item.timestamp,
        }));

        const discoveryLogs = await parse(discoveryRes, "Auto Discovery", (section) => (item) => ({
            id: `discovery-${item.id}`,
            username: item.username,
            action: item.action,
            asset_name: item.target || "-",
            section,
            status: item.status || "unknown",
            timestamp: item.timestamp,
        }));

        const hardeningLogs = await parse(hardeningRes, "Hardening", (section) => (item) => ({
            id: `hardening-${item.id}`,
            username: item.username,
            action: item.action,
            asset_name: item.asset_name || "-",
            section,
            status: item.status || "unknown",
            timestamp: item.timestamp,
        }));

        const all = [
            ...loginLogs,
            ...assetLogs,
            ...assetReqLogs,
            ...auditLogs,
            ...discoveryLogs,
            ...hardeningLogs,
        ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        return all;
    } catch (err) {
        return rejectWithValue(err.message);
    }
});

const logsSlice = createSlice({
    name: "logs",
    initialState: {
        items: [],
        isLoading: false,
        error: null,
        isCleared: false,
    },
    reducers: {
        clearLogs(state) {
            state.items = [];
            state.isCleared = true;
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(fetchAllLogs.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(fetchAllLogs.fulfilled, (state, action) => {
                state.isLoading = false;
                state.items = action.payload;
                state.isCleared = false;
            })
            .addCase(fetchAllLogs.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            });
    },
});

export const { clearLogs } = logsSlice.actions;
export default logsSlice.reducer;