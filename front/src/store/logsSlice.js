import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";

const API_BASE = "/api";

export const fetchAllLogs = createAsyncThunk("logs/fetchAll", async (_, { getState, rejectWithValue }) => {
    const token = getState().auth.token;
    const headers = { Authorization: `Bearer ${token}` };

    try {
        const [loginRes, assetRes, assetReqRes, auditRes, discoveryRes, hardeningRes] = await Promise.allSettled([
            fetch(`${API_BASE}/logs/?limit=50`, { headers }),
            fetch(`${API_BASE}/asset-logs/?limit=50`, { headers }),
            fetch(`${API_BASE}/asset-requirement-logs/?limit=50`, { headers }),
            fetch(`${API_BASE}/audit-logs/?limit=50`, { headers }),
            fetch(`${API_BASE}/discovery-logs/?limit=50`, { headers }),
            fetch(`${API_BASE}/hardening-logs/?limit=50`, { headers }),
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

/**
 * Actually delete the logs on the server.
 *
 * This used to be a plain reducer that only emptied the local array, so the
 * page reported success and the rows reappeared on the next refresh. The real
 * work happens in DELETE /api/logs/clear.
 */
export const clearLogs = createAsyncThunk(
    "logs/clear",
    async (_, { getState, dispatch, rejectWithValue }) => {
        const token = getState().auth.token;
        try {
            const res = await fetch(`${API_BASE}/logs/clear`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) {
                let detail = `Clear failed (${res.status})`;
                try {
                    detail = (await res.json())?.detail || detail;
                } catch {
                    /* non-JSON error body — keep the status text */
                }
                return rejectWithValue(detail);
            }
            const data = await res.json();
            // Re-read from the server rather than trusting a local empty array:
            // the audit trail is intentionally preserved, so some rows remain.
            await dispatch(fetchAllLogs());
            return data;
        } catch (err) {
            return rejectWithValue(err.message);
        }
    }
);

const logsSlice = createSlice({
    name: "logs",
    initialState: {
        items: [],
        isLoading: false,
        error: null,
        isCleared: false,
        isClearing: false,
        clearError: null,
        // Result of the last clear: { total_deleted, deleted: {…} }. Kept so the
        // page can report what actually went, instead of leaving the user to
        // guess why the Auditing rows are still on screen.
        clearResult: null,
    },
    reducers: {
        dismissClearResult: (state) => {
            state.clearResult = null;
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
            })
            .addCase(clearLogs.pending, (state) => {
                state.isClearing = true;
                state.clearError = null;
                state.clearResult = null;
            })
            .addCase(clearLogs.fulfilled, (state, action) => {
                state.isClearing = false;
                // fetchAllLogs (dispatched by the thunk) refills `items`.
                state.clearResult = action.payload;
            })
            .addCase(clearLogs.rejected, (state, action) => {
                state.isClearing = false;
                state.clearError = action.payload;
            });
    },
});

export const { dismissClearResult } = logsSlice.actions;
export default logsSlice.reducer;