import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api";

// ==========================================
// Async Thunks
// ==========================================

export const loginUser = createAsyncThunk(
    "auth/login",
    async (credentials, { rejectWithValue }) => {
        try {
            const response = await api.post("/auth/login", {
                username: credentials.username,
                password: credentials.password,
            });
            return response.data;
        } catch (err) {
            if (err.response?.status === 401) {
                return rejectWithValue("Incorrect username or password");
            }
            if (err.response?.status === 403) {
                return rejectWithValue("Account is inactive");
            }
            if (err.response?.status === 429) {
                return rejectWithValue(
                    err.response?.data?.detail ||
                    "Too many failed login attempts. Please wait before trying again."
                );
            }
            if (err.response?.data?.detail) {
                const detail = err.response.data.detail;
                if (typeof detail === "string") return rejectWithValue(detail);
                if (Array.isArray(detail)) return rejectWithValue(detail.map(e => e.msg).join(", "));
            }
            return rejectWithValue("Failed to connect to the server");
        }
    }
);

// Validate the stored token against the backend on app load.
// Resolves with the fresh identity/permissions if the token is still valid;
// rejects (→ logout) if it is missing, expired, or otherwise invalid. This is
// what stops an expired token from rendering the dashboard before the first
// real API call bounces the user back to login.
export const verifyToken = createAsyncThunk(
    "auth/verify",
    async (_, { rejectWithValue }) => {
        const token = localStorage.getItem("token");
        if (!token) {
            return rejectWithValue("no-token");
        }
        try {
            const response = await api.get("/auth/me");
            return response.data;
        } catch (err) {
            return rejectWithValue(err.response?.status || "invalid-token");
        }
    }
);

// ==========================================
// Helper - بررسی دسترسی کاربر
// ==========================================

export const hasPermission = (permissions, role, module, action) => {
    if (role === "admin") return true;
    if (!permissions || !permissions[module]) return false;
    return permissions[module][action] === true;
};

// ==========================================
// Slice
// ==========================================

const authSlice = createSlice({
    name: "auth",
    initialState: {
        token:       localStorage.getItem("token") || null,
        username:    localStorage.getItem("username") || null,
        role:        localStorage.getItem("role") || null,
        permissions: JSON.parse(localStorage.getItem("permissions") || "{}"),
        isLoading:   false,
        error:       null,
        // Auth-verification gate: protected routes must not render until the
        // stored token has been confirmed valid against the backend.
        authChecked:     false,
        isAuthenticating: false,
    },
    reducers: {
        logout: (state) => {
            state.token       = null;
            state.username    = null;
            state.role        = null;
            state.permissions = {};
            state.error       = null;

            localStorage.removeItem("token");
            localStorage.removeItem("username");
            localStorage.removeItem("role");
            localStorage.removeItem("permissions");
        },

        clearError: (state) => {
            state.error = null;
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(loginUser.pending, (state) => {
                state.isLoading = true;
                state.error     = null;
            })
            .addCase(loginUser.fulfilled, (state, action) => {
                state.isLoading   = false;
                state.token       = action.payload.access_token;
                state.username    = action.payload.username;
                state.role        = action.payload.role;
                state.permissions = action.payload.permissions || {};

                localStorage.setItem("token",       action.payload.access_token);
                localStorage.setItem("username",    action.payload.username);
                localStorage.setItem("role",        action.payload.role);
                localStorage.setItem("permissions", JSON.stringify(action.payload.permissions || {}));
            })
            .addCase(loginUser.rejected, (state, action) => {
                state.isLoading = false;
                state.error     = action.payload;
            })

            // ── Token verification on app load ──
            .addCase(verifyToken.pending, (state) => {
                state.isAuthenticating = true;
            })
            .addCase(verifyToken.fulfilled, (state, action) => {
                state.isAuthenticating = false;
                state.authChecked      = true;
                // Refresh identity/permissions from the server (may have changed
                // since the token was issued).
                state.username    = action.payload.username;
                state.role        = action.payload.role;
                state.permissions = action.payload.permissions || {};

                localStorage.setItem("username",    action.payload.username);
                localStorage.setItem("role",        action.payload.role);
                localStorage.setItem("permissions", JSON.stringify(action.payload.permissions || {}));
            })
            .addCase(verifyToken.rejected, (state) => {
                // Token missing/expired/invalid → clear the session so
                // ProtectedRoute sends the user straight to login (no flash).
                state.isAuthenticating = false;
                state.authChecked      = true;
                state.token       = null;
                state.username    = null;
                state.role        = null;
                state.permissions = {};

                localStorage.removeItem("token");
                localStorage.removeItem("username");
                localStorage.removeItem("role");
                localStorage.removeItem("permissions");
            });
    },
});

export const { logout, clearError } = authSlice.actions;
export default authSlice.reducer;