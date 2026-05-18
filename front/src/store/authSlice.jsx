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
            if (err.response?.data?.detail) {
                const detail = err.response.data.detail;
                if (typeof detail === "string") return rejectWithValue(detail);
                if (Array.isArray(detail)) return rejectWithValue(detail.map(e => e.msg).join(", "));
            }
            return rejectWithValue("Failed to connect to the server");
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
            });
    },
});

export const { logout, clearError } = authSlice.actions;
export default authSlice.reducer;