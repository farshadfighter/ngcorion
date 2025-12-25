import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api";  // ✅ تغییر

export const loginUser = createAsyncThunk(
    "auth/login",
    async (credentials, { rejectWithValue }) => {
        try {
            const response = await api.post("/auth/login", {  // ✅ تغییر - حذف /api
                username: credentials.username,
                password: credentials.password,
            });
            return response.data;
        } catch (err) {
            if (err.response?.status === 401) {
                return rejectWithValue("Invalid username or password");
            }
            return rejectWithValue("Failed to connect to the server");
        }
    }
);

// بقیه کد بدون تغییر...
const authSlice = createSlice({
    name: "auth",
    initialState: {
        token: localStorage.getItem("token") || null,
        username: localStorage.getItem("username") || null,
        role: localStorage.getItem("role") || null,
        isLoading: false,
        error: null,
    },
    reducers: {
        logout: (state) => {
            state.token = null;
            state.username = null;
            state.role = null;
            state.error = null;

            localStorage.removeItem("token");
            localStorage.removeItem("username");
            localStorage.removeItem("role");
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(loginUser.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(loginUser.fulfilled, (state, action) => {
                state.isLoading = false;
                state.token = action.payload.access_token;
                state.username = action.payload.username;
                state.role = action.payload.role;

                localStorage.setItem("token", action.payload.access_token);
                localStorage.setItem("username", action.payload.username);
                localStorage.setItem("role", action.payload.role);
            })
            .addCase(loginUser.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            });
    },
});

export const { logout } = authSlice.actions;
export default authSlice.reducer;