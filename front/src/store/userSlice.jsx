import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api";

// Get all users
export const fetchUsers = createAsyncThunk(
    "users/fetchAll",
    async (_, { rejectWithValue }) => {
        try {
            const response = await api.get("/api/users/");  // ✅ تغییر
            return response.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to fetch users");
        }
    }
);

// Get single user
export const fetchUser = createAsyncThunk(
    "users/fetchOne",
    async (userId, { rejectWithValue }) => {
        try {
            const response = await api.get(`/api/users/${userId}`);  // ✅ تغییر
            return response.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to fetch user");
        }
    }
);

// Create user
export const createUser = createAsyncThunk(
    "users/create",
    async (userData, { rejectWithValue }) => {
        try {
            const response = await api.post("/api/users/", userData);  // ✅ تغییر
            return response.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to create user");
        }
    }
);

// Update user
export const updateUser = createAsyncThunk(
    "users/update",
    async ({ userId, userData }, { rejectWithValue }) => {
        try {
            const response = await api.put(`/api/users/${userId}`, userData);  // ✅ تغییر
            return response.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to update user");
        }
    }
);

// Delete user
export const deleteUser = createAsyncThunk(
    "users/delete",
    async (userId, { rejectWithValue }) => {
        try {
            await api.delete(`/api/users/${userId}`);  // ✅ تغییر
            return userId;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Failed to delete user");
        }
    }
);

// Search users
export const searchUsers = createAsyncThunk(
    "users/search",
    async (query, { rejectWithValue }) => {
        try {
            const response = await api.get(`/api/users/search/?q=${query}`);  // ✅ تغییر
            return response.data;
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || "Search failed");
        }
    }
);

// بقیه slice بدون تغییر...
const userSlice = createSlice({
    name: "users",
    initialState: {
        users: [],
        selectedUser: null,
        isLoading: false,
        error: null,
        successMessage: null,
    },
    reducers: {
        clearMessages: (state) => {
            state.error = null;
            state.successMessage = null;
        },
        clearSelectedUser: (state) => {
            state.selectedUser = null;
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(fetchUsers.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(fetchUsers.fulfilled, (state, action) => {
                state.isLoading = false;
                state.users = action.payload;
            })
            .addCase(fetchUsers.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            })
            .addCase(fetchUser.pending, (state) => {
                state.isLoading = true;
            })
            .addCase(fetchUser.fulfilled, (state, action) => {
                state.isLoading = false;
                state.selectedUser = action.payload;
            })
            .addCase(fetchUser.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            })
            .addCase(createUser.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(createUser.fulfilled, (state, action) => {
                state.isLoading = false;
                state.users.push(action.payload);
                state.successMessage = "User created successfully!";
            })
            .addCase(createUser.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            })
            .addCase(updateUser.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(updateUser.fulfilled, (state, action) => {
                state.isLoading = false;
                const index = state.users.findIndex(u => u.id === action.payload.id);
                if (index !== -1) {
                    state.users[index] = action.payload;
                }
                state.successMessage = "User updated successfully!";
            })
            .addCase(updateUser.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            })
            .addCase(deleteUser.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(deleteUser.fulfilled, (state, action) => {
                state.isLoading = false;
                state.users = state.users.filter(u => u.id !== action.payload);
                state.successMessage = "User deleted successfully!";
            })
            .addCase(deleteUser.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            })
            .addCase(searchUsers.pending, (state) => {
                state.isLoading = true;
            })
            .addCase(searchUsers.fulfilled, (state, action) => {
                state.isLoading = false;
                state.users = action.payload;
            })
            .addCase(searchUsers.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            });
    },
});

export const { clearMessages, clearSelectedUser } = userSlice.actions;
export default userSlice.reducer;