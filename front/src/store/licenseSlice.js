import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import {
    getLicenseStatus,
    activateLicense,
    clearLicenseFromStorage,
} from "../components/License/licenseService";

// =====================
// Thunks
// =====================

// دریافت وضعیت لایسنس
export const getLicenseStatusThunk = createAsyncThunk(
    "license/getStatus",
    async (_, { rejectWithValue }) => {
        try {
            const data = await getLicenseStatus();
            return data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || err.message || "Failed to get license status"
            );
        }
    }
);

// فعال‌سازی لایسنس
export const activateLicenseThunk = createAsyncThunk(
    "license/activate",
    async (licenseKey, { rejectWithValue }) => {
        try {
            const data = await activateLicense(licenseKey);
            return data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || err.message || "Failed to activate license"
            );
        }
    }
);

// =====================
// Slice
// =====================
const licenseSlice = createSlice({
    name: "license",
    initialState: {
        // اطلاعات لایسنس فعال
        isValid: false,
        planType: null,
        isPilotMode: false,
        limits: null,
        usage: null,
        expiresAt: null,
        message: "",

        // وضعیت loading
        isActivating: false,
        isValidating: false,

        // پیام‌ها
        error: null,
        successMessage: null,

        // آیا لایسنس از storage لود شده
        isInitialized: false,

    },
    reducers: {
        clearMessages: (state) => {
            state.error = null;
            state.successMessage = null;
        },
        clearLicense: (state) => {
            clearLicenseFromStorage();
            state.isValid = false;
            state.planType = null;
            state.isPilotMode = false;
            state.limits = null;
            state.usage = null;
            state.message = "";
            state.isInitialized = false;
        },

    },
    extraReducers: (builder) => {
        builder
            // Get Status
            .addCase(getLicenseStatusThunk.pending, (state) => {
                state.isValidating = true;
                state.error = null;
            })
        .addCase(getLicenseStatusThunk.fulfilled, (state, action) => {
            state.isValidating = false;
            state.isValid = action.payload.valid;
            state.planType = action.payload.plan_type;
            state.isPilotMode = action.payload.is_pilot_mode;
            state.limits = action.payload.limits;   // { max_audits, max_hardens } — Asset Management is not license-gated
            state.usage = action.payload.usage;     // { used_audits, used_hardens }
            state.expiresAt = action.payload.expires_at;  // ✅ اضافه شد
            state.message = action.payload.message;
            state.isInitialized = true;
        })
            .addCase(getLicenseStatusThunk.rejected, (state, action) => {
                state.isValidating = false;
                state.isValid = false;
                state.error = action.payload;
                state.isInitialized = true;
            })

            // Activate
            .addCase(activateLicenseThunk.pending, (state) => {
                state.isActivating = true;
                state.error = null;
            })
            .addCase(activateLicenseThunk.fulfilled, (state, action) => {
                state.isActivating = false;
                state.isValid = action.payload.valid;
                state.planType = action.payload.plan_type;
                state.isPilotMode = action.payload.is_pilot_mode;
                state.limits = action.payload.limits;
                state.usage = action.payload.usage;     // ✅ اضافه شد
                state.expiresAt = action.payload.expires_at;  // ✅ اضافه شد
                state.message = action.payload.message;
                state.successMessage = "License activated successfully!";
                state.isInitialized = true;
            })
            .addCase(activateLicenseThunk.rejected, (state, action) => {
                state.isActivating = false;
                state.error = action.payload;
            });
    },
});

export const {
    clearMessages,
    clearLicense,
} = licenseSlice.actions;

export default licenseSlice.reducer;
