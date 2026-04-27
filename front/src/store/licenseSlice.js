import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import {
    activateLicense,
    validateLicense,
    sendHeartbeat,
    consumeOperation,
    loadLicenseFromStorage,
    clearLicenseFromStorage,
} from "../components/License/licenseService";

// =====================
// Thunks
// =====================

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

// اعتبارسنجی لایسنس
export const validateLicenseThunk = createAsyncThunk(
    "license/validate",
    async (_, { rejectWithValue }) => {
        try {
            const data = await validateLicense();
            return data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || err.message || "Failed to validate license"
            );
        }
    }
);

// heartbeat
export const heartbeatThunk = createAsyncThunk(
    "license/heartbeat",
    async (_, { rejectWithValue }) => {
        try {
            const data = await sendHeartbeat();
            return data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || err.message || "Heartbeat failed"
            );
        }
    }
);

// مصرف عملیات
export const consumeOperationThunk = createAsyncThunk(
    "license/consume",
    async ({ operationType, count = 1 }, { rejectWithValue }) => {
        try {
            const data = await consumeOperation(operationType, count);
            return data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || err.message || "Failed to consume operation"
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
        organizationToken: null,

        // وضعیت loading
        isActivating: false,
        isValidating: false,
        isConsuming: false,

        // heartbeat
        heartbeatActive: false,
        lastHeartbeat: null,

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
            state.organizationToken = null;
            state.heartbeatActive = false;
            state.lastHeartbeat = null;
            state.isInitialized = false;
        },
        setHeartbeatActive: (state, action) => {
            state.heartbeatActive = action.payload;
        },
        updateLastHeartbeat: (state) => {
            state.lastHeartbeat = new Date().toISOString();
        },
        // چک کردن آیا لایسنس در storage هست
        initializeFromStorage: (state) => {
            const stored = loadLicenseFromStorage();
            state.isInitialized = true;
            if (stored) {
                state.organizationToken = stored.organization_token;
            }
        },
    },
    extraReducers: (builder) => {
        builder
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
                state.usage = action.payload.usage;
                state.organizationToken = action.payload.organization_token;
                state.successMessage = "License activated successfully!";
                state.isInitialized = true;
            })
            .addCase(activateLicenseThunk.rejected, (state, action) => {
                state.isActivating = false;
                state.error = action.payload;
            })

            // Validate
            .addCase(validateLicenseThunk.pending, (state) => {
                state.isValidating = true;
                state.error = null;
            })
            .addCase(validateLicenseThunk.fulfilled, (state, action) => {
                state.isValidating = false;
                state.isValid = action.payload.valid;
                state.planType = action.payload.plan_type;
                state.isPilotMode = action.payload.is_pilot_mode;
                state.limits = action.payload.limits;
                state.usage = action.payload.usage;
                state.isInitialized = true;
            })
            .addCase(validateLicenseThunk.rejected, (state, action) => {
                state.isValidating = false;
                state.isValid = false;
                state.error = action.payload;
            })

            // Heartbeat
            .addCase(heartbeatThunk.fulfilled, (state, action) => {
                state.lastHeartbeat = new Date().toISOString();
                if (action.payload.should_downgrade) {
                    state.isValid = false;
                }
            })
            .addCase(heartbeatThunk.rejected, (state) => {
                state.lastHeartbeat = new Date().toISOString();
            })

            // Consume
            .addCase(consumeOperationThunk.pending, (state) => {
                state.isConsuming = true;
                state.error = null;
            })
            .addCase(consumeOperationThunk.fulfilled, (state, action) => {
                state.isConsuming = false;
                state.usage = action.payload.usage;
                state.limits = action.payload.limits;
            })
            .addCase(consumeOperationThunk.rejected, (state, action) => {
                state.isConsuming = false;
                state.error = action.payload;
            });
    },
});

export const {
    clearMessages,
    clearLicense,
    setHeartbeatActive,
    updateLastHeartbeat,
    initializeFromStorage,
} = licenseSlice.actions;

export default licenseSlice.reducer;