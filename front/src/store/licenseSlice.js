/**
 * Redux slice: license status and activation.
 */
import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import {
    getLicenseStatus,
    getLicenseUsage,
    activateLicense,
    clearLicenseFromStorage,
} from "../components/License/licenseService";
import { t } from "../i18n";
import { apiErrorDetail } from "../utils/apiError.js";

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
                apiErrorDetail(err, err?.message || t("Failed to get license status"))
            );
        }
    }
);

// The inventory against the license's asset limit (GET /api/license/usage).
export const getLicenseUsageThunk = createAsyncThunk(
    "license/getUsage",
    async (_, { rejectWithValue }) => {
        try {
            return await getLicenseUsage();
        } catch (err) {
            return rejectWithValue(apiErrorDetail(err, err.message));
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
                apiErrorDetail(err, err?.message || t("Failed to activate license"))
            );
        }
    }
);

// The status fields of an API answer (LicenseStatusResponse) as slice state.
function applyStatus(data) {
    return {
        isValid: !!data.valid,
        planCode: data.plan_code ?? null,
        planName: data.plan_name ?? null,
        isPilotMode: !!data.is_pilot_mode,
        maxAssets: data.max_assets ?? null,
        addonPacks: data.addon_packs ?? 0,
        expiresAt: data.expires_at ?? null,
        lastContactAt: data.last_contact_at ?? null,
        offline: !!data.offline,
        offlinePilot: !!data.offline_pilot,
        offlinePilotUntil: data.offline_pilot_until ?? null,
        offlineLicense: !!data.offline_license,
        offlineUntil: data.offline_until ?? null,
        message: data.message ?? "",
    };
}

// =====================
// Slice
// =====================
const licenseSlice = createSlice({
    name: "license",
    initialState: {
        // اطلاعات لایسنس فعال (GET /api/license/status)
        isValid: false,
        planCode: null,
        planName: null,
        isPilotMode: false,
        maxAssets: null,          // null = unlimited
        addonPacks: 0,
        expiresAt: null,
        lastContactAt: null,      // when the license server last signed an answer
        offline: false,           // the license server cannot be reached right now
        offlinePilot: false,      // no contact for > 48h: pilot entitlement until offlinePilotUntil
        offlinePilotUntil: null,
        offlineLicense: false,    // an offline (air-gapped) license file is installed
        offlineUntil: null,       // ...valid until
        message: "",
        // The inventory against the limit (GET /api/license/usage):
        // { used, max_assets, unlimited, over_limit, remaining, licensed_through_id }
        usage: null,

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
            Object.assign(state, applyStatus({}));
            state.usage = null;
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
                Object.assign(state, applyStatus(action.payload));
                state.isInitialized = true;
            })
            .addCase(getLicenseUsageThunk.fulfilled, (state, action) => {
                state.usage = action.payload;
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
                Object.assign(state, applyStatus(action.payload));
                state.successMessage = t("License activated successfully!");
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
