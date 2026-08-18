import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api";

/**
 * System Configuration sections (/api/system/*).
 *
 * Every section behaves the same way — GET to load, PUT to save — so one pair
 * of thunks keyed by section name serves all six rather than six near-identical
 * copies.
 *
 * Two backend behaviours shape this slice:
 *   - Secrets come back masked as "********". Sending that value back unchanged
 *     keeps the stored secret, so the forms can round-trip a masked GET safely.
 *   - A PUT can succeed while the host-level apply step fails; that arrives as
 *     `warning` alongside success:true and must reach the user.
 */
export const fetchSection = createAsyncThunk(
    "systemConfig/fetch",
    async (section, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/system/${section}`);
            return { section, data: res.data };
        } catch (err) {
            return rejectWithValue({
                section,
                message: err.response?.data?.detail || err.message,
            });
        }
    }
);

export const saveSection = createAsyncThunk(
    "systemConfig/save",
    async ({ section, payload }, { rejectWithValue }) => {
        try {
            const res = await api.put(`/api/system/${section}`, payload);
            return { section, data: res.data };
        } catch (err) {
            const detail = err.response?.data?.detail;
            return rejectWithValue({
                section,
                // FastAPI validation errors arrive as a list of objects; flatten
                // them so the dialog can show one readable line.
                message: Array.isArray(detail)
                    ? detail.map((d) => d.msg || String(d)).join(", ")
                    : detail || err.message,
            });
        }
    }
);

/**
 * POST /api/system/{section}/test — SMS and SMTP only.
 *
 * Two things shape the handling: the test runs against the *stored* settings,
 * not the form, so it needs a save first; and a failed delivery still returns
 * HTTP 200 with success:false, so the body decides the outcome, not the status.
 */
export const testSection = createAsyncThunk(
    "systemConfig/test",
    async ({ section, payload }, { rejectWithValue }) => {
        try {
            const res = await api.post(`/api/system/${section}/test`, payload);
            return { section, result: res.data };
        } catch (err) {
            const detail = err.response?.data?.detail;
            return rejectWithValue({
                section,
                message: Array.isArray(detail)
                    ? detail.map((d) => d.msg || String(d)).join(", ")
                    : detail || err.message,
            });
        }
    }
);

/**
 * Certificate upload — multipart, not JSON, and it either carries
 * cert_file (+ optional key_file) or pfx_file (+ pfx_password). The backend
 * rejects both together, so the caller sends one shape or the other.
 */
export const uploadCertificate = createAsyncThunk(
    "systemConfig/uploadCertificate",
    async (formData, { rejectWithValue }) => {
        try {
            const res = await api.post(
                "/api/system/certificate/upload",
                formData,
                { headers: { "Content-Type": "multipart/form-data" } }
            );
            return res.data;
        } catch (err) {
            const detail = err.response?.data?.detail;
            return rejectWithValue(
                Array.isArray(detail)
                    ? detail.map((d) => d.msg || String(d)).join(", ")
                    : detail || err.message
            );
        }
    }
);

export const deleteCertificate = createAsyncThunk(
    "systemConfig/deleteCertificate",
    async (_, { rejectWithValue }) => {
        try {
            const res = await api.delete("/api/system/certificate");
            return res.data;
        } catch (err) {
            return rejectWithValue(
                err.response?.data?.detail || err.message
            );
        }
    }
);

const systemConfigSlice = createSlice({
    name: "systemConfig",
    initialState: {
        sections: {},
        loading: {},
        saving: {},
        errors: {},
        warnings: {},
        testing: {},
        testResults: {},
    },
    reducers: {
        clearSectionError: (state, action) => {
            delete state.errors[action.payload];
            delete state.warnings[action.payload];
        },
        clearTestResult: (state, action) => {
            delete state.testResults[action.payload];
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(fetchSection.pending, (state, action) => {
                state.loading[action.meta.arg] = true;
                delete state.errors[action.meta.arg];
            })
            .addCase(fetchSection.fulfilled, (state, action) => {
                const { section, data } = action.payload;
                state.loading[section] = false;
                // Guard against a non-JSON body (a proxy error page, an HTML
                // login redirect): storing a string here would make every
                // `config?.field` read silently undefined instead of failing.
                if (data && typeof data === "object" && !Array.isArray(data)) {
                    state.sections[section] = data;
                } else {
                    state.errors[section] = "Unexpected response from server.";
                }
            })
            .addCase(fetchSection.rejected, (state, action) => {
                const { section, message } = action.payload || {};
                if (section) {
                    state.loading[section] = false;
                    state.errors[section] = message;
                }
            })
            .addCase(saveSection.pending, (state, action) => {
                const section = action.meta.arg.section;
                state.saving[section] = true;
                delete state.errors[section];
                delete state.warnings[section];
            })
            .addCase(saveSection.fulfilled, (state, action) => {
                const { section, data } = action.payload;
                state.saving[section] = false;
                state.sections[section] = data;
                if (data?.warning) state.warnings[section] = data.warning;
            })
            .addCase(saveSection.rejected, (state, action) => {
                const { section, message } = action.payload || {};
                if (section) {
                    state.saving[section] = false;
                    state.errors[section] = message;
                }
            })
            .addCase(testSection.pending, (state, action) => {
                const section = action.meta.arg.section;
                state.testing[section] = true;
                delete state.testResults[section];
            })
            .addCase(testSection.fulfilled, (state, action) => {
                const { section, result } = action.payload;
                state.testing[section] = false;
                // A delivery failure arrives as 200 + success:false, so the
                // body is what decides whether this went well.
                state.testResults[section] = {
                    success: !!result?.success,
                    message: result?.message || "",
                };
            })
            .addCase(testSection.rejected, (state, action) => {
                const { section, message } = action.payload || {};
                if (section) {
                    state.testing[section] = false;
                    state.testResults[section] = { success: false, message };
                }
            })
            .addCase(uploadCertificate.pending, (state) => {
                state.saving.certificate = true;
                delete state.errors.certificate;
                delete state.warnings.certificate;
            })
            .addCase(uploadCertificate.fulfilled, (state, action) => {
                state.saving.certificate = false;
                // /certificate returns the metadata object directly, unlike the
                // JSON sections which wrap theirs in { config }.
                state.sections.certificate = action.payload?.certificate || null;
                // Installed, but Traefik may not have picked it up.
                if (action.payload?.traefik?.published === false) {
                    state.warnings.certificate = action.payload.traefik.message;
                }
            })
            .addCase(uploadCertificate.rejected, (state, action) => {
                state.saving.certificate = false;
                state.errors.certificate = action.payload;
            })
            .addCase(deleteCertificate.pending, (state) => {
                state.saving.certificate = true;
                delete state.errors.certificate;
                delete state.warnings.certificate;
            })
            .addCase(deleteCertificate.fulfilled, (state, action) => {
                state.saving.certificate = false;
                state.sections.certificate = { has_cert: false };
                if (action.payload?.message) {
                    state.warnings.certificate = action.payload.message;
                }
            })
            .addCase(deleteCertificate.rejected, (state, action) => {
                state.saving.certificate = false;
                state.errors.certificate = action.payload;
            });
    },
});

export const { clearSectionError, clearTestResult } = systemConfigSlice.actions;
export default systemConfigSlice.reducer;
