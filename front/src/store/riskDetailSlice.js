import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api";

/**
 * Per-asset risk detail: GET /api/risk/assets/{id}, plus the audit findings
 * list chained off the audit_id that response carries.
 *
 * The findings live in the auditing module and are guarded by AUDITING read —
 * a user with only RISK permission gets a 403 there. That is not a failure of
 * the page, so findings errors are captured separately and the rest still
 * renders.
 */
export const fetchAssetRiskDetail = createAsyncThunk(
    "riskDetail/fetch",
    async (assetId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/risk/assets/${assetId}`);
            const detail = res.data || {};

            const auditId = detail.risk_score?.audit_id;
            if (!auditId) {
                return { detail, findings: [], findingsError: null };
            }

            try {
                const findingsRes = await api.get(
                    `/api/audit/sessions/${auditId}/results`
                );
                return { detail, findings: findingsRes.data || [], findingsError: null };
            } catch (err) {
                const status = err.response?.status;
                return {
                    detail,
                    findings: [],
                    findingsError:
                        status === 403
                            ? "Audit findings need the Auditing module permission."
                            : err.response?.data?.detail || err.message,
                };
            }
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || err.message);
        }
    }
);

const riskDetailSlice = createSlice({
    name: "riskDetail",
    initialState: {
        detail: null,
        findings: [],
        findingsError: null,
        isLoading: false,
        error: null,
    },
    reducers: {
        clearRiskDetail(state) {
            state.detail = null;
            state.findings = [];
            state.findingsError = null;
            state.error = null;
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(fetchAssetRiskDetail.pending, (state) => {
                state.isLoading = true;
                state.error = null;
            })
            .addCase(fetchAssetRiskDetail.fulfilled, (state, action) => {
                state.isLoading = false;
                state.detail = action.payload.detail;
                state.findings = action.payload.findings;
                state.findingsError = action.payload.findingsError;
            })
            .addCase(fetchAssetRiskDetail.rejected, (state, action) => {
                state.isLoading = false;
                state.error = action.payload;
            });
    },
});

export const { clearRiskDetail } = riskDetailSlice.actions;
export default riskDetailSlice.reducer;
