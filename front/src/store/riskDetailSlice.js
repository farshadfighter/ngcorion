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

/**
 * Score history for this asset, newest first. Every recalculation writes a row
 * carrying the trigger that caused it and, for audit-driven ones, the audit
 * session id — which is what makes the per-audit view possible.
 */
export const fetchAssetRiskHistory = createAsyncThunk(
    "riskDetail/fetchHistory",
    async (assetId, { rejectWithValue }) => {
        try {
            const res = await api.get(`/api/risk/assets/${assetId}/history`, {
                params: { limit: 100 },
            });
            return res.data || [];
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || err.message);
        }
    }
);

/**
 * Zones for the edit dialog's dropdown. Kept here rather than in riskSlice so
 * the detail page can load them without pulling in the whole dashboard fetch.
 */
export const fetchZonesForDetail = createAsyncThunk(
    "riskDetail/fetchZones",
    async (_, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/risk/zones");
            return res.data || [];
        } catch (err) {
            return rejectWithValue(err.response?.data?.detail || err.message);
        }
    }
);

/**
 * PUT /api/risk/assets/{id}/profile — sets criticality and/or zone.
 *
 * The backend recalculates the score as part of this call and returns both the
 * profile and the fresh risk_score, so the page updates from the response
 * instead of refetching.
 *
 * Needs RISK:write. `zone_id: null` deliberately clears the zone, so it is sent
 * whenever the field was touched rather than being stripped as empty.
 */
export const updateAssetProfile = createAsyncThunk(
    "riskDetail/updateProfile",
    async ({ assetId, criticalityLevel, zoneId, reason }, { rejectWithValue }) => {
        try {
            const body = {};
            if (criticalityLevel !== undefined) {
                body.criticality_level = criticalityLevel;
            }
            if (zoneId !== undefined) body.zone_id = zoneId;
            if (reason) body.reason = reason;
            const res = await api.put(
                `/api/risk/assets/${assetId}/profile`,
                body
            );
            return res.data;
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
        zones: [],
        isSavingProfile: false,
        profileError: null,
        history: [],
        historyError: null,
        isLoadingHistory: false,
    },
    reducers: {
        clearRiskDetail(state) {
            state.detail = null;
            state.findings = [];
            state.findingsError = null;
            state.error = null;
            state.profileError = null;
            state.history = [];
            state.historyError = null;
        },
        clearProfileError(state) {
            state.profileError = null;
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
            })
            .addCase(fetchZonesForDetail.fulfilled, (state, action) => {
                state.zones = action.payload;
            })
            .addCase(fetchAssetRiskHistory.pending, (state) => {
                state.isLoadingHistory = true;
                state.historyError = null;
            })
            .addCase(fetchAssetRiskHistory.fulfilled, (state, action) => {
                state.isLoadingHistory = false;
                state.history = action.payload;
            })
            .addCase(fetchAssetRiskHistory.rejected, (state, action) => {
                state.isLoadingHistory = false;
                state.historyError = action.payload;
            })
            .addCase(updateAssetProfile.pending, (state) => {
                state.isSavingProfile = true;
                state.profileError = null;
            })
            .addCase(updateAssetProfile.fulfilled, (state, action) => {
                state.isSavingProfile = false;
                if (!state.detail) return;
                const { risk_score: score, profile } = action.payload || {};
                if (score) {
                    state.detail.risk_score = {
                        ...state.detail.risk_score,
                        ...score,
                    };
                }
                // The asset block carries confidentiality_level, which this
                // endpoint does not touch — only the zone label needs syncing,
                // and the profile response gives an id rather than a name.
                if (profile && state.detail.risk_score) {
                    const zone = state.zones.find((z) => z.id === profile.zone_id);
                    state.detail.risk_score.zone_name = zone ? zone.name : null;
                }
            })
            .addCase(updateAssetProfile.rejected, (state, action) => {
                state.isSavingProfile = false;
                state.profileError = action.payload;
            });
    },
});

export const { clearRiskDetail, clearProfileError } = riskDetailSlice.actions;
export default riskDetailSlice.reducer;
