import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api.js";

// ===========================
// ERROR NORMALIZATION
// ===========================

/**
 * Always returns a plain string error message.
 *
 * Backend SSH/connection errors return `detail` as an object
 * (SSHConnectionError.to_dict() → { error_type, message, device_ip, ... }).
 * Storing that object in state.error and rendering it as a React child
 * silently breaks the error banner, so the user sees "no error" even on a
 * genuine 401. Flatten it to a string here so every banner renders.
 */
const getErrorMessage = (error, fallback) => {
    const detail = error?.response?.data?.detail;
    if (typeof detail === "string") return detail;
    if (detail && typeof detail === "object") return detail.message || detail.error_type || fallback;
    return error?.message || fallback;
};

// ===========================
// DEVICE TYPE → API PATH MAP
// ===========================

/**
 * Maps any UI device type to its correct backend API path segment.
 *
 * UI Device Types (19 total) → API paths (7 total):
 *   linux   → linux-ubuntu-24, linux-ubuntu-22, linux-ubuntu-20,
 *              linux-redhat-10, linux-redhat-9, linux-redhat-8,
 *              linux-rocky-10, linux-rocky-9, linux-rocky-8
 *   cisco   → cisco
 *   fortinet→ fortinet
 *   apache  → apache
 *   mongodb → mongodb
 *   mssql   → mssql-2016, mssql-2019, mssql-2022
 *   windows → windows-2016, windows-2022, windows-2025
 */
const DEVICE_API_PATH_MAP = {
    // Linux family
    "linux-ubuntu-24": "linux",
    "linux-ubuntu-22": "linux",
    "linux-ubuntu-20": "linux",
    "linux-redhat-10": "linux",
    "linux-redhat-9":  "linux",
    "linux-redhat-8":  "linux",
    "linux-rocky-10":  "linux",
    "linux-rocky-9":   "linux",
    "linux-rocky-8":   "linux",

    // Cisco family
    "cisco": "cisco",

    // Fortinet family
    "fortinet": "fortinet",

    // Apache family
    "apache": "apache",

    // MongoDB family
    "mongodb": "mongodb",

    // MSSQL family
    "mssql-2016": "mssql",
    "mssql-2019": "mssql",
    "mssql-2022": "mssql",

    // Windows family
    "windows-2016": "windows",
    "windows-2022": "windows",
    "windows-2025": "windows",
};

/**
 * Returns the backend API path segment for a given UI device type.
 * Falls back gracefully for unknown types.
 */
const getDeviceApiPath = (deviceType) => {
    if (!deviceType) return "cisco";
    return DEVICE_API_PATH_MAP[deviceType] || deviceType;
};

// ===========================
// HELPER: HUMAN-READABLE NAME
// ===========================

export const getDeviceName = (deviceType) => {
    const names = {
        // Linux family
        "linux-ubuntu-24":  "Ubuntu 24.04 LTS",
        "linux-ubuntu-22":  "Ubuntu 22.04 LTS",
        "linux-ubuntu-20":  "Ubuntu 20.04 LTS",
        "linux-redhat-10":  "Red Hat Enterprise Linux 10",
        "linux-redhat-9":   "Red Hat Enterprise Linux 9",
        "linux-redhat-8":   "Red Hat Enterprise Linux 8",
        "linux-rocky-10":   "Rocky Linux 10",
        "linux-rocky-9":    "Rocky Linux 9",
        "linux-rocky-8":    "Rocky Linux 8",

        // Bare-type fallbacks for sessions with no sub_device_type
        "linux":            "Linux Server",
        "mssql":            "SQL Server",
        "windows":          "Windows Server",

        // Cisco
        "cisco":            "Cisco Router/Switch",

        // Fortinet
        "fortinet":         "FortiGate Firewall",

        // Apache
        "apache":           "Apache Web Server",

        // MongoDB
        "mongodb":          "MongoDB",

        // MSSQL
        "mssql-2016":       "SQL Server 2016",
        "mssql-2019":       "SQL Server 2019",
        "mssql-2022":       "SQL Server 2022",

        // Windows
        "windows-2016":     "Windows Server 2016",
        "windows-2022":     "Windows Server 2022",
        "windows-2025":     "Windows Server 2025",
    };
    return names[deviceType] || deviceType || "Unknown Device";
};

// ===========================
// HELPER: CREDENTIAL PAYLOAD
// ===========================

/**
 * Builds the correct credential payload object based on device type.
 *
 * Linux / Apache:
 *   { ssh_username, ssh_password, sudo_password? }
 *
 * Cisco:
 *   { ssh_username, ssh_password, ssh_secret? }
 *
 * Fortinet:
 *   { ssh_username, ssh_password, vdom? }
 *
 * MongoDB:
 *   { ssh_username, ssh_password, mongo_username?, mongo_password?, mongo_port? }
 *
 * MSSQL:
 *   { mssql_username, mssql_password, mssql_port? }
 *
 * Windows:
 *   { windows_username, windows_password, winrm_port?, transport? }
 */
export const buildCredentialsPayload = (deviceType, credentials) => {
    const apiPath = getDeviceApiPath(deviceType);

    switch (apiPath) {
        case "linux":
        case "apache":
            return {
                ssh_username: credentials.ssh_username,
                ssh_password: credentials.ssh_password,
                ssh_port:     credentials.ssh_port || 22,
                ...(credentials.sudo_password && { sudo_password: credentials.sudo_password }),
            };

        case "cisco":
            return {
                ssh_username: credentials.ssh_username,
                ssh_password: credentials.ssh_password,
                ssh_port:     credentials.ssh_port || 22,
                ...(credentials.ssh_secret && { ssh_secret: credentials.ssh_secret }),
            };

        case "fortinet":
            return {
                ssh_username: credentials.ssh_username,
                ssh_password: credentials.ssh_password,
                ssh_port:     credentials.ssh_port || 22,
                ...(credentials.vdom && { vdom: credentials.vdom }),
            };

        case "mongodb":
            return {
                ssh_username: credentials.ssh_username,
                ssh_password: credentials.ssh_password,
                ssh_port:     credentials.ssh_port || 22,
                ...(credentials.mongo_username && { mongo_username: credentials.mongo_username }),
                ...(credentials.mongo_password && { mongo_password: credentials.mongo_password }),
                ...(credentials.mongo_port     && { mongo_port:     credentials.mongo_port }),
            };

        case "mssql":
            return {
                mssql_username: credentials.mssql_username,
                mssql_password: credentials.mssql_password,
                mssql_port:     credentials.mssql_port || 1433,
            };

        case "windows":
            return {
                windows_username: credentials.windows_username,
                windows_password: credentials.windows_password,
                winrm_port:       credentials.winrm_port  || 5986,
                transport:        credentials.transport    || "ntlm",
            };

        default:
            // Generic SSH fallback
            return {
                ssh_username: credentials.ssh_username,
                ssh_password: credentials.ssh_password,
                ssh_port:     credentials.ssh_port || 22,
            };
    }
};

// ===========================
// ASYNC THUNKS
// ===========================

/**
 * Fix All Flow - Step 1: Execute audit with device type
 * POST /api/audit/{device}/execute
 */
export const executeAuditWithDevice = createAsyncThunk(
    "hardening/executeAudit",
    async ({ deviceType, assetId, credentials, jobName }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const endpoint = `/api/audit/${apiPath}/execute`;

            const credPayload = buildCredentialsPayload(deviceType, credentials);

            const payload = {
                asset_id: assetId,
                ...credPayload,
                ...(jobName && { job_name: jobName }),
                ...(apiPath === "linux" && deviceType?.startsWith("linux-") && { sub_device_type: deviceType }),
            };

            const response = await api.post(endpoint, payload);
            return { ...response.data, device_type: deviceType };
        } catch (error) {
            return rejectWithValue(
                getErrorMessage(error, "Failed to start audit")
            );
        }
    }
);

/**
 * Fix All Flow - Step 2: Check session status (polling)
 * GET /api/audit/{device}/sessions/{id}
 */
export const checkHardeningSessionStatus = createAsyncThunk(
    "hardening/checkSessionStatus",
    async ({ sessionId, deviceType }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const response = await api.get(
                `/api/audit/${apiPath}/sessions/${sessionId}`
            );
            return response.data;
        } catch (error) {
            return rejectWithValue(
                getErrorMessage(error, "Failed to check session status")
            );
        }
    }
);

/**
 * Fix Unsuccessful Flow - Fetch audit sessions for ALL device families
 * GET /api/audit/{device}/sessions
 */
export const fetchAuditSessions = createAsyncThunk(
    "hardening/fetchAuditSessions",
    async (_arg, { rejectWithValue }) => {
        try {
            // Fetch from every API family in parallel
            const families = ["cisco", "fortinet", "linux", "apache", "mongodb", "mssql", "windows"];

            const results = await Promise.allSettled(
                families.map((family) =>
                    api.get(`/api/audit/${family}/sessions`)
                )
            );

            const allSessions = [];
            results.forEach((result, idx) => {
                if (result.status === "fulfilled") {
                    const data = result.value.data;
                    if (Array.isArray(data)) {
                        allSessions.push(...data);
                    }
                } else {
                    console.warn(
                        `Failed to fetch ${families[idx]} sessions:`,
                        result.reason?.message
                    );
                }
            });

            return allSessions;
        } catch (error) {
            return rejectWithValue(
                getErrorMessage(error, "Failed to fetch audit sessions")
            );
        }
    }
);

/**
 * Fix Unsuccessful Flow - Fetch audit results for a session
 * GET /api/audit/{device}/sessions/{id}/results
 */
export const fetchAuditResults = createAsyncThunk(
    "hardening/fetchAuditResults",
    async ({ sessionId, deviceType }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const response = await api.get(
                `/api/audit/${apiPath}/sessions/${sessionId}/results`
            );
            return response.data;
        } catch (error) {
            return rejectWithValue(
                getErrorMessage(error, "Failed to fetch audit results")
            );
        }
    }
);

/**
 * Fix Single - Preview hardening for a single check
 * POST /api/hardening/{device}/preview
 * (Supported for cisco and fortinet; linux/apache/mongodb use execute-single directly)
 */
export const previewHardenCheck = createAsyncThunk(
    "hardening/previewCheck",
    async ({ auditResultId, checkId, deviceType, parameters }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            // Cisco and Fortinet use audit_result_id (int from AuditResult row).
            // All other families use check_id (string like "LNX-L1-5.2.10").
            const isCiscoOrFortinet = apiPath === "cisco" || apiPath === "fortinet";
            const payload = isCiscoOrFortinet
                ? { audit_result_id: auditResultId, parameters: parameters || {} }
                : { check_id: checkId, parameters: parameters || {} };
            const res = await api.post(`/api/hardening/${apiPath}/preview`, payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                getErrorMessage(err, "Failed to preview hardening")
            );
        }
    }
);

/**
 * Fix Single - Execute hardening for a single check
 *
 * Cisco / Fortinet  → POST /api/hardening/{device}/execute
 * Linux / Apache / MongoDB → POST /api/hardening/{device}/execute-single
 * MSSQL / Windows   → POST /api/hardening/{device}/execute-single
 */
export const executeHardenCheck = createAsyncThunk(
    "hardening/executeCheck",
    async ({ actionId, checkId, assetId, sessionId, deviceType, credentials, parameters, skipBackup = false }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const credPayload = buildCredentialsPayload(deviceType, credentials);

            // Cisco and Fortinet use action_id based execute
            if (apiPath === "cisco" || apiPath === "fortinet") {
                const endpoint = `/api/hardening/${apiPath}/execute`;
                const payload = {
                    action_id: actionId,
                    ...credPayload,
                    parameters: parameters || {},
                    skip_backup: skipBackup,
                };
                const res = await api.post(endpoint, payload);
                return res.data;
            }

            // Linux, Apache, MongoDB, MSSQL, Windows use execute-single with check_id
            const endpoint = `/api/hardening/${apiPath}/execute-single`;
            const payload = {
                asset_id: assetId,
                check_id: checkId,
                ...credPayload,
                parameters: parameters || {},
                ...(sessionId != null && { session_id: sessionId }),
                // Pass the known distro variant so the backend skips live distro
                // detection (one fewer SSH round-trip). Only meaningful for Linux.
                ...(apiPath === "linux" && deviceType?.startsWith("linux-") && { sub_device_type: deviceType }),
            };
            const res = await api.post(endpoint, payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                getErrorMessage(err, "Failed to execute hardening")
            );
        }
    }
);

/**
 * Harden All - Get required parameters for a session
 * GET /api/hardening/{device}/session/{id}/parameters
 */
export const fetchRequiredParameters = createAsyncThunk(
    "hardening/fetchParameters",
    async ({ sessionId, deviceType }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const response = await api.get(
                `/api/hardening/${apiPath}/session/${sessionId}/parameters`
            );
            return response.data;
        } catch (error) {
            return rejectWithValue(
                getErrorMessage(error, "Failed to fetch parameters")
            );
        }
    }
);

/**
 * Harden All - Auto harden with CIS defaults
 * POST /api/hardening/{device}/auto-harden-defaults
 */
export const autoHardenWithDefaults = createAsyncThunk(
    "hardening/autoHardenDefaults",
    async ({ sessionId, assetId, deviceType, credentials, skipBackup = false }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const credPayload = buildCredentialsPayload(deviceType, credentials);

            const payload = {
                session_id: sessionId,
                asset_id:   assetId,
                ...credPayload,
                // Cisco/Fortinet expect confirmed flag
                ...(["cisco", "fortinet"].includes(apiPath) && {
                    audit_session_id: sessionId,
                    confirmed: true,
                    skip_backup: skipBackup,
                }),
            };

            const response = await api.post(
                `/api/hardening/${apiPath}/auto-harden-defaults`,
                payload
            );
            return response.data;
        } catch (error) {
            return rejectWithValue(
                getErrorMessage(error, "Failed to auto harden")
            );
        }
    }
);

/**
 * Harden All - Batch execute selected checks
 * POST /api/hardening/{device}/batch-execute
 *
 * Cisco/Fortinet use check_ids[] + parameters{}
 * Linux/Apache/MongoDB/MSSQL/Windows use checks[{check_id, parameters}]
 */
export const discoverFortinetVdoms = createAsyncThunk(
    "hardening/discoverFortinetVdoms",
    // mode: "audit" (default) hits the audit endpoint (AUDIT read) — used by the
    // audit-driven forms. mode: "hardening" hits the hardening endpoint
    // (HARDENING read) so hardening-only users can list VDOMs too.
    async ({ asset_id, ssh_username, ssh_password, ssh_port = 22, mode = "audit" }, { rejectWithValue }) => {
        try {
            const endpoint = mode === "hardening"
                ? "/api/hardening/fortinet/vdoms/discover"
                : "/api/audit/fortinet/vdoms/discover";
            const res = await api.post(endpoint, {
                asset_id, ssh_username, ssh_password, ssh_port,
            });
            return res.data; // { asset_id, asset_name, target_ip, vdoms: string[] }
        } catch (err) {
            return rejectWithValue(getErrorMessage(err, "VDOM discovery failed"));
        }
    }
);

/**
 * Fetch the list of FortiGate check IDs that have an auto-fix template.
 * Checks NOT in this list are manual/review-only — previewing them returns a
 * 400 ("must be applied manually"), so the UI shows a "Manual" badge instead
 * of a dead-end "Harden" button.
 * GET /api/hardening/fortinet/templated-checks
 */
export const fetchFortinetTemplatedChecks = createAsyncThunk(
    "hardening/fetchFortinetTemplatedChecks",
    async (_arg, { rejectWithValue }) => {
        try {
            const res = await api.get("/api/hardening/fortinet/templated-checks");
            return res.data; // string[] of check numbers
        } catch (err) {
            return rejectWithValue(
                getErrorMessage(err, "Failed to fetch auto-fixable checks")
            );
        }
    }
);

/**
 * Fetch read-only remediation guidance for a manual (non-auto-fixable) FortiGate
 * check: the exact CLI commands + human guidance from the catalog. Powers the
 * "View Fix" modal — NO SSH / no device execution.
 * GET /api/hardening/fortinet/manual-guidance/{check_id}
 */
export const fetchFortinetManualGuidance = createAsyncThunk(
    "hardening/fetchFortinetManualGuidance",
    async (arg, { rejectWithValue }) => {
        // Accepts a bare checkId (legacy) or { checkId, resultId }. With a
        // resultId, evidence-sourced parameters (e.g. failing Policy IDs) come
        // back with their options pre-populated from that audit result.
        const { checkId, resultId } = typeof arg === "object" && arg !== null ? arg : { checkId: arg };
        try {
            const query = resultId ? `?audit_result_id=${resultId}` : "";
            const res = await api.get(`/api/hardening/fortinet/manual-guidance/${checkId}${query}`);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                getErrorMessage(err, "Failed to load remediation guidance")
            );
        }
    }
);

/**
 * Fetch the LIVE device objects behind a smart-dropdown parameter (antivirus
 * profiles, IPS sensors, application lists, interfaces, admin accounts, ...).
 * Needs SSH credentials — read-only `show` command on the device.
 * POST /api/hardening/fortinet/device-options/{audit_result_id}
 */
export const fetchFortinetDeviceOptions = createAsyncThunk(
    "hardening/fetchFortinetDeviceOptions",
    async ({ auditResultId, optionType, credentials }, { rejectWithValue }) => {
        try {
            const credPayload = buildCredentialsPayload("fortinet", credentials);
            const res = await api.post(
                `/api/hardening/fortinet/device-options/${auditResultId}`,
                {
                    option_type: optionType,
                    ssh_username: credPayload.ssh_username,
                    ssh_password: credPayload.ssh_password,
                    ssh_port: credPayload.ssh_port,
                }
            );
            return res.data; // { option_type, options: string[] }
        } catch (err) {
            return rejectWithValue(
                getErrorMessage(err, "Failed to load options from the device")
            );
        }
    }
);

/**
 * Execute a MANUAL FortiGate check's remediation over SSH. Renders the
 * parameterised template with the operator's values, pushes it in the control's
 * scope, and returns the raw device output/errors. NO verification is performed.
 * POST /api/hardening/fortinet/manual-execute
 */
export const executeFortinetManualFix = createAsyncThunk(
    "hardening/executeFortinetManualFix",
    async ({ auditResultId, parameters, credentials, skipBackup = true }, { rejectWithValue }) => {
        try {
            const credPayload = buildCredentialsPayload("fortinet", credentials);
            const payload = {
                audit_result_id: auditResultId,
                ...credPayload,
                parameters: parameters || {},
                skip_backup: skipBackup,
            };
            const res = await api.post("/api/hardening/fortinet/manual-execute", payload);
            return res.data;
        } catch (err) {
            return rejectWithValue(
                getErrorMessage(err, "Failed to execute manual remediation")
            );
        }
    }
);

export const batchExecuteChecks = createAsyncThunk(
    "hardening/batchExecute",
    async ({ sessionId, assetId, deviceType, credentials, checkIds, checks, parameters, skipBackup = false }, { rejectWithValue }) => {
        try {
            const apiPath = getDeviceApiPath(deviceType);
            const credPayload = buildCredentialsPayload(deviceType, credentials);

            let payload;

            if (apiPath === "cisco" || apiPath === "fortinet") {
                // Cisco / Fortinet: flat check_ids + shared parameters object
                payload = {
                    audit_session_id: sessionId,
                    check_ids: checkIds || [],
                    parameters: parameters || {},
                    ...credPayload,
                    skip_backup: skipBackup,
                };
            } else {
                // Linux / Apache / MongoDB / MSSQL / Windows: checks array with per-check params
                payload = {
                    session_id: sessionId,
                    asset_id:   assetId,
                    ...credPayload,
                    checks: checks || (checkIds || []).map((id) => ({
                        check_id:   id,
                        parameters: (parameters && parameters[id]) || {},
                    })),
                };
            }

            const response = await api.post(
                `/api/hardening/${apiPath}/batch-execute`,
                payload
            );
            return response.data;
        } catch (error) {
            return rejectWithValue(
                getErrorMessage(error, "Failed to batch execute")
            );
        }
    }
);

// ===========================
// INITIAL STATE
// ===========================

const initialState = {
    // Session management
    sessions:        [],
    auditSessions:   [],
    activeSessionId: null,
    currentSession:  null,

    // Device
    deviceType: null, // one of the 19 UI device type strings

    // Wizard state
    wizardMode:    null, // 'fix-all' | 'fix-unsuccessful'
    wizardStep:    1,
    pollingActive: false,

    // Data
    cisChecks:          [],
    failedChecks:       [],
    auditResults:       [],
    sessionStatus:      null,
    requiredParameters: null,
    previewData:        null,

    // VDOM discovery (FortiGate)
    vdomDiscovery: { vdoms: null, isDiscovering: false, error: null },

    // FortiGate check IDs that have an auto-fix template (used to gate the
    // "Harden" button vs a "Manual" badge in the results table). Empty until
    // fetched; an empty list means "don't gate" so we never hide Harden by mistake.
    fortinetTemplatedChecks: [],

    // Loading states
    isLoading:       false,
    isExecuting:     false,
    isFetchingParams: false,

    // Messages
    error:          null,
    message:        null,
    successMessage: null,
};

// ===========================
// SLICE
// ===========================

const hardeningSlice = createSlice({
    name: "hardening",
    initialState,
    reducers: {
        clearMessages: (state) => {
            state.error          = null;
            state.message        = null;
            state.successMessage = null;
        },

        clearCurrentSession: (state) => {
            state.currentSession = null;
            state.cisChecks      = [];
            state.failedChecks   = [];
            state.auditResults   = [];
            state.sessionStatus  = null;
        },

        setActiveSession: (state, action) => {
            state.activeSessionId = action.payload;
        },

        clearActiveSession: (state) => {
            state.activeSessionId = null;
        },

        setPollingActive: (state, action) => {
            state.pollingActive = action.payload;
        },

        setDeviceType: (state, action) => {
            state.deviceType = action.payload;
        },

        clearDeviceType: (state) => {
            state.deviceType = null;
        },

        setWizardMode: (state, action) => {
            state.wizardMode = action.payload;
            state.wizardStep = 1;
        },

        setWizardStep: (state, action) => {
            state.wizardStep = action.payload;
        },

        resetWizard: (state) => {
            state.wizardMode        = null;
            state.wizardStep        = 1;
            state.currentSession    = null;
            state.cisChecks         = [];
            state.failedChecks      = [];
            state.auditResults      = [];
            state.sessionStatus     = null;
            state.requiredParameters = null;
            state.previewData       = null;
            state.deviceType        = null;
            state.error             = null;
            state.message           = null;
            state.successMessage    = null;
            state.pollingActive     = false;
        },

        clearRequiredParameters: (state) => {
            state.requiredParameters = null;
        },

        clearPreviewData: (state) => {
            state.previewData = null;
        },
        clearVdomDiscovery: (state) => {
            state.vdomDiscovery = { vdoms: null, isDiscovering: false, error: null };
        },

        // Reflect a successful harden in the loaded results list immediately —
        // no page reload / re-audit round-trip. `verified: true` (auto-fix whose
        // post-fix verification passed; the backend has already flipped the DB
        // row to PASS) turns the row green with a "Hardened" badge.
        // `verified: false` (manual remediation — never auto-verified) keeps the
        // FAIL status but tags the row "applied, re-audit to verify".
        markCheckHardened: (state, action) => {
            const { resultId, verified, targetVdom } = action.payload || {};
            const apply = (check) => {
                if (!check || check.id !== resultId) return;
                if (verified) {
                    check.status = "PASS";
                    check.justHardened = true;
                } else {
                    check.manualApplied = true;
                }
                if (targetVdom) check.hardenedVdom = targetVdom;
            };
            (state.cisChecks || []).forEach(apply);
            (state.auditResults || []).forEach(apply);
            if (verified) {
                state.failedChecks = (state.failedChecks || []).filter(
                    (c) => c.id !== resultId
                );
            }
        },
    },

    extraReducers: (builder) => {

        // ── executeAuditWithDevice ─────────────────────────────
        builder
            .addCase(executeAuditWithDevice.pending, (state) => {
                state.isLoading = true;
                state.error     = null;
                state.message   = null;
            })
            .addCase(executeAuditWithDevice.fulfilled, (state, action) => {
                state.isLoading      = false;
                state.currentSession = action.payload;
                state.activeSessionId = action.payload.session_id;
                state.deviceType     = action.payload.device_type;
                state.sessionStatus  = action.payload.status || null;
                state.pollingActive  = true;
                state.message        = "Audit started successfully.";
            })
            .addCase(executeAuditWithDevice.rejected, (state, action) => {
                state.isLoading     = false;
                state.error         = action.payload;
                state.pollingActive = false;
            });

        // ── checkHardeningSessionStatus ───────────────────────
        builder
            .addCase(checkHardeningSessionStatus.pending, (state) => {
                state.isLoading = true;
            })
            .addCase(checkHardeningSessionStatus.fulfilled, (state, action) => {
                state.isLoading      = false;
                state.currentSession = action.payload;
                state.sessionStatus  = action.payload.status || null;

                if (
                    action.payload.status === "completed" ||
                    action.payload.status === "failed"
                ) {
                    state.pollingActive = false;
                }
            })
            .addCase(checkHardeningSessionStatus.rejected, (state, action) => {
                state.isLoading     = false;
                state.error         = action.payload;
                state.pollingActive = false;
            });

        // ── fetchAuditSessions ────────────────────────────────
        builder
            .addCase(fetchAuditSessions.pending, (state) => {
                state.isLoading = true;
                state.error     = null;
            })
            .addCase(fetchAuditSessions.fulfilled, (state, action) => {
                state.isLoading    = false;
                state.auditSessions = action.payload;
            })
            .addCase(fetchAuditSessions.rejected, (state, action) => {
                state.isLoading = false;
                state.error     = action.payload;
            });

        // ── fetchAuditResults ─────────────────────────────────
        builder
            .addCase(fetchAuditResults.pending, (state) => {
                state.isLoading = true;
                state.error     = null;
            })
            .addCase(fetchAuditResults.fulfilled, (state, action) => {
                state.isLoading    = false;
                // Carry "just hardened" flags across the refetch so the badge
                // set by markCheckHardened doesn't vanish when the list refreshes
                // after the modal closes. (Verified fixes come back as PASS from
                // the server anyway; the flags only style the row.)
                const prevFlags = {};
                (state.cisChecks || []).forEach((c) => {
                    if (c.justHardened || c.manualApplied) {
                        prevFlags[c.id] = {
                            justHardened:  c.justHardened,
                            manualApplied: c.manualApplied,
                            hardenedVdom:  c.hardenedVdom,
                        };
                    }
                });
                const merged = (action.payload || []).map((c) =>
                    prevFlags[c.id] ? { ...c, ...prevFlags[c.id] } : c
                );
                state.auditResults = merged;
                state.cisChecks    = merged;
                state.failedChecks = merged.filter((check) => {
                    const s = check.status?.toString().toUpperCase();
                    return s === "FAIL" || s === "FAILED";
                });
            })
            .addCase(fetchAuditResults.rejected, (state, action) => {
                state.isLoading = false;
                state.error     = action.payload;
            });

        // ── previewHardenCheck ────────────────────────────────
        builder
            .addCase(previewHardenCheck.pending, (state) => {
                state.isLoading  = true;
                state.error      = null;
                state.previewData = null;
            })
            .addCase(previewHardenCheck.fulfilled, (state, action) => {
                state.isLoading  = false;
                state.previewData = action.payload;
            })
            .addCase(previewHardenCheck.rejected, (state, action) => {
                state.isLoading = false;
                state.error     = action.payload;
            });

        // ── executeHardenCheck ────────────────────────────────
        builder
            .addCase(executeHardenCheck.pending, (state) => {
                state.isExecuting = true;
                state.error       = null;
                state.successMessage = null;
            })
            .addCase(executeHardenCheck.fulfilled, (state, action) => {
                state.isExecuting    = false;
                state.successMessage = "Check hardened successfully!";
            })
            .addCase(executeHardenCheck.rejected, (state, action) => {
                state.isExecuting = false;
                state.error       = action.payload;
            });

        // ── fetchRequiredParameters ───────────────────────────
        builder
            .addCase(fetchRequiredParameters.pending, (state) => {
                state.isFetchingParams  = true;
                state.error             = null;
                state.requiredParameters = null;
            })
            .addCase(fetchRequiredParameters.fulfilled, (state, action) => {
                state.isFetchingParams  = false;
                state.requiredParameters = action.payload;
            })
            .addCase(fetchRequiredParameters.rejected, (state, action) => {
                state.isFetchingParams = false;
                state.error            = action.payload;
            });

        // ── autoHardenWithDefaults ────────────────────────────
        builder
            .addCase(autoHardenWithDefaults.pending, (state) => {
                state.isExecuting = true;
                state.error       = null;
                state.successMessage = null;
            })
            .addCase(autoHardenWithDefaults.fulfilled, (state, action) => {
                state.isExecuting    = false;
                state.successMessage = "Hardening applied successfully!";
            })
            .addCase(autoHardenWithDefaults.rejected, (state, action) => {
                state.isExecuting = false;
                state.error       = action.payload;
            });

        // ── batchExecuteChecks ────────────────────────────────
        builder
            .addCase(batchExecuteChecks.pending, (state) => {
                state.isExecuting = true;
                state.error       = null;
                state.successMessage = null;
            })
            .addCase(batchExecuteChecks.fulfilled, (state, action) => {
                state.isExecuting    = false;
                state.successMessage = "Batch hardening completed!";
            })
            .addCase(batchExecuteChecks.rejected, (state, action) => {
                state.isExecuting = false;
                state.error       = action.payload;
            });

        // ── discoverFortinetVdoms ──────────────────────────────
        builder
            .addCase(discoverFortinetVdoms.pending, (state) => {
                state.vdomDiscovery = { vdoms: null, isDiscovering: true, error: null };
            })
            .addCase(discoverFortinetVdoms.fulfilled, (state, action) => {
                state.vdomDiscovery = {
                    vdoms: action.payload.vdoms || [],
                    isDiscovering: false,
                    error: null,
                };
            })
            .addCase(discoverFortinetVdoms.rejected, (state, action) => {
                state.vdomDiscovery = {
                    vdoms: null,
                    isDiscovering: false,
                    error: action.payload,
                };
            });

        // ── fetchFortinetTemplatedChecks ───────────────────────
        builder
            .addCase(fetchFortinetTemplatedChecks.fulfilled, (state, action) => {
                state.fortinetTemplatedChecks = Array.isArray(action.payload)
                    ? action.payload
                    : [];
            })
            .addCase(fetchFortinetTemplatedChecks.rejected, (state) => {
                // Non-fatal: leave the list empty so every check keeps its
                // "Harden" button (fail open — never hide the action on error).
                state.fortinetTemplatedChecks = [];
            });
    },
});

// ===========================
// EXPORTS
// ===========================

export const {
    clearMessages,
    clearCurrentSession,
    setActiveSession,
    clearActiveSession,
    setPollingActive,
    setDeviceType,
    clearDeviceType,
    setWizardMode,
    setWizardStep,
    resetWizard,
    clearRequiredParameters,
    clearPreviewData,
    clearVdomDiscovery,
    markCheckHardened,
} = hardeningSlice.actions;

export default hardeningSlice.reducer;