/**
 * Redux slice: login (and its two-step code step), logout (the server revokes the token), token
 * check and the cached role and permissions. The token is kept in localStorage; the backend re-checks role and permissions on
 * every request.
 */
import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";
import api from "../config/api";
import { t } from "../i18n";

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
                return rejectWithValue(t("Incorrect username or password"));
            }
            if (err.response?.status === 403) {
                return rejectWithValue(t("Account is inactive"));
            }
            if (err.response?.status === 429) {
                return rejectWithValue(
                    err.response?.data?.detail ||
                    t("Too many failed login attempts. Please wait before trying again.")
                );
            }
            if (err.response?.data?.detail) {
                const detail = err.response.data.detail;
                if (typeof detail === "string") return rejectWithValue(detail);
                if (Array.isArray(detail)) return rejectWithValue(detail.map(e => e.msg).join(", "));
            }
            return rejectWithValue(t("Failed to connect to the server"));
        }
    }
);

// Second sign-in step (two-step sign-in on): the password step's mfa_token and a code from the
// authenticator app, or a recovery code, for the session.
export const loginMfa = createAsyncThunk(
    "auth/loginMfa",
    async ({ mfaToken, code }, { rejectWithValue }) => {
        try {
            const response = await api.post("/auth/login/mfa", { mfa_token: mfaToken, code: code.trim() });
            return response.data;
        } catch (err) {
            const detail = err.response?.data?.detail;
            if (err.response?.status === 401 && detail === "The sign-in step has expired. Sign in again.") {
                return rejectWithValue({ expired: true, message: t("The sign-in step has expired. Sign in again.") });
            }
            if (err.response?.status === 401) return rejectWithValue({ message: t("The code is not correct.") });
            if (err.response?.status === 429) {
                return rejectWithValue({ message: t("Too many failed login attempts. Please wait before trying again.") });
            }
            if (err.response?.status === 422) return rejectWithValue({ message: t("Enter the 6-digit code or a recovery code.") });
            return rejectWithValue({ message: t("Failed to connect to the server") });
        }
    }
);

// Validate the stored token against the backend on app load.
// Resolves with the fresh identity/permissions if the token is still valid;
// rejects (→ logout) if it is missing, expired, or otherwise invalid. This is
// what stops an expired token from rendering the dashboard before the first
// real API call bounces the user back to login.
// Server-side logout: the backend revokes this token, so a copy of it stops
// working at once. The local session is cleared whatever the server says
// (offline, already expired), so the user is never stuck signed in.
export const logoutUser = createAsyncThunk("auth/logoutUser", async (_, { dispatch }) => {
    try {
        await api.post("/auth/logout", null, { timeout: 5000 });
    } catch {
        // already invalid or unreachable: nothing more to revoke
    }
    dispatch(authSlice.actions.logout());
});

export const verifyToken = createAsyncThunk(
    "auth/verify",
    async (_, { rejectWithValue }) => {
        const token = localStorage.getItem("token");
        if (!token) {
            return rejectWithValue("no-token");
        }
        try {
            const response = await api.get("/auth/me");
            return response.data;
        } catch (err) {
            return rejectWithValue(err.response?.status || "invalid-token");
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

// A login or second-step answer that carries the session.
const signedIn = (state, data) => {
    state.isLoading   = false;
    state.mfaChallenge = null;
    state.token       = data.access_token;
    state.username    = data.username;
    state.role        = data.role;
    state.permissions = data.permissions || {};
    state.language    = data.language || null;
    state.languageChosen = !!data.language_chosen;
    state.mustChangePassword = !!data.must_change_password;
    state.mfaEnrolmentDue = !!data.mfa_enrolment_due;
    state.recoveryCodesLeft = data.mfa_recovery_codes_left ?? null;

    localStorage.setItem("token",       data.access_token);
    localStorage.setItem("username",    data.username);
    localStorage.setItem("role",        data.role);
    localStorage.setItem("permissions", JSON.stringify(data.permissions || {}));
};

const authSlice = createSlice({
    name: "auth",
    initialState: {
        token:       localStorage.getItem("token") || null,
        username:    localStorage.getItem("username") || null,
        role:        localStorage.getItem("role") || null,
        permissions: JSON.parse(localStorage.getItem("permissions") || "{}"),
        isLoading:   false,
        error:       null,
        // Auth-verification gate: protected routes must not render until the
        // stored token has been confirmed valid against the backend.
        authChecked:     false,
        isAuthenticating: false,
        // The password was chosen by someone else (an administrator, the
        // installer): the dashboard shows only the change-password form, and
        // the backend refuses everything else until it is done.
        mustChangePassword: false,
        // Two-step sign-in: the password step passed and the code is asked ({ token, username }).
        mfaChallenge: null,
        // Required for this role and not set up: the dashboard shows only its setup.
        mfaEnrolmentDue: false,
        // Signed in with a recovery code: how many are left (a warning is shown once).
        recoveryCodesLeft: null,
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

        cancelMfa: (state) => {
            state.mfaChallenge = null;
            state.error = null;
        },

        // The server answered 403 X-MFA-Enrollment-Required (the grace period ended mid-session).
        mfaEnrolmentRequired: (state) => {
            state.mfaEnrolmentDue = true;
        },

        recoveryWarningSeen: (state) => {
            state.recoveryCodesLeft = null;
        },

        // Two-step sign-in was turned on, off or moved: the server ended the other sessions and
        // answered with a fresh token for this one.
        sessionReplaced: (state, action) => {
            state.token = action.payload.access_token;
            state.mfaEnrolmentDue = !!action.payload.mfa_enrolment_due;
            localStorage.setItem("token", action.payload.access_token);
        },

        // PUT /auth/me/password answered with a fresh token (the old one stops
        // working once the password changes).
        passwordChanged: (state, action) => {
            state.token = action.payload.access_token;
            state.mustChangePassword = false;
            localStorage.setItem("token", action.payload.access_token);
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(loginUser.pending, (state) => {
                state.isLoading = true;
                state.error     = null;
            })
            .addCase(loginUser.fulfilled, (state, action) => {
                if (action.payload.mfa_required) {
                    state.isLoading = false;
                    state.mfaChallenge = { token: action.payload.mfa_token, username: action.payload.username };
                    return;
                }
                signedIn(state, action.payload);
            })
            .addCase(loginUser.rejected, (state, action) => {
                state.isLoading = false;
                state.error     = action.payload;
            })
            .addCase(loginMfa.pending, (state) => {
                state.isLoading = true;
                state.error     = null;
            })
            .addCase(loginMfa.fulfilled, (state, action) => {
                signedIn(state, action.payload);
            })
            .addCase(loginMfa.rejected, (state, action) => {
                state.isLoading = false;
                state.error     = action.payload?.message || t("Failed to connect to the server");
                if (action.payload?.expired) state.mfaChallenge = null;
            })

            // ── Token verification on app load ──
            .addCase(verifyToken.pending, (state) => {
                state.isAuthenticating = true;
            })
            .addCase(verifyToken.fulfilled, (state, action) => {
                state.isAuthenticating = false;
                state.authChecked      = true;
                // Refresh identity/permissions from the server (may have changed
                // since the token was issued).
                state.username    = action.payload.username;
                state.role        = action.payload.role;
                state.permissions = action.payload.permissions || {};
                state.language    = action.payload.language || null;
                state.languageChosen = !!action.payload.language_chosen;
                state.mustChangePassword = !!action.payload.must_change_password;
                state.mfaEnrolmentDue = !!action.payload.mfa_enrolment_due;

                localStorage.setItem("username",    action.payload.username);
                localStorage.setItem("role",        action.payload.role);
                localStorage.setItem("permissions", JSON.stringify(action.payload.permissions || {}));
            })
            .addCase(verifyToken.rejected, (state) => {
                // Token missing/expired/invalid → clear the session so
                // ProtectedRoute sends the user straight to login (no flash).
                state.isAuthenticating = false;
                state.authChecked      = true;
                state.token       = null;
                state.username    = null;
                state.role        = null;
                state.permissions = {};

                localStorage.removeItem("token");
                localStorage.removeItem("username");
                localStorage.removeItem("role");
                localStorage.removeItem("permissions");
            });
    },
});

export const {
    logout, clearError, passwordChanged, cancelMfa, mfaEnrolmentRequired, recoveryWarningSeen, sessionReplaced,
} = authSlice.actions;
export default authSlice.reducer;