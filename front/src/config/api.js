import axios from 'axios';

const API_BASE_URL = '';

// No default Content-Type header here on purpose. Axios already sets
// 'application/json' automatically for a plain object body, and - critically -
// only sets the correct 'multipart/form-data; boundary=...' header for a
// FormData body when Content-Type isn't already present in the request
// headers. A blanket 'application/json' default here silently overrode that
// for every FormData upload (Asset List/Asset Requirement Excel import, TLS
// certificate upload): the browser sent the file under a JSON Content-Type,
// so the server never saw a 'file' field at all - it came back as a 422
// "Field required".
const api = axios.create({
    baseURL: API_BASE_URL,
});

// ==========================================
// Request Interceptor — اضافه کردن token
// ==========================================

api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('token');
        // Public auth endpoints must not carry a (possibly stale) bearer token.
        const isPublicAuthPath =
            config.url.includes('/auth/login') ||
            config.url.includes('/auth/forgot-password') ||
            config.url.includes('/auth/reset-password');
        if (token && !isPublicAuthPath) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// ==========================================
// Response Interceptor — مدیریت خطاها
// ==========================================

api.interceptors.response.use(
    (response) => response,
    (error) => {

        // ----------------------------------------
        // 401 — Unauthorized: توکن نداره یا منقضی شده
        // ----------------------------------------
        if (error.response?.status === 401) {
            // A 401 can have two completely different origins:
            //   1) User session/token expired → should logout
            //   2) SSH authentication on the device itself (auditing/hardening) failed —
            //      meaning the device username/password was wrong, not the app token.
            //      User should NOT be logged out of the app in this case.
            // Device-level errors are returned as a structured object with error_type
            // (like authentication_error), but session errors are simple strings.
            const detail = error.response.data?.detail;
            
            // Check if this is a device SSH error by looking for:
            // - error_type field (structured error from backend)
            // - URL contains /audit/ or /harden/ (device operations)
            // - detail is an object (not a simple string like "Invalid token")
            const isDeviceOperation =
                error.config?.url?.includes('/audit/') ||
                error.config?.url?.includes('/harden/') ||
                error.config?.url?.includes('/hardening/');

            const isDeviceSshError =
                detail && typeof detail === 'object' && 'error_type' in detail;

            // The app-load token check (/auth/me) handles its own 401 through the
            // verifyToken thunk (clears state, routes to login). Skipping the hard
            // redirect here avoids a full page reload on startup.
            const isAuthVerify = error.config?.url?.includes('/auth/me');

            // Only logout if this is NOT a device SSH error AND NOT a device operation
            const shouldLogout = !isDeviceSshError && !isDeviceOperation && !isAuthVerify;

            if (shouldLogout) {
                localStorage.removeItem('token');
                localStorage.removeItem('username');
                localStorage.removeItem('role');
                localStorage.removeItem('permissions');
                window.location.href = '/';
            } else {
                // This is a device authentication error - let the component handle it
                // Make sure the error is properly formatted for the component
                if (detail && typeof detail === 'object') {
                    // Flatten the structured error to a string for consistent handling
                    error.response.data.detail = detail.message || detail.error_type || 'Authentication failed';
                }
            }
            return Promise.reject(error);
        }

        // ----------------------------------------
        // 403 — Forbidden: سه حالت داره
        // ----------------------------------------
        if (error.response?.status === 403) {
            const data = error.response.data;

            // حالت ۱: لایسنس فعال نیست — دست نخورده
            if (data.license_required) {
                window.dispatchEvent(new CustomEvent('license-required', {
                    detail: { message: data.detail }
                }));
                return Promise.reject(error);
            }

            // حالت ۲: سهمیه تمام شده — دست نخورده
            if (data.detail?.includes('quota') || data.detail?.includes('limit')) {
                window.dispatchEvent(new CustomEvent('quota-exhausted', {
                    detail: { message: data.detail }
                }));
                return Promise.reject(error);
            }

            // حالت ۳: Permission Denied — اضافه شد
            // بک‌اند 403 برگردونده ولی نه به خاطر لایسنس
            window.dispatchEvent(new CustomEvent('permission-denied', {
                detail: {
                    message: data.detail || 'You do not have permission to perform this action.',
                    url: error.config?.url,
                }
            }));
        }

        return Promise.reject(error);
    }
);

export default api;
