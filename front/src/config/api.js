import axios from 'axios';

const API_BASE_URL = '';

const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json'
    }
});

// ==========================================
// Request Interceptor — اضافه کردن token
// ==========================================

api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('token');
        if (token && !config.url.includes('/auth/login')) {
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
            // یک 401 می‌تونه دو منشأ کاملاً متفاوت داشته باشه:
            //   ۱) نشست/توکن کاربر منقضی شده  →  باید logout بشه
            //   ۲) احراز هویت SSH روی خودِ دستگاه (هاردنینگ/ادیت) شکست خورده —
            //      یعنی یوزر/پسوردِ دستگاه اشتباه بوده، نه توکنِ برنامه.
            //      اینجا نباید کاربر از برنامه بیرون انداخته بشه.
            // خطاهای سطح دستگاه به‌صورت یک آبجکت ساختاریافته با error_type برمی‌گردن
            // (مثل authentication_error)، ولی خطای نشست یک رشته‌ی ساده‌ست.
            const detail = error.response.data?.detail;
            const isDeviceSshError =
                detail && typeof detail === 'object' && 'error_type' in detail;

            if (!isDeviceSshError) {
                localStorage.removeItem('token');
                localStorage.removeItem('username');
                localStorage.removeItem('role');
                localStorage.removeItem('permissions'); // ← اضافه شد
                window.location.href = '/';
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