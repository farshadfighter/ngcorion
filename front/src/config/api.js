import axios from 'axios';

const API_BASE_URL = '';

const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json'
    }
});

// Request interceptor - اضافه کردن token
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

// Response interceptor - مدیریت خطاها
api.interceptors.response.use(
    (response) => response,
    (error) => {
        // مدیریت 401 - Unauthorized
        if (error.response?.status === 401) {
            localStorage.removeItem('token');
            localStorage.removeItem('username');
            localStorage.removeItem('role');
            window.location.href = '/';
            return Promise.reject(error);
        }

        // مدیریت 403 - Forbidden (License issues)
        if (error.response?.status === 403) {
            const data = error.response.data;

            // لایسنس فعال نیست
            if (data.license_required) {
                // ارسال event برای نمایش مودال فعال‌سازی لایسنس
                window.dispatchEvent(new CustomEvent('license-required', {
                    detail: { message: data.detail }
                }));
            }

            // سهمیه تمام شده
            if (data.detail?.includes('quota') || data.detail?.includes('limit')) {
                // ارسال event برای نمایش مودال سهمیه تمام شده
                window.dispatchEvent(new CustomEvent('quota-exhausted', {
                    detail: { message: data.detail }
                }));
            }
        }

        return Promise.reject(error);
    }
);

export default api;
