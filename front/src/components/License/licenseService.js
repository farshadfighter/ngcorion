import api from "../../config/api.js";

// =====================
// HELPER: ذخیره و خواندن از localStorage
// =====================
const STORAGE_KEY = 'ngcorion_license';

export const saveLicenseToStorage = (data) => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
};

export const loadLicenseFromStorage = () => {
    const data = localStorage.getItem(STORAGE_KEY);
    return data ? JSON.parse(data) : null;
};

export const clearLicenseFromStorage = () => {
    localStorage.removeItem(STORAGE_KEY);
};

// =====================
// API CALLS
// =====================

/**
 * دریافت وضعیت لایسنس فعلی
 * این endpoint همیشه در دسترس است و نیازی به احراز هویت ندارد
 */
export const getLicenseStatus = async () => {
    const response = await api.get('/api/license/status');
    return response.data;
};

/**
 * فعال‌سازی لایسنس
 * Backend به صورت خودکار fingerprint را دریافت و لایسنس را فعال می‌کند
 */
export const activateLicense = async (licenseKey) => {
    const response = await api.post('/api/license/activate', {
        license_key: licenseKey,
    });

    const data = response.data;

    // فقط license_key را برای مرجع ذخیره می‌کنیم
    // organization_token و fingerprint هرگز به frontend ارسال نمی‌شوند
    saveLicenseToStorage({
        license_key: licenseKey,
    });

    return data;
};
