import api from "../../config/api.js";

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

export const getLicenseStatus = async () => {
    const response = await api.get('/api/license/status');
    return response.data;
};

export const activateLicense = async (licenseKey) => {
    const response = await api.post('/api/license/activate', {
        license_key: licenseKey,
    });

    const data = response.data;

    saveLicenseToStorage({
        license_key: licenseKey,
        organization_token: data.organization_token,
    });

    return data;
};