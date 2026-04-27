import api from "../../config/api.js";

// =====================
// HELPER: امضای HMAC-SHA256
// =====================
const signRequest = async (data, organizationToken) => {
    const timestamp = new Date().toISOString();
    const payload = JSON.stringify(data, Object.keys(data).sort());
    const message = `${payload}:${timestamp}`;

    const encoder = new TextEncoder();
    const keyData = encoder.encode(organizationToken);
    const messageData = encoder.encode(message);

    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
    const signatureArray = Array.from(new Uint8Array(signatureBuffer));
    const signature = signatureArray
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    return { signature, timestamp };
};

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

// گرفتن fingerprint از سرور
export const getFingerprint = async () => {
    const response = await api.get('/api/fingerprint');
    return response.data.fingerprint;
};

// فعال‌سازی لایسنس
export const activateLicense = async (licenseKey) => {
    const fingerprint = await getFingerprint();

    const response = await api.post('/api/licenses/activate', {
        license_key: licenseKey,
        vm_fingerprint: fingerprint,
    });

    const data = response.data;

    // ذخیره اطلاعات لازم برای درخواست‌های بعدی
    saveLicenseToStorage({
        license_key: licenseKey,
        organization_token: data.organization_token,
        vm_fingerprint: fingerprint,
    });

    return data;
};

// اعتبارسنجی لایسنس
export const validateLicense = async () => {
    const stored = loadLicenseFromStorage();
    if (!stored) throw new Error('No license found');

    const data = {
        license_key: stored.license_key,
        organization_token: stored.organization_token,
        vm_fingerprint: stored.vm_fingerprint,
    };

    const { signature, timestamp } = await signRequest(data, stored.organization_token);

    const response = await api.post('/api/licenses/validate', data, {
        headers: {
            'X-Signature': signature,
            'X-Timestamp': timestamp,
        },
    });

    return response.data;
};

// heartbeat - هر ساعت صدا زده میشه
export const sendHeartbeat = async () => {
    const stored = loadLicenseFromStorage();
    if (!stored) throw new Error('No license found');

    const response = await api.post('/api/licenses/heartbeat', {
        license_key: stored.license_key,
        organization_token: stored.organization_token,
        vm_fingerprint: stored.vm_fingerprint,
    });

    return response.data;
};

// مصرف عملیات
export const consumeOperation = async (operationType, count = 1) => {
    const stored = loadLicenseFromStorage();
    if (!stored) throw new Error('No license found');

    const data = {
        license_key: stored.license_key,
        organization_token: stored.organization_token,
        vm_fingerprint: stored.vm_fingerprint,
        operation_type: operationType,
        count,
    };

    const { signature, timestamp } = await signRequest(data, stored.organization_token);

    const response = await api.post('/api/licenses/consume', data, {
        headers: {
            'X-Signature': signature,
            'X-Timestamp': timestamp,
        },
    });

    return response.data;
};