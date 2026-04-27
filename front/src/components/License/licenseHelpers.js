import { LICENSE_TYPES, API_FIELD_MAP } from "./licenseConfig";

// چک کردن آیا محدودیت رسیده یا نه
export const isLimitReached = (licenseType, module, currentUsage) => {
    const license = LICENSE_TYPES[licenseType];
    if (!license) return true;

    const limit = license.limits[module];
    if (limit === Infinity) return false;

    return currentUsage >= limit;
};

// گرفتن محدودیت یک ماژول
export const getModuleLimit = (licenseType, module) => {
    const license = LICENSE_TYPES[licenseType];
    if (!license) return 0;

    const limit = license.limits[module];
    return limit === Infinity ? "∞" : limit;
};

// گرفتن درصد استفاده
export const getUsagePercentage = (licenseType, module, currentUsage) => {
    const license = LICENSE_TYPES[licenseType];
    if (!license) return 0;

    const limit = license.limits[module];
    if (limit === Infinity) return 0;

    return Math.min((currentUsage / limit) * 100, 100);
};

// چک کردن آیا لایسنس معتبره
export const isLicenseValid = (licenseType) => {
    return licenseType && licenseType in LICENSE_TYPES;
};

// گرفتن اطلاعات کامل لایسنس
export const getLicenseInfo = (licenseType) => {
    if (!isLicenseValid(licenseType)) return null;
    return LICENSE_TYPES[licenseType];
};

// نمایش مقدار استفاده به صورت "used/limit"
export const formatUsage = (licenseType, module, currentUsage) => {
    const limit = getModuleLimit(licenseType, module);
    return `${currentUsage}/${limit}`;
};

// تبدیل response API به فرمت usage ما
export const mapApiResponseToUsage = (apiResponse) => {
    if (!apiResponse) return null;

    const usage = {};
    Object.keys(API_FIELD_MAP).forEach((module) => {
        const { used, max } = API_FIELD_MAP[module];
        usage[module] = {
            used: apiResponse[used] ?? 0,
            max: apiResponse[max] ?? 0,
        };
    });

    return usage;
};

// چک کردن آیا لایسنس منقضی شده
export const isLicenseExpired = (expiresAt) => {
    if (!expiresAt) return true;
    return new Date(expiresAt) < new Date();
};

// فرمت تاریخ انقضا
export const formatExpiryDate = (expiresAt) => {
    if (!expiresAt) return "—";
    return new Date(expiresAt).toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric",
    });
};