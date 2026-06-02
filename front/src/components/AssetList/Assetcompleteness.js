/**
 * بررسی تکمیل بودن اطلاعات یک asset
 * true  = تکمیل (نوار سبز)
 * false = ناقص  (نوار نارنجی)
 */
export const isAssetComplete = (asset) => {
    if (!asset) return false;

    const requiredFields = [
        asset.asset_name,
        asset.asset_type_id || asset.asset_type_name,
        asset.ip_address,
        asset.location_id || asset.location_name,
        asset.owner_id || asset.owner_name,
        asset.status,
        asset.manufacturer,
        asset.model,
        asset.serial_number,
    ];

    return requiredFields.every(
        (field) => field !== null && field !== undefined && String(field).trim() !== ""
    );
};