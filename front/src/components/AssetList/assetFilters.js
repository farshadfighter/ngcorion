import { t, n } from "../../i18n";
/**
 * Filters of the asset list taken from the address, so another page (the assets overview) can open the
 * list already narrowed: ?missing=owner|ip|os|location, ?type=<asset type id>, ?vendor=<manufacturer>,
 * ?os=<operating system>, ?status=<status>, ?added=<days>. Several combine (all must match).
 */
const blank = (v) => v === null || v === undefined || String(v).trim() === "";
const same = (a, b) => String(a || "").trim().toLowerCase() === String(b || "").trim().toLowerCase();

const MISSING = {
    owner: { test: (a) => blank(a.owner_id), label: t("No owner") },
    ip: { test: (a) => blank(a.ip_address), label: t("No IP address") },
    os: { test: (a) => blank(a.os_name), label: t("No operating system") },
    location: { test: (a) => blank(a.location_id), label: t("No location") },
};

export const FILTER_KEYS = ["missing", "type", "vendor", "os", "status", "added"];

/** The filters in the address: [{key, value}], unknown values left out. */
export function readFilters(params) {
    const out = [];
    for (const key of FILTER_KEYS) {
        const value = params.get(key);
        if (blank(value)) continue;
        if (key === "missing" && !MISSING[value]) continue;
        if (key === "added" && !(Number(value) > 0)) continue;
        out.push({ key, value });
    }
    return out;
}

/** Whether an asset passes every filter. `now` is a Date (for "added"). */
export function matchesFilters(asset, filters, now = new Date()) {
    return filters.every(({ key, value }) => {
        switch (key) {
            case "missing": return MISSING[value].test(asset);
            case "type": return String(asset.asset_type_id) === String(value);
            case "vendor": return same(asset.manufacturer, value);
            case "os": return same(asset.os_name, value);
            case "status": return same(asset.status, value);
            case "added": {
                const created = asset.created_at ? new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(asset.created_at)
                    ? asset.created_at : `${asset.created_at}Z`) : null;
                return Boolean(created) && now - created <= Number(value) * 86400000;
            }
            default: return true;
        }
    });
}

/** What a filter chip says. `typeName(id)` resolves an asset type, `statusName` a status. */
export function filterLabel({ key, value }, typeName = (id) => id, statusName = (s) => s) {
    switch (key) {
        case "missing": return MISSING[value].label;
        case "type": return t("Type: {{name}}", { name: typeName(value) });
        case "vendor": return t("Vendor: {{name}}", { name: value });
        case "os": return t("Operating system: {{name}}", { name: value });
        case "status": return t("Status: {{name}}", { name: statusName(value) });
        case "added": return t("Added in the last {{days}} days", { days: n(Number(value)) });
        default: return value;
    }
}
