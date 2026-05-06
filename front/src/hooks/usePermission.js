import { useSelector } from "react-redux";

/**
 * hook برای چک کردن دسترسی کاربر
 *
 * @param {string} module  - نام ماژول: "hardening" | "auditing" | "asset_list" | ...
 * @param {string} action  - نوع عملیات: "read" | "write" | "delete"
 * @returns {boolean}
 *
 * مثال استفاده:
 *   const canReadHardening = usePermission("hardening", "read");
 *   const canDeleteAsset   = usePermission("asset_list", "delete");
 */
export const usePermission = (module, action = "read") => {
    const { role, permissions } = useSelector((state) => state.auth);

    // admin همیشه دسترسی کامل دارد
    if (role === "admin") return true;

    // اگه permissions لود نشده
    if (!permissions || !permissions[module]) return false;

    return permissions[module][action] === true;
};


/**
 * hook برای گرفتن تمام دسترسی‌های یک ماژول
 *
 * @param {string} module - نام ماژول
 * @returns {{ read: boolean, write: boolean, delete: boolean }}
 *
 * مثال استفاده:
 *   const perms = useModulePermissions("asset_list");
 *   if (perms.write) { ... }
 */
export const useModulePermissions = (module) => {
    const { role, permissions } = useSelector((state) => state.auth);

    if (role === "admin") {
        return { read: true, write: true, delete: true };
    }

    if (!permissions || !permissions[module]) {
        return { read: false, write: false, delete: false };
    }

    return {
        read:   permissions[module].read   === true,
        write:  permissions[module].write  === true,
        delete: permissions[module].delete === true,
    };
};