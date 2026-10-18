import { NavLink } from "react-router-dom";
import { useSelector } from "react-redux";
import { t } from "../../i18n";
import "../../assets/BackupModule.css";
import "../../assets/Lifecycle.css";

/** The accounts of NGCorion: people, and (system administrators only) the API keys of other systems. */
export function UsersTabs() {
    const isAdmin = useSelector((s) => s.auth.role) === "admin";
    if (!isAdmin) return null;
    return (
        <nav className="bkm-chips sw-tabs" aria-label={t("Users")}>
            <NavLink end to="/settings/users" className={({ isActive }) => `bkm-chip ${isActive ? "is-on" : ""}`}>
                {t("Users")}
            </NavLink>
            <NavLink to="/settings/api-keys" className={({ isActive }) => `bkm-chip ${isActive ? "is-on" : ""}`}>
                {t("API keys")}
            </NavLink>
        </nav>
    );
}
