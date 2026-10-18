import { NavLink } from "react-router-dom";
import { t } from "../../i18n";

/** The two views of the software inventory: what is installed, and how long its vendor supports it. */
export function SoftwareTabs() {
    return (
        <nav className="bkm-chips sw-tabs" aria-label={t("Software")}>
            <NavLink end to="/assets/software" className={({ isActive }) => `bkm-chip ${isActive ? "is-on" : ""}`}>
                {t("Installed Software")}
            </NavLink>
            <NavLink to="/assets/software/lifecycle" className={({ isActive }) => `bkm-chip ${isActive ? "is-on" : ""}`}>
                {t("End of life")}
            </NavLink>
        </nav>
    );
}
