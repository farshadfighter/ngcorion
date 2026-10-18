import { NavLink } from "react-router-dom";
import { t } from "../../i18n";
import "../../assets/BackupModule.css";
import "../../assets/Lifecycle.css";

/** The two views of the vulnerabilities: known CVEs of the software, and the certificates of the TLS services. */
export function CveTabs() {
    return (
        <nav className="bkm-chips sw-tabs" aria-label={t("Vulnerabilities (CVE)")}>
            <NavLink end to="/cve" className={({ isActive }) => `bkm-chip ${isActive ? "is-on" : ""}`}>
                {t("CVE Findings")}
            </NavLink>
            <NavLink to="/cve/certificates" className={({ isActive }) => `bkm-chip ${isActive ? "is-on" : ""}`}>
                {t("TLS certificates")}
            </NavLink>
        </nav>
    );
}
