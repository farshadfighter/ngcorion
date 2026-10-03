import { Link } from "react-router-dom";
import { useSelector } from "react-redux";
import { usePermission } from "../../hooks/usePermission";
import { t } from "../../i18n";
import "../../assets/BackupModule.css";
import "../../assets/Reports.css";


/** "Report" button on a module page: opens the builder for that module's report, with the page's filters. */
export function ReportShortcut({ template, query = {}, className, adminOnly = false, title }) {
    const canBuild = usePermission("reports", "write");
    const { role } = useSelector((state) => state.auth);
    if (!canBuild || (adminOnly && role !== "admin")) return null;
    const qs = new URLSearchParams(Object.entries(query).filter(([, v]) => v !== undefined && v !== null && v !== "")).toString();
    return (
        <Link className={className} to={`/reports/new/${template}${qs ? `?${qs}` : ""}`} title={title || t("Build a report from this page")}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"
                 strokeLinejoin="round" aria-hidden="true"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h5" /><path d="M9 17v-3M12 17v-6M15 17v-2" /></svg>
            {t("Report")}
        </Link>
    );
}
