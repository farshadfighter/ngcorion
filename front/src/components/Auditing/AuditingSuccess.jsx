import { t } from "../../i18n";
export const AuditingSuccess = ({ sessionData, jobName, onBackToHome, onSeeResult }) => {
    return (
        <div className="auditing-success-container">
            {/* Success Icon */}
            <div className="success-icon-wrapper">
                <div className="success-icon">✓</div>
            </div>

            {/* Success Message */}
            <div className="success-message">
                <div className="success-text">{t("The auditing was successful.")}</div>
            </div>

            {/* Job Info */}
            <div className="success-info">
                <p>
                    <strong>{t("job name :")}</strong> {jobName || t("job number{{session_id}}", { session_id: sessionData.session_id })}
                </p>
                <p>
                    <strong>{t("Asset :")}</strong> {sessionData.asset_name || "N/A"} ({sessionData.target_ip || "N/A"})
                </p>
            </div>

            {/* Actions */}
            <div className="success-actions">
                <button className="btn-back-home" onClick={onBackToHome}>
                    {t("Back to Homepage")}
                </button>
                <button className="btn-see-result" onClick={onSeeResult}>
                    {t("See Result")}
                </button>
            </div>
        </div>
    );
};