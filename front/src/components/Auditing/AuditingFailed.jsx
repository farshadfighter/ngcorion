import { t } from "../../i18n";
export const AuditingFailed = ({ sessionData, jobName, errorMessage, onBackToHome }) => {
    return (
        <div className="auditing-failed-container">
            {/* Failed Icon */}
            <div className="failed-icon-wrapper">
                <div className="failed-icon">✕</div>
            </div>

            {/* Failed Message */}
            <div className="failed-message">
                <div className="failed-text">{t("The auditing was failed")}</div>
            </div>

            {/* Error Message (if provided) */}
            {errorMessage && (
                <div className="alert alert-error" style={{ margin: "20px 0", textAlign: "start" }}>
                    <strong>{t("Error:")}</strong> {errorMessage}
                </div>
            )}

            {/* Error Reasons */}
            <div className="failed-info">
                <div className="failed-info-icon">ℹ️</div>
                <div className="failed-info-text">
                    <p>{t("It can be caused by the following factors")}</p>
                    <ul>
                        <li>{t("(Incorrect IP address)")}</li>
                        <li>{t("(Incorrect username)")}</li>
                        <li>{t("(Incorrect password)")}</li>
                        <li>{t("(Internet connection)")}</li>
                        <li>{t("(Incorrect device selection)")}</li>
                    </ul>
                </div>
            </div>

            {/* Job Info */}
            <div className="failed-details">
                <p>
                    <strong>{t("job name :")}</strong> {jobName || t("job number {{id}}", { id: sessionData?.session_id || '' })}
                </p>
                <p>
                    <strong>{t("Asset :")}</strong> {sessionData?.asset_name || "N/A"} ({sessionData?.target_ip || "N/A"})
                </p>
            </div>

            {/* Action */}
            <div className="failed-actions">
                <button className="btn-back-home" onClick={onBackToHome}>
                    {t("Back to Homepage")}
                </button>
            </div>
        </div>
    );
};