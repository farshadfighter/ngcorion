export const AuditingFailed = ({ sessionData, jobName, errorMessage, onBackToHome }) => {
    return (
        <div className="auditing-failed-container">
            {/* Failed Icon */}
            <div className="failed-icon-wrapper">
                <div className="failed-icon">✕</div>
            </div>

            {/* Failed Message */}
            <div className="failed-message">
                <div className="failed-text">The auditing was failed</div>
            </div>

            {/* Error Reasons */}
            <div className="failed-info">
                <div className="failed-info-icon">ℹ️</div>
                <div className="failed-info-text">
                    <p>It can be caused by the following factors</p>
                    <ul>
                        <li>(Incorrect IP address)</li>
                        <li>(Incorrect username)</li>
                        <li>(Incorrect password)</li>
                        <li>(Internet connection)</li>
                        <li>(Incorrect device selection)</li>
                    </ul>
                </div>
            </div>

            {/* Job Info */}
            <div className="failed-details">
                <p>
                    <strong>job name :</strong> {jobName || `job number${sessionData?.session_id || ''}`}
                </p>
                <p>
                    <strong>Asset :</strong> {sessionData?.asset_name || "N/A"} ({sessionData?.target_ip || "N/A"})
                </p>
            </div>

            {/* Action */}
            <div className="failed-actions">
                <button className="btn-back-home" onClick={onBackToHome}>
                    Back to Homepage
                </button>
            </div>
        </div>
    );
};