export const AuditingSuccess = ({ sessionData, jobName, onBackToHome, onSeeResult }) => {
    return (
        <div className="auditing-success-container">
            {/* Success Icon */}
            <div className="success-icon-wrapper">
                <div className="success-icon">✓</div>
            </div>

            {/* Success Message */}
            <div className="success-message">
                <div className="success-text">The auditing was successful.</div>
            </div>

            {/* Job Info */}
            <div className="success-info">
                <p>
                    <strong>job name :</strong> {jobName || `job number${sessionData.session_id}`}
                </p>
                <p>
                    <strong>Asset :</strong> {sessionData.asset_name || "N/A"} ({sessionData.target_ip || "N/A"})
                </p>
            </div>

            {/* Actions */}
            <div className="success-actions">
                <button className="btn-back-home" onClick={onBackToHome}>
                    Back to Homepage
                </button>
                <button className="btn-see-result" onClick={onSeeResult}>
                    See Result
                </button>
            </div>
        </div>
    );
};