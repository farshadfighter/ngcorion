export const FixUnsuccessfulSuccess = ({ sessionData, onNext }) => {
    return (
        <div className="auditing-success-container">
            {/* Success Icon */}
            <div className="success-icon-wrapper">
                <div className="success-icon">✓</div>
            </div>

            {/* Success Message */}
            <div className="success-message">
                <div className="success-text">Audit Results Loaded Successfully</div>
            </div>

            {/* Session Info */}
            <div className="success-info">
                <p>
                    <strong>Asset:</strong> {sessionData.asset_name || "N/A"} ({sessionData.target_ip || "N/A"})
                </p>
                <p>
                    <strong>Audit Session:</strong> #{sessionData.session_id || "N/A"}
                </p>
                <p>
                    <strong>Status:</strong> Ready to fix unsuccessful checks
                </p>
            </div>

            {/* Actions */}
            <div className="success-actions">
                <button
                    className="btn-see-result"
                    onClick={onNext}
                    style={{
                        padding: '12px 32px',
                        background: '#1e3a5f',
                        color: 'white',
                        border: 'none',
                        borderRadius: '8px',
                        fontSize: '14px',
                        fontWeight: '600',
                        cursor: 'pointer',
                        transition: 'all 0.2s'
                    }}
                >
                    Next
                </button>
            </div>
        </div>
    );
};

export default FixUnsuccessfulSuccess;
