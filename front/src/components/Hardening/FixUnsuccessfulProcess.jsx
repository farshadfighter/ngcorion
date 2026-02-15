import { useEffect, useRef, useState, useCallback } from "react";
import { useDispatch, useSelector } from "react-redux";
import { checkHardeningSessionStatus } from "../../store/hardeningSlice";

export const FixUnsuccessfulProcess = ({ sessionData, onComplete, onError }) => {
    const dispatch = useDispatch();
    const { currentSession, isLoading } = useSelector((state) => state.hardening);
    const pollIntervalRef = useRef(null);
    const [isRefreshing, setIsRefreshing] = useState(false);

    const checkSessionStatus = useCallback(() => {
        if (sessionData.session_id) {
            dispatch(checkHardeningSessionStatus({
                sessionId: sessionData.session_id,
                deviceType: sessionData.device_type
            }));
        }
    }, [dispatch, sessionData.session_id, sessionData.device_type]);

    useEffect(() => {
        // Check immediately
        checkSessionStatus();

        // Then poll every 3 seconds
        pollIntervalRef.current = setInterval(() => {
            checkSessionStatus();
        }, 3000);

        return () => {
            // Cleanup polling on unmount
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
            }
        };
    }, [checkSessionStatus]);

    useEffect(() => {
        if (currentSession) {
            if (currentSession.status === "completed") {
                // Stop polling
                if (pollIntervalRef.current) {
                    clearInterval(pollIntervalRef.current);
                    pollIntervalRef.current = null;
                }
                // Move to next step
                setTimeout(() => {
                    onComplete();
                }, 1000);
            } else if (currentSession.status === "failed") {
                // Stop polling
                if (pollIntervalRef.current) {
                    clearInterval(pollIntervalRef.current);
                    pollIntervalRef.current = null;
                }
                // Move to error step
                setTimeout(() => {
                    onError();
                }, 1000);
            }
        }
    }, [currentSession, onComplete, onError]);

    const handleRefresh = () => {
        setIsRefreshing(true);
        checkSessionStatus();
        setTimeout(() => {
            setIsRefreshing(false);
        }, 500);
    };

    return (
        <div className="auditing-process-container">
            {/* Loading Animation - SIMPLE DOTS */}
            <div className="process-animation">
                <div className="loading-dots">
                    <div className="dot"></div>
                    <div className="dot"></div>
                    <div className="dot"></div>
                </div>
            </div>

            {/* Status Message */}
            <div className="process-message">
                <div className="message-icon">ℹ️</div>
                <p>Be patient, loading audit results, it may take a few moments.</p>
            </div>

            {/* Session Info */}
            <div className="process-info">
                <p>
                    <strong>Asset:</strong> {sessionData.asset_name || "N/A"} ({sessionData.target_ip || "N/A"})
                </p>
                <p>
                    <strong>Audit Session:</strong> #{sessionData.session_id || "N/A"}
                </p>
                {sessionData.device_type && (
                    <p>
                        <strong>Device Type:</strong> {sessionData.device_type}
                    </p>
                )}
            </div>

            {/* Refresh Button Only */}
            <div className="process-actions">
                <button
                    className="btn-refresh"
                    onClick={handleRefresh}
                    disabled={isRefreshing || isLoading}
                    style={{
                        padding: '10px 24px',
                        background: 'white',
                        border: '1px solid #d1d5db',
                        borderRadius: '8px',
                        fontSize: '14px',
                        fontWeight: '600',
                        color: '#374151',
                        cursor: 'pointer',
                        transition: 'all 0.2s'
                    }}
                >
                    {isRefreshing ? "Refreshing..." : "Refresh"}
                </button>
            </div>
        </div>
    );
};

export default FixUnsuccessfulProcess;
