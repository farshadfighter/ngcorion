import { useEffect, useRef, useState, useCallback } from "react";
import { useDispatch, useSelector } from "react-redux";
import { checkHardeningSessionStatus } from "../../store/hardeningSlice";

export const HardeningProcess = ({ sessionData, onComplete, onError }) => {
    const dispatch = useDispatch();
    const { currentSession } = useSelector((state) => state.hardening);
    const pollIntervalRef = useRef(null);
    const [isRefreshing, setIsRefreshing] = useState(false);

    const startPolling = useCallback(() => {
        // Check immediately
        if (sessionData.session_id && sessionData.session_id !== "pending" && sessionData.device_type) {
            dispatch(checkHardeningSessionStatus({
                sessionId: sessionData.session_id,
                deviceType: sessionData.device_type
            }));

            // Then poll every 3 seconds
            pollIntervalRef.current = setInterval(() => {
                dispatch(checkHardeningSessionStatus({
                    sessionId: sessionData.session_id,
                    deviceType: sessionData.device_type
                }));
            }, 3000);
        }
    }, [dispatch, sessionData.session_id, sessionData.device_type]);

    useEffect(() => {
        // Start polling immediately
        startPolling();

        return () => {
            // Cleanup polling on unmount
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
            }
        };
    }, [startPolling]);

    useEffect(() => {
        // Check if session is completed
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
        if (sessionData.session_id && sessionData.session_id !== "pending" && sessionData.device_type) {
            dispatch(checkHardeningSessionStatus({
                sessionId: sessionData.session_id,
                deviceType: sessionData.device_type
            }));
        }
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
                <p>Be patient, connection is being established, it may take a few moments.</p>
            </div>

            {/* Session Info */}
            <div className="process-info">
                <p>
                    <strong>Asset:</strong> {sessionData.asset_name || "N/A"} ({sessionData.target_ip || "N/A"})
                </p>
                <p>
                    <strong>Device Type:</strong> {sessionData.device_type || "N/A"}
                </p>
                <p>
                    <strong>Status:</strong> {currentSession?.status || sessionData.status || "Connecting..."}
                </p>
            </div>

            {/* Refresh Button Only */}
            <div className="process-actions">
                <button
                    className="btn-refresh"
                    onClick={handleRefresh}
                    disabled={isRefreshing}
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

export default HardeningProcess;