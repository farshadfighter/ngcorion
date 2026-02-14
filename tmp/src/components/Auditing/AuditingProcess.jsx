import { useEffect, useRef, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { checkAuditStatus } from "../../store/auditSlice";

export const AuditingProcess = ({ sessionData, onComplete, onError }) => {
    const dispatch = useDispatch();
    const { currentSession } = useSelector((state) => state.audit);
    const pollIntervalRef = useRef(null);
    const [isRefreshing, setIsRefreshing] = useState(false);

    useEffect(() => {
        // Start polling immediately
        startPolling();

        return () => {
            // Cleanup polling on unmount
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
            }
        };
    }, []);

    useEffect(() => {
        // Check if audit is completed
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
                onError();
            }
        }
    }, [currentSession, onComplete, onError]);

    const startPolling = () => {
        // Check immediately
        dispatch(checkAuditStatus(sessionData.session_id));

        // Then poll every 3 seconds
        pollIntervalRef.current = setInterval(() => {
            dispatch(checkAuditStatus(sessionData.session_id));
        }, 3000);
    };

    const handleRefresh = () => {
        setIsRefreshing(true);
        dispatch(checkAuditStatus(sessionData.session_id));
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
                <p>Be patient, auditing is being processed, it may take a few minutes.</p>
            </div>

            {/* Job Info */}
            <div className="process-info">
                <p>
                    <strong>job name :</strong> {sessionData.asset_name || "N/A"}
                </p>
                <p>
                    <strong>Asset :</strong> {sessionData.asset_name || "N/A"} ({sessionData.target_ip || "N/A"})
                </p>
            </div>

            {/* Refresh Button Only */}
            <div className="process-actions">
                <button
                    className="btn-refresh"
                    onClick={handleRefresh}
                    disabled={isRefreshing}
                >
                    🔄 {isRefreshing ? "Refreshing..." : "Refresh"}
                </button>
            </div>
        </div>
    );
};