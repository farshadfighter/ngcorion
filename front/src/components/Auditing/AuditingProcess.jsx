import { useEffect, useRef, useState, useCallback } from "react";
import { useDispatch, useSelector } from "react-redux";
import { checkAuditStatus } from "../../store/auditSlice";

export const AuditingProcess = ({ sessionData, jobName, onComplete, onError }) => {
    const dispatch = useDispatch();
    const { currentSession } = useSelector((state) => state.audit);
    const pollIntervalRef = useRef(null);
    const [isRefreshing, setIsRefreshing] = useState(false);
    const [isPending, setIsPending] = useState(
        !sessionData.session_id || sessionData.session_id === "pending"
    );

    const startPolling = useCallback((sessionId) => {
        if (!sessionId || sessionId === "pending") return;

        if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current);
            pollIntervalRef.current = null;
        }

        dispatch(checkAuditStatus(sessionId));

        pollIntervalRef.current = setInterval(() => {
            dispatch(checkAuditStatus(sessionId));
        }, 3000);
    }, [dispatch]);

    // ✅ وقتی session_id از "pending" به مقدار واقعی تغییر کرد
    useEffect(() => {
        if (sessionData.session_id && sessionData.session_id !== "pending") {
            setIsPending(false);
            startPolling(sessionData.session_id);
        } else {
            setIsPending(true);
        }

        return () => {
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
            }
        };
    }, [sessionData.session_id, startPolling]);

    // ✅ چک status - هر چیزی غیر از completed و running → failed
    useEffect(() => {
        if (!currentSession) return;
        // Don't process any session update until we have a real session ID
        if (!sessionData.session_id || sessionData.session_id === "pending") return;
        // Ignore updates for a different session (stale Redux state)
        if (currentSession.session_id !== sessionData.session_id) return;

        if (currentSession.status === "completed") {
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
                pollIntervalRef.current = null;
            }
            setTimeout(() => onComplete(), 1000);

        } else if (currentSession.status === "failed") {
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
                pollIntervalRef.current = null;
            }
            const errorMsg =
                currentSession.error_message ||
                currentSession.error ||
                "Audit failed. Please check your credentials and try again.";
            setTimeout(() => onError(errorMsg), 1000);
        }
    }, [currentSession, sessionData.session_id, onComplete, onError]);

    const handleRefresh = () => {
        if (!sessionData.session_id || sessionData.session_id === "pending") return;
        setIsRefreshing(true);
        dispatch(checkAuditStatus(sessionData.session_id));
        setTimeout(() => setIsRefreshing(false), 500);
    };

    return (
        <div className="auditing-process-container">
            <div className="process-animation">
                <div className="loading-dots">
                    <div className="dot"></div>
                    <div className="dot"></div>
                    <div className="dot"></div>
                </div>
            </div>

            <div className="process-message">
                <div className="message-icon">ℹ️</div>
                {isPending ? (
                    <p>Connecting to server, please wait...</p>
                ) : (
                    <p>Be patient, auditing is being processed, it may take a few minutes.</p>
                )}
            </div>

            <div className="process-info">
                <p>
                    <strong>job name :</strong> {jobName || `job number${sessionData?.session_id || ''}`}
                </p>
                <p>
                    <strong>Asset :</strong> {sessionData.asset_name || "N/A"} ({sessionData.target_ip || "N/A"})
                </p>
                {!isPending && (
                    <p>
                        <strong>Session ID :</strong> #{sessionData.session_id}
                    </p>
                )}
            </div>

            <div className="process-actions">
                <button
                    style={{
                        padding: '10px 24px',
                        background: isPending ? '#9ca3af' : '#1e3a5f',
                        color: 'white',
                        border: 'none',
                        borderRadius: '8px',
                        fontSize: '14px',
                        fontWeight: '600',
                        cursor: isPending ? 'not-allowed' : 'pointer',
                        transition: 'all 0.2s'
                    }}
                    onClick={handleRefresh}
                    disabled={isRefreshing || isPending}
                >
                    {isRefreshing ? "Refreshing..." : "Refresh"}
                </button>
            </div>
        </div>
    );
};

export default AuditingProcess;