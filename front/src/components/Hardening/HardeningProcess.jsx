import { useEffect, useRef, useState, useCallback } from "react";
import { useDispatch, useSelector } from "react-redux";
import { checkHardeningSessionStatus } from "../../store/hardeningSlice";

// چند بار پشت سر هم خطا بیاد تا onError صدا زده بشه
const MAX_CONSECUTIVE_ERRORS = 3;

export const HardeningProcess = ({ sessionData, onComplete, onError }) => {
    const dispatch = useDispatch();
    const { currentSession, error } = useSelector((state) => state.hardening);
    const pollIntervalRef   = useRef(null);
    const hasCalledCallback = useRef(false);
    const consecutiveErrors = useRef(0);       // شمارنده خطاهای پشت سر هم
    const [isRefreshing, setIsRefreshing] = useState(false);

    const stopPolling = () => {
        if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current);
            pollIntervalRef.current = null;
        }
    };

    const poll = useCallback(() => {
        if (
            sessionData.session_id &&
            sessionData.session_id !== "pending" &&
            sessionData.device_type
        ) {
            dispatch(checkHardeningSessionStatus({
                sessionId:  sessionData.session_id,
                deviceType: sessionData.device_type,
            }));
        }
    }, [dispatch, sessionData.session_id, sessionData.device_type]);

    // شروع polling
    useEffect(() => {
        poll();
        pollIntervalRef.current = setInterval(poll, 3000);
        return () => stopPolling();
    }, [poll]);

    // ── وقتی session status تغییر کرد ──
    useEffect(() => {
        if (!currentSession || hasCalledCallback.current) return;

        // Only honor the session we're actually polling — a leftover
        // currentSession from a previous run must not trigger a false complete.
        const currentId = currentSession.session_id ?? currentSession.id;
        if (
            sessionData.session_id != null &&
            currentId != null &&
            String(currentId) !== String(sessionData.session_id)
        ) {
            return;
        }

        if (currentSession.status === "completed") {
            consecutiveErrors.current = 0;
            hasCalledCallback.current = true;
            stopPolling();
            setTimeout(() => onComplete(), 1000);

        } else if (currentSession.status === "failed") {
            consecutiveErrors.current = 0;
            hasCalledCallback.current = true;
            stopPolling();
            setTimeout(() => onError(), 1000);

        } else {
            // هر response موفق شمارنده خطا رو ریست میکنه
            consecutiveErrors.current = 0;
        }
    }, [currentSession, sessionData.session_id, onComplete, onError]);

    // ── وقتی خطا اومد ──
    // فقط بعد از MAX_CONSECUTIVE_ERRORS خطای پشت سر هم، onError صدا زده میشه
    // یه خطای موقت (مثل timeout) باعث fail نمیشه
    useEffect(() => {
        if (!error || hasCalledCallback.current) return;

        consecutiveErrors.current += 1;

        if (consecutiveErrors.current >= MAX_CONSECUTIVE_ERRORS) {
            hasCalledCallback.current = true;
            stopPolling();
            setTimeout(() => onError(), 500);
        }
    }, [error, onError]);

    const handleRefresh = () => {
        setIsRefreshing(true);
        poll();
        setTimeout(() => setIsRefreshing(false), 500);
    };

    return (
        <div className="auditing-process-container">
            {/* Loading Animation */}
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
                <p><strong>Asset:</strong> {sessionData.asset_name || "N/A"} ({sessionData.target_ip || "N/A"})</p>
                <p><strong>Device Type:</strong> {sessionData.device_type || "N/A"}</p>
                <p><strong>Status:</strong> {currentSession?.status || sessionData.status || "Connecting..."}</p>
            </div>

            {/* Refresh Button */}
            <div className="process-actions">
                <button
                    className="btn-refresh"
                    onClick={handleRefresh}
                    disabled={isRefreshing}
                    style={{
                        padding:      "10px 24px",
                        background:   "white",
                        border:       "1px solid #d1d5db",
                        borderRadius: "8px",
                        fontSize:     "14px",
                        fontWeight:   "600",
                        color:        "#374151",
                        cursor:       "pointer",
                        transition:   "all 0.2s",
                    }}
                >
                    {isRefreshing ? "Refreshing..." : "Refresh"}
                </button>
            </div>
        </div>
    );
};

export default HardeningProcess;