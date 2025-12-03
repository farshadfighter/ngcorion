/* ==========================================
   NGCORION - Activity Log Component
   ========================================== */

import React, { useRef, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { clearActivityLog } from '../../store/slices/discoverySlice';
import './ActivityLog.css';

const ActivityLog = ({ autoScroll = true }) => {
  const dispatch = useDispatch();
  const { activityLog } = useSelector((state) => state.discovery);
  const logContainerRef = useRef(null);

  // Auto scroll to top on new logs
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = 0;
    }
  }, [activityLog, autoScroll]);

  const getLogIcon = (type) => {
    switch (type) {
      case 'success': return '✅';
      case 'error': return '❌';
      case 'warning': return '⚠️';
      case 'info': return 'ℹ️';
      case 'host': return '🖥️';
      default: return '📝';
    }
  };

  const formatTime = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    });
  };

  return (
    <div className="activity-log">
      <div className="activity-log-header">
        <h3>📋 Activity Log</h3>
        <div className="log-actions">
          <span className="log-count">{activityLog.length} entries</span>
          {activityLog.length > 0 && (
            <button 
              className="btn-clear"
              onClick={() => dispatch(clearActivityLog())}
              title="Clear log"
            >
              🗑️ Clear
            </button>
          )}
        </div>
      </div>
      
      <div className="activity-log-container" ref={logContainerRef}>
        {activityLog.length === 0 ? (
          <div className="log-empty">
            <p>No activity yet. Start a scan to see logs here.</p>
          </div>
        ) : (
          <div className="log-entries">
            {activityLog.map((log) => (
              <div key={log.id} className={`log-entry log-${log.type}`}>
                <span className="log-icon">{getLogIcon(log.type)}</span>
                <div className="log-content">
                  <div className="log-message">{log.message}</div>
                  {log.details && (
                    <div className="log-details">{log.details}</div>
                  )}
                </div>
                <span className="log-time">{formatTime(log.timestamp)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ActivityLog;
