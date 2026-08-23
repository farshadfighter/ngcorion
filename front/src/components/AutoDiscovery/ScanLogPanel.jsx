import React, { useRef, useEffect } from 'react';
import { isNmapMissing, NMAP_INSTALL_COMMAND } from './scanErrors.jsx';

const ACTION_LABELS = {
    scan_started: 'Scan Started',
    scan_completed: 'Scan Completed',
    scan_failed: 'Scan Failed',
    scan_cancelled: 'Scan Cancelled',
    host_discovered: 'Host Discovered',
    port_scanned: 'Port Scanned',
    discovery_applied: 'Discovery Applied',
    asset_created_from_discovery: 'Asset Created',
};

// The nmap-missing failure reaches the log stream verbatim; replace it there
// too so the panel and the alert say the same actionable thing.
const logDetail = (entry) => {
    const detail = entry.error_message || entry.details?.message;
    if (!detail) return null;
    if (isNmapMissing(detail)) {
        return `nmap روی سرور نصب نیست — ${NMAP_INSTALL_COMMAND}`;
    }
    return detail;
};

const ScanLogPanel = ({ logs }) => {
    const bottomRef = useRef(null);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [logs]);

    if (!logs || logs.length === 0) {
        return (
            <div className="scan-log-panel scan-log-empty">
                Waiting for scan events…
            </div>
        );
    }

    return (
        <div className="scan-log-panel">
            {logs.map((entry) => (
                <div key={entry.id} className={`scan-log-entry log-status-${entry.status || 'info'}`}>
                    <span className="log-dot" />
                    <span className="log-time">
                        {entry.timestamp
                            ? new Date(entry.timestamp).toLocaleTimeString('en-US', { hour12: false })
                            : '--:--:--'}
                    </span>
                    <span className="log-action">
                        {ACTION_LABELS[entry.action] || entry.action}
                    </span>
                    {entry.ip_address && (
                        <span className="log-ip">{entry.ip_address}</span>
                    )}
                    {logDetail(entry) && (
                        <span className="log-detail">
                            {logDetail(entry)}
                        </span>
                    )}
                </div>
            ))}
            <div ref={bottomRef} />
        </div>
    );
};

export default ScanLogPanel;
