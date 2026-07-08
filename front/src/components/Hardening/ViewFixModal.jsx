import React, { useEffect, useState } from 'react';
import { useDispatch } from 'react-redux';
import { fetchFortinetManualGuidance } from '../../store/hardeningSlice';
import '../../assets/hardening/Hardenallmodal.css';

/**
 * Read-only remediation guidance for a manual (non-auto-fixable) FortiGate check.
 * Shows the check title/description, the exact CLI commands from the catalog, and
 * a "Copy commands" button. It never touches the device — no SSH, no execution.
 */
const ViewFixModal = ({ checkId, checkTitle, onClose }) => {
    const dispatch = useDispatch();
    const [guidance, setGuidance] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [copied, setCopied] = useState(false);

    useEffect(() => {
        let active = true;
        setLoading(true);
        setError(null);
        dispatch(fetchFortinetManualGuidance(checkId))
            .unwrap()
            .then((data) => { if (active) setGuidance(data); })
            .catch((err) => { if (active) setError(typeof err === 'string' ? err : 'Failed to load remediation guidance.'); })
            .finally(() => { if (active) setLoading(false); });
        return () => { active = false; };
    }, [dispatch, checkId]);

    const commands = guidance?.remediation_commands ?? [];

    const handleCopy = async () => {
        const text = commands.join('\n');
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch {
            // Clipboard API unavailable (non-secure context): fall back to a textarea.
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch { /* noop */ }
            document.body.removeChild(ta);
        }
    };

    const title = guidance?.check_title || checkTitle || checkId;

    return (
        <div className="hardening-modal-overlay" onClick={onClose}>
            <div className="hardening-modal-content hardening-modal-large" onClick={(e) => e.stopPropagation()}>
                <div className="hardening-modal-header">
                    <div className="hardening-modal-title">
                        <span className="hardening-modal-icon">📋</span>
                        <h2>View Fix — Manual Remediation</h2>
                    </div>
                    <button className="hardening-modal-close" onClick={onClose}>×</button>
                </div>

                <div className="hardening-modal-info">
                    <span className="hardening-info-icon">ℹ️</span>
                    <p>This check has no automated fix. Apply the steps below on the device manually — nothing is executed from here.</p>
                </div>

                <div className="hardening-modal-body">
                    {loading && (
                        <div className="hardening-modal-loading">
                            <div className="hardening-spinner"></div>
                            <p>Loading remediation…</p>
                        </div>
                    )}

                    {!loading && error && (
                        <div className="hardening-modal-error"><p>{error}</p></div>
                    )}

                    {!loading && !error && guidance && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                            {/* Title + metadata */}
                            <div>
                                <h3 style={{ fontSize: '18px', color: '#1e3a5f', margin: '0 0 8px 0', fontWeight: 700 }}>{title}</h3>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                                    {guidance.cis_id && <span style={badge}>CIS {guidance.cis_id}</span>}
                                    {guidance.cis_section && <span style={badge}>{guidance.cis_section}</span>}
                                    {guidance.severity && <span style={badge}>{guidance.severity}</span>}
                                    {guidance.scope && <span style={badge}>{guidance.scope}</span>}
                                </div>
                            </div>

                            {/* Description / guidance */}
                            {guidance.remediation_guidance && (
                                <div className="hardening-info-box">
                                    <p style={{ margin: 0, lineHeight: 1.6 }}>{guidance.remediation_guidance}</p>
                                </div>
                            )}

                            {/* CLI commands + copy */}
                            {commands.length > 0 ? (
                                <div>
                                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', margin: '0 0 12px 0' }}>
                                        <h4 style={{ fontSize: '15px', color: '#1e3a5f', margin: 0, fontWeight: 700 }}>CLI Commands</h4>
                                        <button
                                            onClick={handleCopy}
                                            style={{ padding: '7px 14px', background: copied ? '#059669' : '#1e3a5f', color: 'white', border: 'none', borderRadius: '6px', fontSize: '13px', fontWeight: 600, cursor: 'pointer' }}
                                        >
                                            {copied ? '✓ Copied' : '📄 Copy commands'}
                                        </button>
                                    </div>
                                    <pre style={{ background: '#0f172a', color: '#e2e8f0', padding: '16px', borderRadius: '8px', fontSize: '13px', lineHeight: 1.7, overflowX: 'auto', margin: 0, fontFamily: "'Consolas','Monaco','Courier New',monospace", whiteSpace: 'pre' }}>{commands.join('\n')}</pre>
                                </div>
                            ) : (
                                <div className="hardening-info-box">
                                    <p style={{ margin: 0 }}>No CLI commands for this check — follow the guidance above.</p>
                                </div>
                            )}
                        </div>
                    )}
                </div>

                <div className="hardening-modal-footer">
                    <button className="hardening-btn-primary" onClick={onClose}>Close</button>
                </div>
            </div>
        </div>
    );
};

const badge = {
    display: 'inline-block',
    padding: '3px 10px',
    background: '#eef2f7',
    color: '#1e3a5f',
    border: '1px solid #dbe3ee',
    borderRadius: '999px',
    fontSize: '12px',
    fontWeight: 600,
};

export default ViewFixModal;
