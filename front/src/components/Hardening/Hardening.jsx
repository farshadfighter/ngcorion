/**
 * Hardening - Main container component for Cisco hardening operations
 *
 * Three modes:
 * 1. Fix Single - Fix individual checks
 * 2. Fix All - Batch fix selected checks with user parameters
 * 3. Automatic - Apply CIS defaults without user input
 */

import { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    fetchAuditSessions,
    fetchSessionResults,
    setSelectedSession,
    clearSelectedSession,
    clearError,
    clearSuccessMessage,
    selectAuditSessions,
    selectSelectedSession,
    selectFailedChecks,
    selectSelectedCheckIds,
    selectLoading,
    selectError,
    selectSuccessMessage,
    selectDeviceType,
} from '../../store/hardeningSlice';
import { AuditResultsTable } from './AuditResultsTable';
import { FixSingleModal } from './FixSingleModal';
import { FixAllModal } from './FixAllModal';
import { AutoHardenModal } from './AutoHardenModal';
import { HardeningHistory } from './HardeningHistory';
import HardeningWizard from './HardeningWizard';
import '../../assets/Hardening.css';

export const Hardening = () => {
    const dispatch = useDispatch();

    // Redux state
    const auditSessions = useSelector(selectAuditSessions);
    const selectedSession = useSelector(selectSelectedSession);
    const failedChecks = useSelector(selectFailedChecks);
    const selectedCheckIds = useSelector(selectSelectedCheckIds);
    const loading = useSelector(selectLoading);
    const error = useSelector(selectError);
    const successMessage = useSelector(selectSuccessMessage);
    const deviceType = useSelector(selectDeviceType);

    // Device type display names
    const deviceTypeLabels = {
        cisco: 'Cisco IOS',
        fortinet: 'FortiGate',
        linux: 'Linux',
        windows: 'Windows',
        apache: 'Apache',
    };

    // Local state
    const [activeTab, setActiveTab] = useState('results'); // 'results' | 'history' | 'wizard'
    const [showFixSingleModal, setShowFixSingleModal] = useState(false);
    const [showFixAllModal, setShowFixAllModal] = useState(false);
    const [showAutoHardenModal, setShowAutoHardenModal] = useState(false);
    const [selectedCheckForFix, setSelectedCheckForFix] = useState(null);
    const [showWizard, setShowWizard] = useState(false);
    const [wizardMode, setWizardMode] = useState(null); // 'post_audit' | 'full'

    // Load audit sessions on mount
    useEffect(() => {
        dispatch(fetchAuditSessions());
    }, [dispatch]);

    // Clear messages after timeout
    useEffect(() => {
        if (error || successMessage) {
            const timer = setTimeout(() => {
                if (error) dispatch(clearError());
                if (successMessage) dispatch(clearSuccessMessage());
            }, 5000);
            return () => clearTimeout(timer);
        }
    }, [error, successMessage, dispatch]);

    // Handle session selection
    const handleSessionChange = (e) => {
        const sessionId = parseInt(e.target.value);
        if (sessionId) {
            const session = auditSessions.find(s => s.id === sessionId);
            dispatch(setSelectedSession(session));
            dispatch(fetchSessionResults(sessionId));
        } else {
            dispatch(clearSelectedSession());
        }
    };

    // Handle Fix Single click
    const handleFixSingle = (check) => {
        setSelectedCheckForFix(check);
        setShowFixSingleModal(true);
    };

    // Handle Fix All click
    const handleFixAll = () => {
        if (selectedCheckIds.length === 0) {
            alert('Please select at least one check to fix.');
            return;
        }
        setShowFixAllModal(true);
    };

    // Handle Automatic Hardening click
    const handleAutoHarden = () => {
        setShowAutoHardenModal(true);
    };

    // Handle Full Hardening wizard
    const handleFullHardening = () => {
        setWizardMode('full');
        setShowWizard(true);
    };

    // Handle Post-Audit wizard
    const handlePostAuditWizard = () => {
        if (!selectedSession) {
            alert('Please select an audit session first.');
            return;
        }
        setWizardMode('post_audit');
        setShowWizard(true);
    };

    // Handle wizard close
    const handleWizardClose = (action) => {
        if (action === 'select_session') {
            // User needs to select a session for post-audit mode
            setShowWizard(false);
            setWizardMode(null);
            return;
        }
        setShowWizard(false);
        setWizardMode(null);
        // Refresh sessions after wizard completes
        dispatch(fetchAuditSessions());
        if (selectedSession) {
            dispatch(fetchSessionResults(selectedSession.id));
        }
    };

    // Format date for display
    const formatDate = (dateStr) => {
        if (!dateStr) return 'N/A';
        return new Date(dateStr).toLocaleString();
    };

    return (
        <div className="hardening-container">
            {/* Messages */}
            {error && (
                <div className="alert alert-error">
                    <span>{error}</span>
                    <button onClick={() => dispatch(clearError())}>×</button>
                </div>
            )}
            {successMessage && (
                <div className="alert alert-success">
                    <span>{successMessage}</span>
                    <button onClick={() => dispatch(clearSuccessMessage())}>×</button>
                </div>
            )}

            {/* Tab Navigation */}
            <div className="hardening-tabs">
                <button
                    className={`tab-btn ${activeTab === 'results' ? 'active' : ''}`}
                    onClick={() => setActiveTab('results')}
                >
                    Audit Results
                </button>
                <button
                    className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
                    onClick={() => setActiveTab('history')}
                >
                    Hardening History
                </button>
                <div className="tab-spacer"></div>
                <button
                    className="btn btn-primary full-hardening-btn"
                    onClick={handleFullHardening}
                >
                    Full Hardening Wizard
                </button>
            </div>

            {/* Results Tab */}
            {activeTab === 'results' && (
                <div className="results-tab">
                    {/* Session Selector */}
                    <div className="session-selector">
                        <label htmlFor="session-select">Select Audit Session:</label>
                        <select
                            id="session-select"
                            value={selectedSession?.id || ''}
                            onChange={handleSessionChange}
                            disabled={loading.sessions}
                        >
                            <option value="">-- Select a session --</option>
                            {auditSessions.map(session => {
                                const sessionDeviceType = session.device_type || session.session_type || 'cisco';
                                const deviceLabel = deviceTypeLabels[sessionDeviceType] || sessionDeviceType;
                                return (
                                    <option key={session.id} value={session.id}>
                                        [{deviceLabel}] {session.target_ip} - {formatDate(session.created_at)} -
                                        Compliance: {session.compliance_pct?.toFixed(1)}%
                                    </option>
                                );
                            })}
                        </select>
                        {loading.sessions && <span className="loading-spinner">Loading...</span>}
                    </div>

                    {/* Session Summary */}
                    {selectedSession && (
                        <div className="session-summary">
                            <div className="summary-item">
                                <span className="label">Device:</span>
                                <span className="value">{selectedSession.target_ip}</span>
                            </div>
                            <div className="summary-item">
                                <span className="label">Total Checks:</span>
                                <span className="value">{selectedSession.total_checks}</span>
                            </div>
                            <div className="summary-item passed">
                                <span className="label">Passed:</span>
                                <span className="value">{selectedSession.passed_checks}</span>
                            </div>
                            <div className="summary-item failed">
                                <span className="label">Failed:</span>
                                <span className="value">{selectedSession.failed_checks}</span>
                            </div>
                            <div className="summary-item">
                                <span className="label">Compliance:</span>
                                <span className="value">{selectedSession.compliance_pct?.toFixed(1)}%</span>
                            </div>
                        </div>
                    )}

                    {/* Mode Buttons */}
                    {selectedSession && failedChecks.length > 0 && (
                        <div className="mode-buttons">
                            <button
                                className="btn btn-primary"
                                onClick={handleFixAll}
                                disabled={selectedCheckIds.length === 0}
                            >
                                Fix Selected ({selectedCheckIds.length})
                            </button>
                            <button
                                className="btn btn-secondary"
                                onClick={handleAutoHarden}
                            >
                                Automatic Hardening
                            </button>
                            <button
                                className="btn btn-secondary"
                                onClick={handlePostAuditWizard}
                            >
                                Schema Wizard (Post-Audit)
                            </button>
                        </div>
                    )}

                    {/* Results Table */}
                    {selectedSession && (
                        <AuditResultsTable onFixSingle={handleFixSingle} />
                    )}

                    {!selectedSession && (
                        <div className="no-session-message">
                            <p>Select an audit session to view results and perform hardening.</p>
                        </div>
                    )}
                </div>
            )}

            {/* History Tab */}
            {activeTab === 'history' && <HardeningHistory />}

            {/* Modals */}
            {showFixSingleModal && selectedCheckForFix && (
                <FixSingleModal
                    check={selectedCheckForFix}
                    onClose={() => {
                        setShowFixSingleModal(false);
                        setSelectedCheckForFix(null);
                    }}
                />
            )}

            {showFixAllModal && (
                <FixAllModal
                    onClose={() => setShowFixAllModal(false)}
                />
            )}

            {showAutoHardenModal && (
                <AutoHardenModal
                    onClose={() => setShowAutoHardenModal(false)}
                />
            )}

            {/* Schema-driven Hardening Wizard */}
            {showWizard && (
                <div className="modal-overlay">
                    <div className="modal wizard-modal">
                        <HardeningWizard
                            onClose={handleWizardClose}
                            initialMode={wizardMode}
                            sessionId={wizardMode === 'post_audit' ? selectedSession?.id : null}
                            checkNumbers={wizardMode === 'post_audit' ? failedChecks.map(c => c.check_number) : null}
                        />
                    </div>
                </div>
            )}
        </div>
    );
};

export default Hardening;
