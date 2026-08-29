import { Fragment, useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAuditResults } from "../../store/hardeningSlice";
import HardenAllModal from "./HardenAllModal";
import FixSingleModal from "./FixSingleModal";
import ViewFixModal from "./ViewFixModal";
import { groupChecksByScope } from "./vdomScope";
// This screen reuses the Auditing result table's styling (result-table,
// result-badge, severity-badge). The build inlines every stylesheet into one
// bundle so it renders either way, but the dependency is real — import it so
// the styles cannot disappear if that ever changes.
import "../../assets/Auditing.css";

export const HardeningResults = ({ sessionData, onClose, onNavigateToAuditing }) => {
    const dispatch = useDispatch();
    const { cisChecks, isLoading, fortinetTemplatedChecks } = useSelector(
        (state) => state.hardening
    );
    const [showHardenAllModal, setShowHardenAllModal] = useState(false);
    const [showFixSingleModal, setShowFixSingleModal] = useState(false);
    const [selectedCheck, setSelectedCheck] = useState(null);
    const [viewFixCheck, setViewFixCheck] = useState(null);

    useEffect(() => {
        if (sessionData?.session_id && sessionData?.device_type) {
            dispatch(fetchAuditResults({
                sessionId: sessionData.session_id,
                deviceType: sessionData.device_type
            }));
        }
    }, [sessionData?.session_id, sessionData?.device_type, dispatch]);

    const handleAuditingClick = () => {
        onClose();
        if (onNavigateToAuditing) {
            onNavigateToAuditing();
        } else {
            window.location.hash = "#operation-device";
        }
    };

    const handleHardenAll = () => setShowHardenAllModal(true);

    const handleModalSuccess = () => {
        if (sessionData?.session_id && sessionData?.device_type) {
            dispatch(fetchAuditResults({
                sessionId: sessionData.session_id,
                deviceType: sessionData.device_type
            }));
        }
        setShowHardenAllModal(false);
    };

    const handleHardenSingle = (check) => {
        setSelectedCheck(check);
        setShowFixSingleModal(true);
    };

    const handleFixSingleSuccess = () => {
        if (sessionData?.session_id && sessionData?.device_type) {
            dispatch(fetchAuditResults({
                sessionId: sessionData.session_id,
                deviceType: sessionData.device_type
            }));
        }
        setShowFixSingleModal(false);
        setSelectedCheck(null);
    };

    /* Per-control risk level, same badge as the Auditing result table: both
       screens read the same /sessions/{id}/results payload, which already
       carries `severity` per row. */
    const titleCase = (s) =>
        s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : "-";

    const getSeverityBadge = (severity) => {
        const level = severity?.toString().toLowerCase();
        if (!level) return <span style={{ color: '#9ca3af' }}>—</span>;
        return (
            <span className={`severity-badge severity-${level}`}>
                {titleCase(level)}
            </span>
        );
    };

    // Real audit statuses (this flow runs an audit right before this screen).
    // "Unknown" only when the row genuinely has no status.
    const getStatusBadge = (status) => {
        const s = status?.toString().toUpperCase();
        if (s === 'PASS' || s === 'PASSED') return <span className="result-badge result-success">Successful</span>;
        if (s === 'FAIL' || s === 'FAILED') return <span className="result-badge result-fail">Failed</span>;
        if (s === 'ERROR')                  return <span className="result-badge result-error">Error</span>;
        return <span className="result-badge result-unknown">Unknown</span>;
    };

    // Show the "audit your asset" hint only when no row carries a real status.
    const hasKnownStatus = (cisChecks || []).some((c) =>
        ['PASS', 'PASSED', 'FAIL', 'FAILED', 'ERROR'].includes(c.status?.toString().toUpperCase())
    );

    const getDeviceLabel = (dt) => {
        if (dt === 'fortinet')         return 'FortiGate';
        if (dt === 'linux' || dt?.startsWith('linux-'))  return 'Linux';
        if (dt === 'apache')           return 'Apache';
        if (dt === 'mongodb')          return 'MongoDB';
        if (dt?.startsWith('mssql-'))  return 'SQL Server';
        if (dt?.startsWith('windows-'))return 'Windows';
        return 'Cisco';
    };

    // A check is auto-fixable when it's not a FortiGate device, or the templated
    // list hasn't loaded (fail open — never hide "Harden" by mistake), or the
    // check number is in the templated set. Anything else only has manual
    // remediation, which is what View Fix shows.
    const isFortinet = (sessionData?.sub_device_type || sessionData?.device_type) === 'fortinet';
    const templatedSet = new Set(fortinetTemplatedChecks || []);
    const isAutoFixable = (check) =>
        !isFortinet || templatedSet.size === 0 || templatedSet.has(check.check_number);

    const totalChecks = cisChecks?.length || 0;

    // Conformity split for the summary cards, same rule as the status badge.
    const passedChecks = (cisChecks || []).filter((c) =>
        ['PASS', 'PASSED'].includes(c.status?.toString().toUpperCase())
    ).length;
    const failedChecks = (cisChecks || []).filter((c) =>
        ['FAIL', 'FAILED'].includes(c.status?.toString().toUpperCase())
    ).length;
    const conformityPercent = totalChecks ? Math.round((passedChecks / totalChecks) * 100) : 0;
    const nonConformityPercent = totalChecks ? Math.round((failedChecks / totalChecks) * 100) : 0;

    const fmtDate = (value) => {
        if (!value) return '—';
        const d = new Date(value);
        return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
    };

    // Split into Global vs per-VDOM groups (FortiGate multi-VDOM devices tag
    // each row with its vdom; flat devices get a single unlabeled group).
    // Section, [VDOM], Recommendation, Risk Level, Result, Action
    const { hasVdom, groups } = groupChecksByScope(cisChecks);
    const colCount = hasVdom ? 6 : 5;

    return (
        <div className="modal-overlay result-modal-overlay" onClick={!showFixSingleModal && !showHardenAllModal ? onClose : undefined}>
            <div className="result-modal-content" onClick={(e) => e.stopPropagation()}>
                {/* Header */}
                <div className="result-modal-header">
                    <button className="result-back-btn" onClick={onClose}>
                        ← Hardening Result
                    </button>
                </div>

                <div className="hr-body">
                    {/* One panel: the conformity numbers lead, the session
                        details sit underneath them. Shared with
                        FixUnsuccessfulResults so both result screens match. */}
                    <div className="hr-panel">
                    <div className="result-stats-summary">
                        <div className="result-card result-card-success">
                            <div className="card-percent">{conformityPercent}%</div>
                            <div className="card-sub">{passedChecks} of {totalChecks} checks</div>
                            <div className="card-label">Conformity</div>
                        </div>

                        <div className="result-card result-card-danger">
                            <div className="card-percent">{nonConformityPercent}%</div>
                            <div className="card-sub">{failedChecks} of {totalChecks} checks</div>
                            <div className="card-label">Non-Conformity</div>
                        </div>

                        <div className="result-card result-card-total">
                            <div className="card-number">{totalChecks}</div>
                            <div className="card-label">Total Conditions</div>
                        </div>
                    </div>

                    <div className="result-stats-container">
                        <div className="result-card result-card-info">
                            <div className="card-label">Benchmark</div>
                            <div className="card-value">
                                {getDeviceLabel(sessionData?.sub_device_type || sessionData?.device_type)} CIS
                            </div>
                        </div>

                        <div className="result-card result-card-info">
                            <div className="card-label">Asset</div>
                            <div className="card-value">{sessionData?.asset_name || 'N/A'}</div>
                        </div>

                        <div className="result-card result-card-info">
                            <div className="card-label">IP Address</div>
                            <div className="card-value">{sessionData?.target_ip || 'N/A'}</div>
                        </div>

                        <div className="result-card result-card-info">
                            <div className="card-label">Audit Date</div>
                            <div className="card-value">
                                {fmtDate(sessionData?.completed_at || sessionData?.started_at)}
                            </div>
                        </div>

                        <div className="result-card result-card-info">
                            <div className="card-label">Device Type</div>
                            <div className="card-value">
                                {getDeviceLabel(sessionData?.sub_device_type || sessionData?.device_type)}
                            </div>
                        </div>

                        <div className="result-card result-card-info">
                            <div className="card-label">Status</div>
                            <div className="card-value">{sessionData?.status || 'Completed'}</div>
                        </div>
                    </div>
                    </div>

                    {/* Figma prompts a re-audit after hardening; the original
                        "status unknown" wording only applied before one had
                        ever run, so both cases share this banner. */}
                    {!isLoading && (
                        <div className="hr-recheck">
                            <div className="hr-recheck-text">
                                <i className="fa-solid fa-circle-info" aria-hidden="true" />
                                <span>
                                    {hasKnownStatus
                                        ? 'After hardening, audit your asset again to get to know the status of your assets'
                                        : 'Status of CIS Benchmark section is unknown, audit your asset to specify status'}
                                </span>
                            </div>
                        </div>
                    )}

                    {/* Same toolbar as FixUnsuccessfulResults: the section label
                        on the left, Go to Auditing + Harden All on the right. */}
                    <div className="result-toolbar">
                        <div className="result-toolbar-left">
                            <span className="result-toolbar-title">Audit Result</span>
                        </div>
                        <div className="result-toolbar-right">
                            <button
                                className="result-toolbar-btn result-toolbar-btn-outline"
                                onClick={handleAuditingClick}
                            >
                                <i className="fa-solid fa-magnifying-glass" /> Go to Auditing
                            </button>
                            <button
                                className="result-toolbar-btn result-toolbar-btn-primary"
                                onClick={handleHardenAll}
                                disabled={totalChecks === 0}
                            >
                                <i className="fa-solid fa-shield-halved" /> Harden All
                            </button>
                        </div>
                    </div>

                    {/* Table */}
                    <div className="result-table-wrapper">
                        {isLoading ? (
                            <div className="loading-spinner">Loading results...</div>
                        ) : (
                            <table className="result-table">
                                <thead>
                                <tr>
                                    <th>Section</th>
                                    {hasVdom && <th>VDOM</th>}
                                    <th>Recommendation</th>
                                    <th>Risk Level</th>
                                    <th>Result</th>
                                    <th style={{ width: '120px' }}>Action</th>
                                </tr>
                                </thead>
                                <tbody>
                                {cisChecks && cisChecks.length > 0 ? (
                                    groups.map((group) => (
                                        <Fragment key={group.key}>
                                            {group.label && (
                                                <tr className="scope-group-row">
                                                    <td colSpan={colCount}>
                                                        {group.label}
                                                        <span className="scope-group-count">
                                                            {group.checks.length} check{group.checks.length !== 1 ? 's' : ''}
                                                        </span>
                                                    </td>
                                                </tr>
                                            )}
                                            {group.checks.map((check) => (
                                                <tr key={check.id}>
                                                    <td style={{ color: '#6b7280', fontWeight: '600' }}>{check.check_number}</td>
                                                    {hasVdom && (
                                                        <td>
                                                            {check.vdom && check.vdom !== 'global'
                                                                ? <span className="vdom-chip">{check.vdom}</span>
                                                                : <span style={{ color: '#9ca3af' }}>—</span>}
                                                        </td>
                                                    )}
                                                    <td>
                                                        <div className="recommendation-text">{check.check_title}</div>
                                                    </td>
                                                    <td>{getSeverityBadge(check.severity)}</td>
                                                    <td>{getStatusBadge(check.status)}</td>
                                                    <td style={{ textAlign: 'center' }}>
                                                        {check.status?.toString().toUpperCase() === 'PASS' ? (
                                                            <span style={{ color: '#9ca3af' }}>—</span>
                                                        ) : isAutoFixable(check) ? (
                                                            <button
                                                                className="hr-btn hr-btn-row"
                                                                onClick={() => handleHardenSingle(check)}
                                                            >
                                                                <img src="/icons/audit.svg" alt="" className="btn-icon" /> Harden
                                                            </button>
                                                        ) : (
                                                            <button
                                                                className="hr-btn hr-btn-outline"
                                                                onClick={() => setViewFixCheck(check)}
                                                                title="No automated fix — view the manual remediation commands"
                                                            >
                                                                <i className="fa-solid fa-clipboard" /> View Fix
                                                            </button>
                                                        )}
                                                    </td>
                                                </tr>
                                            ))}
                                        </Fragment>
                                    ))
                                ) : (
                                    <tr>
                                        <td colSpan={colCount} style={{ textAlign: 'center', padding: '40px' }}>
                                            No checks available
                                        </td>
                                    </tr>
                                )}
                                </tbody>
                            </table>
                        )}
                    </div>
                </div>
            </div>

            {/* Modals */}
            {showHardenAllModal && (
                <HardenAllModal
                    sessionId={sessionData.session_id}
                    onClose={() => setShowHardenAllModal(false)}
                    onSuccess={handleModalSuccess}
                />
            )}

            {showFixSingleModal && selectedCheck && (
                <FixSingleModal
                    check={selectedCheck}
                    assetId={sessionData?.asset_id}
                    sessionId={sessionData?.session_id}
                    deviceType={sessionData.device_type}
                    onClose={() => {
                        setShowFixSingleModal(false);
                        setSelectedCheck(null);
                    }}
                    onSuccess={handleFixSingleSuccess}
                />
            )}

            {viewFixCheck && (
                <ViewFixModal
                    checkId={viewFixCheck.check_number}
                    checkTitle={viewFixCheck.check_title}
                    resultId={viewFixCheck.id}
                    assetId={sessionData?.asset_id}
                    onClose={() => setViewFixCheck(null)}
                    onSuccess={handleModalSuccess}
                />
            )}
        </div>
    );
};

export default HardeningResults;