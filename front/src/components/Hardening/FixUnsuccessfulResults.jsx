import { Fragment, useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { fetchAuditResults, fetchFortinetTemplatedChecks, getDeviceName } from "../../store/hardeningSlice";
import HardenAllModal from './HardenAllModal';
import FixSingleModal from './FixSingleModal';
import ViewFixModal from './ViewFixModal';
import { groupChecksByScope } from './vdomScope';
// This screen reuses the Auditing result table's styling (result-table,
// result-badge, severity-badge). The build inlines every stylesheet into one
// bundle so it renders either way, but the dependency is real — import it so
// the styles cannot disappear if that ever changes.
import '../../assets/Auditing.css';

const titleCase = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : null);

export const FixUnsuccessfulResults = ({ sessionData, onClose, onNavigateToAuditing }) => {
    const dispatch = useDispatch();
    const { cisChecks, isLoading, fortinetTemplatedChecks } = useSelector((state) => state.hardening);
    const [showHardenAllModal, setShowHardenAllModal] = useState(false);
    const [showFixSingleModal, setShowFixSingleModal] = useState(false);
    const [selectedCheck, setSelectedCheck] = useState(null);
    const [viewFixCheck, setViewFixCheck] = useState(null);
    const [activeTab, setActiveTab] = useState('audit');

    const isFortinet = sessionData?.device_type === 'fortinet';

    useEffect(() => {
        if (sessionData?.session_id && sessionData?.device_type) {
            dispatch(fetchAuditResults({
                sessionId: sessionData.session_id,
                deviceType: sessionData.device_type
            }));
        }
    }, [sessionData?.session_id, sessionData?.device_type, dispatch]);

    // FortiGate: load which checks are auto-fixable so we can show a "Manual"
    // badge (instead of a dead-end "Harden" button) for review-only checks.
    useEffect(() => {
        if (isFortinet) dispatch(fetchFortinetTemplatedChecks());
    }, [isFortinet, dispatch]);

    // A check is auto-fixable when it's not a FortiGate device, or the templated
    // list hasn't loaded (fail open — never hide "Harden" by mistake), or the
    // check number is in the templated set.
    const templatedSet = new Set(fortinetTemplatedChecks || []);
    const isAutoFixable = (check) =>
        !isFortinet || templatedSet.size === 0 || templatedSet.has(check.check_number);

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

    const handleViewFix = (check) => setViewFixCheck(check);

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

    const chipStyle = {
        display: 'inline-block',
        maxWidth: '100%',
        padding: '2px 8px',
        borderRadius: '10px',
        fontSize: '11px',
        fontWeight: 600,
        lineHeight: 1.4,
        textAlign: 'left',
    };

    /* Per-control risk level, same badge as the Auditing and Hardening Result
       tables: all three read the same /sessions/{id}/results payload, which
       already carries `severity` per row. */
    const getSeverityBadge = (severity) => {
        const level = severity?.toString().toLowerCase();
        if (!level) return <span style={{ color: '#9ca3af' }}>—</span>;
        return (
            <span className={`severity-badge severity-${level}`}>
                {titleCase(level)}
            </span>
        );
    };

    const getStatusBadge = (check) => {
        const s = check.status?.toString().toUpperCase();
        const base =
            s === 'PASS' ? <span className="result-badge result-success">Successful</span>
            : s === 'FAIL' ? <span className="result-badge result-fail">Unsuccessful</span>
            : s === 'ERROR' ? <span className="result-badge result-error">Error</span>
            : <span className="result-badge result-unknown">Unknown</span>;
        // Live feedback from this session's hardening (set by markCheckHardened —
        // no reload / re-audit needed to see it).
        const vdomSuffix = check.hardenedVdom ? ` (VDOM: ${check.hardenedVdom})` : '';
        return (
            <>
                {base}
                {check.justHardened && (
                    <div style={{ marginTop: '4px' }}>
                        <span style={{ ...chipStyle, background: '#dcfce7', color: '#166534', border: '1px solid #86efac' }}
                              title={`Fixed and verified in this session${vdomSuffix}`}>
                            ✓ Hardened{vdomSuffix}
                        </span>
                    </div>
                )}
                {check.manualApplied && !check.justHardened && (
                    <div style={{ marginTop: '4px' }}>
                        <span style={{ ...chipStyle, background: '#fef3c7', color: '#92400e', border: '1px solid #fcd34d' }}
                              title={`Remediation pushed to the device${vdomSuffix}; manual checks are not auto-verified`}>
                            <i className="fa-solid fa-screwdriver-wrench" /> Applied — re-audit to verify{vdomSuffix}
                        </span>
                    </div>
                )}
            </>
        );
    };

    const getDeviceLabel = (dt) => {
        if (dt === 'fortinet')          return 'FortiGate';
        if (dt === 'linux' || dt?.startsWith('linux-')) return 'Linux';
        if (dt === 'apache')            return 'Apache';
        if (dt === 'mongodb')           return 'MongoDB';
        if (dt?.startsWith('mssql-'))   return 'SQL Server';
        if (dt?.startsWith('windows-')) return 'Windows';
        return 'Cisco';
    };

    const totalChecks   = cisChecks?.length || 0;
    const passedChecks  = cisChecks?.filter(c => c.status?.toString().toUpperCase() === 'PASS').length || 0;
    const failedChecks  = cisChecks?.filter(c => c.status?.toString().toUpperCase() === 'FAIL').length || 0;
    const compliancePercentage    = totalChecks > 0 ? Math.round((passedChecks / totalChecks) * 100) : 0;
    const nonCompliancePercentage = totalChecks > 0 ? Math.round((failedChecks / totalChecks) * 100) : 0;

    const displayedChecks = activeTab === 'unsuccessful'
        ? cisChecks?.filter(c => c.status?.toString().toUpperCase() === 'FAIL')
        : cisChecks;

    // Split into Global vs per-VDOM groups (FortiGate multi-VDOM audits tag
    // each row with its vdom; flat devices get a single unlabeled group).
    // Section, [VDOM], Recommendation, Risk Level, Result, Action
    const { hasVdom, groups } = groupChecksByScope(displayedChecks);
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

                {/* One panel: the conformity numbers lead (CSS `order` lifts the
                    summary above this block), the session details sit under
                    them. Same shell as HardeningResults. */}
                <div className="hr-panel">
                <div className="result-stats-container">
                    <div className="result-card result-card-info">
                        <div className="card-label">Benchmark</div>
                        <div className="card-value">{getDeviceLabel(sessionData?.sub_device_type || sessionData?.device_type)} CIS</div>
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
                            {sessionData?.completed_at ? new Date(sessionData.completed_at).toLocaleDateString() : 'N/A'}
                        </div>
                    </div>

                    <div className="result-card result-card-info">
                        <div className="card-label">Device Type</div>
                        <div className="card-value">
                            {sessionData?.device_type
                                ? getDeviceName(sessionData.sub_device_type || sessionData.device_type)
                                : 'N/A'}
                        </div>
                    </div>

                    <div className="result-card result-card-info">
                        <div className="card-label">Status</div>
                        <div className="card-value">{titleCase(sessionData?.status) || 'Completed'}</div>
                    </div>

                </div>

                <div className="result-stats-summary">
                    <div className="result-card result-card-success">
                        <div className="card-percent">{compliancePercentage}%</div>
                        <div className="card-sub">{passedChecks} of {totalChecks} checks</div>
                        <div className="card-label">Conformity</div>
                    </div>

                    <div className="result-card result-card-danger">
                        <div className="card-percent">{nonCompliancePercentage}%</div>
                        <div className="card-sub">{failedChecks} of {totalChecks} checks</div>
                        <div className="card-label">Non-Conformity</div>
                    </div>

                    <div className="result-card result-card-total">
                        <div className="card-number">{totalChecks}</div>
                        <div className="card-label">Total Conditions</div>
                    </div>
                </div>
                </div>

                {/* Tabs and Table. Flex column with min-height:0 so the table
                    below can scroll — a plain block here grows to fit the rows
                    and leaves .result-table-wrapper nothing to scroll against. */}
                <div style={{
                    padding: '0 24px 24px',
                    flex: 1,
                    minHeight: 0,
                    display: 'flex',
                    flexDirection: 'column',
                }}>
                    {/* Shared toolbar styling with HardeningResults — see
                        .result-toolbar in Auditing.css. */}
                    <div className="result-toolbar">
                        <div className="result-toolbar-left">
                            <button
                                className={`result-toolbar-tab${activeTab === 'audit' ? ' is-active' : ''}`}
                                onClick={() => setActiveTab('audit')}
                            >
                                Audit Result
                            </button>
                            <button
                                className={`result-toolbar-tab${activeTab === 'unsuccessful' ? ' is-active' : ''}`}
                                onClick={() => setActiveTab('unsuccessful')}
                            >
                                Unsuccessful Section
                            </button>
                        </div>
                        <div className="result-toolbar-right">
                            {onNavigateToAuditing && (
                                <button
                                    className="result-toolbar-btn result-toolbar-btn-outline"
                                    onClick={onNavigateToAuditing}
                                >
                                    <i className="fa-solid fa-magnifying-glass" /> Go to Auditing
                                </button>
                            )}
                            <button
                                className="result-toolbar-btn result-toolbar-btn-primary"
                                onClick={handleHardenAll}
                                disabled={failedChecks === 0}
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
                                {displayedChecks && displayedChecks.length > 0 ? (
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
                                                    <td style={{
                                                        color: check.status?.toString().toUpperCase() === 'FAIL' ? '#ef4444' : '#6b7280',
                                                        fontWeight: '600',
                                                    }}>{check.check_number}</td>
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
                                                    <td>{getStatusBadge(check)}</td>
                                                    <td style={{ textAlign: 'center' }}>
                                                        {check.status?.toString().toUpperCase() === 'FAIL' && (
                                                            isAutoFixable(check) ? (
                                                                <button
                                                                    onClick={() => handleHardenSingle(check)}
                                                                    style={{ padding: '8px 18px', background: '#1e3a5f', color: 'white', border: 'none', borderRadius: '6px', fontSize: '13px', fontWeight: '600', cursor: 'pointer', whiteSpace: 'nowrap' }}
                                                                >
                                                                    <i className="fa-solid fa-shield-halved" />️ Harden
                                                                </button>
                                                            ) : (
                                                                <button
                                                                    onClick={() => handleViewFix(check)}
                                                                    title="No automated fix — view the manual remediation commands"
                                                                    style={{ padding: '8px 16px', background: 'white', color: '#1e3a5f', border: '2px solid #1e3a5f', borderRadius: '6px', fontSize: '13px', fontWeight: '600', cursor: 'pointer', whiteSpace: 'nowrap' }}
                                                                >
                                                                    <i className="fa-solid fa-clipboard" /> View Fix
                                                                </button>
                                                            )
                                                        )}
                                                    </td>
                                                </tr>
                                            ))}
                                        </Fragment>
                                    ))
                                ) : (
                                    <tr>
                                        <td colSpan={colCount} style={{ textAlign: 'center', padding: '40px' }}>
                                            {activeTab === 'unsuccessful' ? 'No unsuccessful checks' : 'No results'}
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

            {/* sub_device_type first: the session stores the bare enum
                ("windows"), but the credential form and the API path map key
                off the detailed value ("windows-2022"). */}
            {showFixSingleModal && selectedCheck && (
                <FixSingleModal
                    check={selectedCheck}
                    assetId={sessionData?.asset_id}
                    sessionId={sessionData?.session_id}
                    deviceType={sessionData.sub_device_type || sessionData.device_type}
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

export default FixUnsuccessfulResults;