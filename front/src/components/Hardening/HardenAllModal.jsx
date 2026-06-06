import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    fetchRequiredParameters,
    autoHardenWithDefaults,
    batchExecuteChecks,
    discoverFortinetVdoms,
    clearRequiredParameters,
    clearMessages
} from '../../store/hardeningSlice';
import '../../assets/hardening/Hardenallmodal.css';

// ─── Device type helpers ──────────────────────────────────────────────────────
const isLinux   = (dt) => dt === 'linux' || dt?.startsWith('linux-');
const isCisco   = (dt) => dt === 'cisco';
const isFortinet= (dt) => dt === 'fortinet';
const isApache  = (dt) => dt === 'apache';
const isMongo   = (dt) => dt === 'mongodb';
const isMssql   = (dt) => dt?.startsWith('mssql-');
const isWindows = (dt) => dt?.startsWith('windows-');
const needsSudo = (dt) => isLinux(dt) || isApache(dt) || isMongo(dt);

const HardenAllModal = ({ sessionId, assetId, deviceType, onClose, onSuccess }) => {
    const dispatch = useDispatch();
    const {
        requiredParameters,
        isFetchingParams,
        isExecuting,
        error,
        cisChecks,
        vdomDiscovery
    } = useSelector((state) => state.hardening);

    const [vdomEnabled, setVdomEnabled] = useState(false);

    const [step, setStep] = useState(1); // 1: Parameters, 2: Credentials, 3: Executing, 4: Results
    const [paramValues, setParamValues] = useState({});
    const [sshCredentials, setSshCredentials] = useState({
        // SSH-based
        ssh_username:     '',
        ssh_password:     '',
        ssh_port:         '22',
        ssh_secret:       '',       // Cisco only
        vdom:             '',       // Fortinet only
        sudo_password:    '',       // Linux / Apache / MongoDB
        // MongoDB extra
        mongo_username:   '',
        mongo_password:   '',
        mongo_port:       '27017',
        // MSSQL
        mssql_username:   '',
        mssql_password:   '',
        mssql_port:       '1433',
        // Windows (WinRM)
        windows_username: '',
        windows_password: '',
        winrm_port:       '5986',
        transport:        'ntlm',
    });
    const [executionResult, setExecutionResult] = useState(null);

    useEffect(() => {
        if (sessionId && deviceType) {
            dispatch(fetchRequiredParameters({ sessionId, deviceType }));
        }
        return () => {
            dispatch(clearRequiredParameters());
            dispatch(clearMessages());
        };
    }, [dispatch, sessionId, deviceType]);

    useEffect(() => {
        if (requiredParameters?.required_parameters) {
            const initialValues = {};
            Object.entries(requiredParameters.required_parameters).forEach(([key, param]) => {
                initialValues[key] = param.default || '';
            });
            setParamValues(prev => {
                const hasChanged = JSON.stringify(prev) !== JSON.stringify(initialValues);
                return hasChanged ? initialValues : prev;
            });
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [requiredParameters?.required_parameters]);

    const handleParamChange = (key, value) => setParamValues(prev => ({ ...prev, [key]: value }));

    const handleSSHChange = (e) => {
        const { name, value } = e.target;
        setSshCredentials(prev => ({ ...prev, [name]: value }));
    };

    const handleDetectVdoms = () => {
        if (!assetId || !sshCredentials.ssh_username || !sshCredentials.ssh_password) return;
        dispatch(discoverFortinetVdoms({
            mode:         'hardening',
            asset_id:     parseInt(assetId),
            ssh_username: sshCredentials.ssh_username,
            ssh_password: sshCredentials.ssh_password,
            ssh_port:     parseInt(sshCredentials.ssh_port) || 22,
        }));
    };

    const validateParameters = () => {
        if (!requiredParameters?.required_parameters) return true;
        const errors = [];
        Object.entries(requiredParameters.required_parameters).forEach(([key, param]) => {
            if (!param.optional && !paramValues[key]?.trim()) errors.push(param.description || key);
        });
        if (errors.length > 0) {
            alert(`Please fill in required fields:\n${errors.join('\n')}`);
            return false;
        }
        return true;
    };

    const validateCredentials = () => {
        if (isWindows(deviceType)) {
            if (!sshCredentials.windows_username.trim()) { alert('Windows Username is required'); return false; }
            if (!sshCredentials.windows_password.trim()) { alert('Windows Password is required'); return false; }
        } else if (isMssql(deviceType)) {
            if (!sshCredentials.mssql_username.trim()) { alert('SQL Server Username is required'); return false; }
            if (!sshCredentials.mssql_password.trim()) { alert('SQL Server Password is required'); return false; }
        } else {
            if (!sshCredentials.ssh_username.trim()) { alert('SSH Username is required'); return false; }
            if (!sshCredentials.ssh_password.trim()) { alert('SSH Password is required'); return false; }
        }
        return true;
    };

    const handleNextFromParams = () => {
        if (validateParameters()) setStep(2);
    };

    const handleExecute = async () => {
        if (!validateCredentials()) return;
        setStep(3);

        try {
            let credentials = {};

            if (isWindows(deviceType)) {
                credentials = {
                    windows_username: sshCredentials.windows_username,
                    windows_password: sshCredentials.windows_password,
                    winrm_port:       parseInt(sshCredentials.winrm_port) || 5986,
                    transport:        sshCredentials.transport || 'ntlm',
                };
            } else if (isMssql(deviceType)) {
                credentials = {
                    mssql_username: sshCredentials.mssql_username,
                    mssql_password: sshCredentials.mssql_password,
                    mssql_port:     parseInt(sshCredentials.mssql_port) || 1433,
                };
            } else {
                credentials = {
                    ssh_username: sshCredentials.ssh_username,
                    ssh_password: sshCredentials.ssh_password,
                    ssh_port:     parseInt(sshCredentials.ssh_port) || 22,
                    ...(isCisco(deviceType)    && sshCredentials.ssh_secret     && { ssh_secret:     sshCredentials.ssh_secret }),
                    ...(isFortinet(deviceType) && vdomEnabled && sshCredentials.vdom && { vdom:        sshCredentials.vdom }),
                    ...(needsSudo(deviceType)  && sshCredentials.sudo_password  && { sudo_password:  sshCredentials.sudo_password }),
                    ...(isMongo(deviceType)    && sshCredentials.mongo_username  && { mongo_username: sshCredentials.mongo_username }),
                    ...(isMongo(deviceType)    && sshCredentials.mongo_password  && { mongo_password: sshCredentials.mongo_password }),
                    ...(isMongo(deviceType)    && { mongo_port: parseInt(sshCredentials.mongo_port) || 27017 }),
                };
            }

            const result = await dispatch(autoHardenWithDefaults({
                sessionId,
                assetId,
                deviceType,
                credentials,
            })).unwrap();

            setExecutionResult(result);
            setStep(4);
        } catch (error) {
            console.error('Error executing hardening fixes:', error);
            setStep(2);
        }
    };

    const handleFinish = () => {
        if (onSuccess) onSuccess();
        onClose();
    };

    // ─── Input style helper ────────────────────────────────────────────────────
    const inputStyle = {
        width: '450px',
        padding: '8px 12px',
        border: '1px solid #d1d5db',
        borderRadius: '6px',
        fontSize: '13px',
        color: '#111827',
        transition: 'all 0.2s',
        background: 'white'
    };
    const hintStyle = { fontSize: '12px', color: '#7f8c8d', display: 'block', marginTop: '4px' };

    // ─── Renders ──────────────────────────────────────────────────────────────

    const renderParametersForm = () => {
        if (isFetchingParams) {
            return (
                <div className="hardening-modal-loading">
                    <div className="hardening-spinner"></div>
                    <p>Loading parameters...</p>
                </div>
            );
        }
        if (!requiredParameters?.required_parameters || Object.keys(requiredParameters.required_parameters).length === 0) {
            return (
                <div className="hardening-no-params">
                    <p>No additional parameters required.</p>
                    <p className="hardening-sub-text">Click Next to proceed with credentials.</p>
                </div>
            );
        }
        return (
            <div className="hardening-params-form">
                {Object.entries(requiredParameters.required_parameters).map(([key, param]) => (
                    <div key={key} className="hardening-form-group">
                        <label>
                            {param.description || key}
                            {!param.optional && <span className="hardening-required">*</span>}
                        </label>
                        <div className="hardening-input-with-meta">
                            <input type="text" value={paramValues[key] || ''} onChange={(e) => handleParamChange(key, e.target.value)} placeholder={param.default || `Enter ${key}`} style={inputStyle} />
                            {param.usage && <span className="hardening-param-usage">{param.usage}</span>}
                        </div>
                    </div>
                ))}
            </div>
        );
    };

    const renderCredentialsForm = () => {
        // ── Windows ──────────────────────────────────────────────────────────
        if (isWindows(deviceType)) {
            return (
                <div className="hardening-ssh-form">
                    <div className="hardening-form-group">
                        <label>Windows Username<span className="hardening-required">*</span></label>
                        <input type="text" name="windows_username" value={sshCredentials.windows_username} onChange={handleSSHChange} placeholder="Administrator or DOMAIN\user" autoComplete="username" style={inputStyle} />
                    </div>
                    <div className="hardening-form-group">
                        <label>Windows Password<span className="hardening-required">*</span></label>
                        <input type="password" name="windows_password" value={sshCredentials.windows_password} onChange={handleSSHChange} placeholder="Windows admin password" autoComplete="current-password" style={inputStyle} />
                    </div>
                    <div className="hardening-form-group">
                        <label>WinRM Port</label>
                        <input type="number" name="winrm_port" value={sshCredentials.winrm_port} onChange={handleSSHChange} placeholder="5986" autoComplete="off" style={inputStyle} />
                        <span style={hintStyle}>Default: 5986 (HTTPS)</span>
                    </div>
                    <div className="hardening-form-group">
                        <label>Transport</label>
                        <select name="transport" value={sshCredentials.transport} onChange={handleSSHChange} style={inputStyle}>
                            <option value="ntlm">NTLM</option>
                            <option value="kerberos">Kerberos</option>
                            <option value="credssp">CredSSP</option>
                            <option value="basic">Basic</option>
                        </select>
                    </div>
                </div>
            );
        }

        // ── MSSQL ────────────────────────────────────────────────────────────
        if (isMssql(deviceType)) {
            return (
                <div className="hardening-ssh-form">
                    <div className="hardening-form-group">
                        <label>SQL Server Username<span className="hardening-required">*</span></label>
                        <input type="text" name="mssql_username" value={sshCredentials.mssql_username} onChange={handleSSHChange} placeholder="sa or sysadmin account" autoComplete="username" style={inputStyle} />
                    </div>
                    <div className="hardening-form-group">
                        <label>SQL Server Password<span className="hardening-required">*</span></label>
                        <input type="password" name="mssql_password" value={sshCredentials.mssql_password} onChange={handleSSHChange} placeholder="SQL Server password" autoComplete="current-password" style={inputStyle} />
                    </div>
                    <div className="hardening-form-group">
                        <label>SQL Server Port</label>
                        <input type="number" name="mssql_port" value={sshCredentials.mssql_port} onChange={handleSSHChange} placeholder="1433" autoComplete="off" style={inputStyle} />
                    </div>
                </div>
            );
        }

        // ── SSH-based: Linux, Cisco, Fortinet, Apache, MongoDB ───────────────
        return (
            <div className="hardening-ssh-form">
                <div className="hardening-form-group">
                    <label>SSH Username<span className="hardening-required">*</span></label>
                    <input type="text" name="ssh_username" value={sshCredentials.ssh_username} onChange={handleSSHChange} placeholder="Enter SSH username" autoComplete="username" style={inputStyle} />
                </div>
                <div className="hardening-form-group">
                    <label>SSH Password<span className="hardening-required">*</span></label>
                    <input type="password" name="ssh_password" value={sshCredentials.ssh_password} onChange={handleSSHChange} placeholder="Enter SSH password" autoComplete="current-password" style={inputStyle} />
                </div>
                <div className="hardening-form-group">
                    <label>SSH Port</label>
                    <input type="number" name="ssh_port" value={sshCredentials.ssh_port} onChange={handleSSHChange} placeholder="22" min="1" max="65535" autoComplete="off" style={inputStyle} />
                </div>

                {isCisco(deviceType) && (
                    <div className="hardening-form-group">
                        <label>Enable Password</label>
                        <input type="password" name="ssh_secret" value={sshCredentials.ssh_secret} onChange={handleSSHChange} placeholder="Enter enable secret (optional)" autoComplete="off" style={inputStyle} />
                        <span style={hintStyle}>Required for privileged commands</span>
                    </div>
                )}

                {isFortinet(deviceType) && (
                    <div className="hardening-form-group">
                        <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                            <input
                                type="checkbox"
                                checked={vdomEnabled}
                                onChange={(e) => setVdomEnabled(e.target.checked)}
                                style={{ width: '16px', height: '16px', cursor: 'pointer' }}
                            />
                            This FortiGate uses VDOMs
                        </label>

                        {vdomEnabled && (
                            <div style={{ marginTop: '8px' }}>
                                <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '6px' }}>
                                    <button
                                        type="button"
                                        onClick={handleDetectVdoms}
                                        disabled={vdomDiscovery?.isDiscovering || !sshCredentials.ssh_username || !sshCredentials.ssh_password}
                                        style={{
                                            padding: '6px 14px', fontSize: '13px', fontWeight: 600,
                                            background: '#2563eb', color: 'white', border: 'none',
                                            borderRadius: '6px', cursor: 'pointer',
                                            opacity: (vdomDiscovery?.isDiscovering || !sshCredentials.ssh_username || !sshCredentials.ssh_password) ? 0.5 : 1,
                                        }}
                                    >
                                        {vdomDiscovery?.isDiscovering ? 'Detecting…' : 'Show VDOMs'}
                                    </button>
                                    {vdomDiscovery?.vdoms !== null && !vdomDiscovery?.isDiscovering && (
                                        <span style={{
                                            padding: '3px 10px', borderRadius: '12px', fontSize: '12px', fontWeight: 600,
                                            background: vdomDiscovery.vdoms.length > 0 ? '#d1fae5' : '#f3f4f6',
                                            color: vdomDiscovery.vdoms.length > 0 ? '#065f46' : '#6b7280',
                                            border: `1px solid ${vdomDiscovery.vdoms.length > 0 ? '#6ee7b7' : '#d1d5db'}`,
                                        }}>
                                            {vdomDiscovery.vdoms.length > 0
                                                ? `✓ VDOM Enabled (${vdomDiscovery.vdoms.length})`
                                                : 'No VDOMs found'}
                                        </span>
                                    )}
                                </div>
                                {vdomDiscovery?.error && (
                                    <span style={{ fontSize: '12px', color: '#dc2626', display: 'block', marginBottom: '4px' }}>
                                        {vdomDiscovery.error}
                                    </span>
                                )}
                                {vdomDiscovery?.vdoms?.length > 0 ? (
                                    <select name="vdom" value={sshCredentials.vdom} onChange={handleSSHChange} style={inputStyle}>
                                        <option value="">Select VDOM (default: root)</option>
                                        {vdomDiscovery.vdoms.map((v) => (
                                            <option key={v} value={v}>{v}</option>
                                        ))}
                                    </select>
                                ) : (
                                    <input type="text" name="vdom" value={sshCredentials.vdom} onChange={handleSSHChange} placeholder="VDOM name (e.g. root)" autoComplete="off" style={inputStyle} />
                                )}
                                <span style={hintStyle}>Click "Show VDOMs" to list virtual domains, then pick the target VDOM.</span>
                            </div>
                        )}
                    </div>
                )}

                {needsSudo(deviceType) && (
                    <div className="hardening-form-group">
                        <label>Sudo Password</label>
                        <input type="password" name="sudo_password" value={sshCredentials.sudo_password} onChange={handleSSHChange} placeholder="Sudo password (optional)" autoComplete="off" style={inputStyle} />
                        <span style={hintStyle}>Required for root access (defaults to SSH password)</span>
                    </div>
                )}

                {isMongo(deviceType) && (
                    <>
                        <div className="hardening-form-group">
                            <label>MongoDB Username</label>
                            <input type="text" name="mongo_username" value={sshCredentials.mongo_username} onChange={handleSSHChange} placeholder="admin (optional)" autoComplete="off" style={inputStyle} />
                        </div>
                        <div className="hardening-form-group">
                            <label>MongoDB Password</label>
                            <input type="password" name="mongo_password" value={sshCredentials.mongo_password} onChange={handleSSHChange} placeholder="MongoDB password (optional)" autoComplete="off" style={inputStyle} />
                        </div>
                        <div className="hardening-form-group">
                            <label>MongoDB Port</label>
                            <input type="number" name="mongo_port" value={sshCredentials.mongo_port} onChange={handleSSHChange} placeholder="27017" autoComplete="off" style={inputStyle} />
                        </div>
                    </>
                )}
            </div>
        );
    };

    const renderExecuting = () => (
        <div className="hardening-modal-executing">
            <div className="hardening-spinner-large"></div>
            <h3>Executing Hardening...</h3>
            <p>Please wait while we apply the security hardening configurations.</p>
            <p>This may take a few minutes.</p>
        </div>
    );

    const renderResults = () => {
        if (!executionResult) return <div className="hardening-modal-error"><p>No results available.</p></div>;

        const successCount = executionResult.successful || 0;
        const failedCount  = executionResult.failed     || 0;
        const skippedList  = Array.isArray(executionResult.skipped) ? executionResult.skipped : [];
        const skippedCount = skippedList.length;
        const results      = executionResult.results || [];

        return (
            <div>
                <div className="hardening-results-summary">
                    <div className="hardening-result-item success">
                        <span className="hardening-result-icon">✓</span>
                        <div><strong>{successCount}</strong><span>Successful</span></div>
                    </div>
                    <div className="hardening-result-item failed">
                        <span className="hardening-result-icon">✗</span>
                        <div><strong>{failedCount}</strong><span>Failed</span></div>
                    </div>
                    <div className="hardening-result-item skipped">
                        <span className="hardening-result-icon">⊘</span>
                        <div><strong>{skippedCount}</strong><span>Skipped</span></div>
                    </div>
                </div>

                {/* Per-check results table */}
                {(results.length > 0 || skippedList.length > 0) && (
                    <div className="result-table-wrapper" style={{ marginTop: '24px', maxHeight: '340px', overflowY: 'auto' }}>
                        <table className="result-table">
                            <thead>
                                <tr>
                                    <th>Section</th>
                                    <th>Description</th>
                                    <th>Result</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {results.map((r) => (
                                    <tr key={r.check_id}>
                                        <td style={{ color: r.success ? '#1e3a5f' : '#ef4444', fontWeight: '600' }}>{r.check_id}</td>
                                        <td><div className="recommendation-text">{r.check_title || r.check_id}</div></td>
                                        <td>
                                            {r.success
                                                ? <span className="result-badge result-success">Fixed</span>
                                                : <span className="result-badge result-fail">Failed</span>}
                                        </td>
                                        <td style={{ fontSize: '12px', color: '#6b7280', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                            {r.error_message || r.verification_result || '—'}
                                        </td>
                                    </tr>
                                ))}
                                {skippedList.map((checkId) => (
                                    <tr key={checkId}>
                                        <td style={{ color: '#9ca3af', fontWeight: '600' }}>{checkId}</td>
                                        <td>—</td>
                                        <td><span className="result-badge result-unknown">Skipped</span></td>
                                        <td style={{ fontSize: '12px', color: '#9ca3af' }}>Not auto-fixable</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        );
    };

    // ─── Credential form label by device type ─────────────────────────────────
    const credentialStepLabel = isWindows(deviceType)
        ? 'Enter Windows credentials to execute hardening fixes.'
        : isMssql(deviceType)
            ? 'Enter SQL Server credentials to execute hardening fixes.'
            : 'Enter SSH credentials to execute hardening fixes.';

    return (
        <div className="hardening-modal-overlay" onClick={onClose}>
            <div className="hardening-modal-content hardening-modal-large" onClick={(e) => e.stopPropagation()}>
                <div className="hardening-modal-header">
                    <div className="hardening-modal-title">
                        <span className="hardening-modal-icon"><img src="/icons/audit.svg" alt="" className="btn-icon" /></span>
                        <h2>Harden All Failed Checks</h2>
                    </div>
                    <button className="hardening-modal-close" onClick={onClose}>×</button>
                </div>

                {step <= 2 && (
                    <div className="hardening-modal-info">
                        <span className="hardening-info-icon">ℹ️</span>
                        <p>
                            {step === 1
                                ? 'Review and configure parameters for hardening all failed checks.'
                                : credentialStepLabel}
                        </p>
                    </div>
                )}

                <div className="hardening-modal-body">
                    {step === 1 && renderParametersForm()}
                    {step === 2 && renderCredentialsForm()}
                    {step === 3 && renderExecuting()}
                    {step === 4 && renderResults()}
                </div>

                <div className="hardening-modal-footer">
                    {step === 1 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={onClose}>Cancel</button>
                            <button className="hardening-btn-primary" onClick={handleNextFromParams} disabled={isFetchingParams}>Next</button>
                        </>
                    )}
                    {step === 2 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={() => setStep(1)}>Back</button>
                            <button className="hardening-btn-primary" onClick={handleExecute} disabled={isExecuting}>Execute Hardening</button>
                        </>
                    )}
                    {step === 4 && (
                        <button className="hardening-btn-primary" onClick={handleFinish}>Finish</button>
                    )}
                </div>

                {error && step !== 4 && (
                    <div className="hardening-error-message" style={{ margin: '16px 24px' }}>
                        <span>⚠</span>
                        <p>{typeof error === 'string' ? error : (error?.message || 'Operation failed')}</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default HardenAllModal;