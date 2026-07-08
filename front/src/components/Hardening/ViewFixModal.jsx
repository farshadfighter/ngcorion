import React, { useEffect, useMemo, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    fetchFortinetManualGuidance,
    executeFortinetManualFix,
    discoverFortinetVdoms,
} from '../../store/hardeningSlice';
import CredentialsForm from './CredentialsForm';
import BackupOption from './BackupOption';
import {
    defaultCredentialsState,
    validateCredentials,
    buildCredentials,
} from './hardeningCredentials';
import '../../assets/hardening/Hardenallmodal.css';

/**
 * "View Fix" for a manual (non-auto-fixable) FortiGate check.
 *
 * Guidance-only checks keep the original read-only behaviour (show commands +
 * copy). Checks the backend marks ``executable`` can also be RUN: the modal
 * collects any parameters, then SSH credentials, calls ``manual-execute``, and
 * shows the raw device output. Manual fixes are never auto-verified.
 */
const ViewFixModal = ({ checkId, checkTitle, resultId, assetId, onClose, onSuccess }) => {
    const dispatch = useDispatch();
    const { vdomDiscovery } = useSelector((state) => state.hardening);

    const [guidance, setGuidance] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [copied, setCopied] = useState(false);

    // Execution flow. step: 1 guidance, 2 params, 3 credentials, 4 executing, 5 results
    const [step, setStep] = useState(1);
    const [paramValues, setParamValues] = useState({});
    const [sshCredentials, setSshCredentials] = useState(defaultCredentialsState);
    const [credErrors, setCredErrors] = useState({});
    const [vdomEnabled, setVdomEnabled] = useState(false);
    const [createBackup, setCreateBackup] = useState(false);
    const [formError, setFormError] = useState(null);
    const [executing, setExecuting] = useState(false);
    const [result, setResult] = useState(null);

    useEffect(() => {
        let active = true;
        setLoading(true);
        setError(null);
        dispatch(fetchFortinetManualGuidance(checkId))
            .unwrap()
            .then((data) => {
                if (!active) return;
                setGuidance(data);
                // Seed parameter form with defaults.
                const seed = {};
                (data.parameters || []).forEach((p) => { seed[p.name] = p.default ?? ''; });
                setParamValues(seed);
            })
            .catch((err) => { if (active) setError(typeof err === 'string' ? err : 'Failed to load remediation guidance.'); })
            .finally(() => { if (active) setLoading(false); });
        return () => { active = false; };
    }, [dispatch, checkId]);

    const commands = guidance?.remediation_commands ?? [];
    const parameters = guidance?.parameters ?? [];
    const executable = !!guidance?.executable && !!resultId;
    const title = guidance?.check_title || checkTitle || checkId;

    // Live preview of the commands with the operator's values substituted.
    const previewCommands = useMemo(() => {
        if (!parameters.length) return commands;
        return commands.map((line) => {
            let out = line;
            parameters.forEach((p) => {
                const val = paramValues[p.name] ?? p.default ?? '';
                const shown = p.secret && val ? '********' : val;
                out = out.split(`{${p.name}}`).join(shown);
            });
            return out;
        });
    }, [commands, parameters, paramValues]);

    const handleCopy = async () => {
        const text = (executable ? previewCommands : commands).join('\n');
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch {
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

    const handleParamChange = (name, value) => setParamValues((prev) => ({ ...prev, [name]: value }));

    const handleSSHChange = (e) => {
        const { name, value } = e.target;
        setSshCredentials((prev) => ({ ...prev, [name]: value }));
        setCredErrors((prev) => (prev[name] ? { ...prev, [name]: undefined } : prev));
    };

    const handleDetectVdoms = () => {
        if (!assetId || !sshCredentials.ssh_username || !sshCredentials.ssh_password) return;
        dispatch(discoverFortinetVdoms({
            mode: 'hardening',
            asset_id: parseInt(assetId),
            ssh_username: sshCredentials.ssh_username,
            ssh_password: sshCredentials.ssh_password,
            ssh_port: parseInt(sshCredentials.ssh_port) || 22,
        }));
    };

    const startExecute = () => {
        setFormError(null);
        setStep(parameters.length > 0 ? 2 : 3);
    };

    const validateParams = () => {
        const missing = parameters
            .filter((p) => p.required && !(paramValues[p.name] ?? p.default ?? '').toString().trim())
            .map((p) => p.label);
        if (missing.length) {
            setFormError(`Please fill in required field(s): ${missing.join(', ')}`);
            return false;
        }
        setFormError(null);
        return true;
    };

    const handleNextFromParams = () => { if (validateParams()) setStep(3); };

    const handleExecute = async () => {
        const errs = validateCredentials('fortinet', sshCredentials);
        setCredErrors(errs);
        if (Object.keys(errs).length > 0) return;
        if (!validateParams()) { setStep(2); return; }

        setFormError(null);
        setExecuting(true);
        setStep(4);
        try {
            const credentials = buildCredentials('fortinet', sshCredentials, { vdomEnabled });
            const data = await dispatch(executeFortinetManualFix({
                auditResultId: resultId,
                parameters: paramValues,
                credentials,
                skipBackup: !createBackup,
            })).unwrap();
            setResult(data);
            setStep(5);
            if (data?.success && onSuccess) onSuccess();
        } catch (err) {
            setFormError(typeof err === 'string' ? err : (err?.message || 'Execution failed.'));
            setStep(3);
        } finally {
            setExecuting(false);
        }
    };

    // ─── Renders ────────────────────────────────────────────────────────────
    const renderGuidance = () => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div>
                <h3 style={{ fontSize: '18px', color: '#1e3a5f', margin: '0 0 8px 0', fontWeight: 700 }}>{title}</h3>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                    {guidance.cis_id && <span style={badge}>CIS {guidance.cis_id}</span>}
                    {guidance.cis_section && <span style={badge}>{guidance.cis_section}</span>}
                    {guidance.severity && <span style={badge}>{guidance.severity}</span>}
                    {guidance.scope && <span style={badge}>{guidance.scope}</span>}
                    {executable && <span style={{ ...badge, background: '#dcfce7', color: '#166534', border: '1px solid #86efac' }}>Executable</span>}
                </div>
            </div>

            {guidance.remediation_guidance && (
                <div className="hardening-info-box">
                    <p style={{ margin: 0, lineHeight: 1.6 }}>{guidance.remediation_guidance}</p>
                </div>
            )}

            {(guidance.warnings ?? []).length > 0 && (
                <div className="hardening-warnings-box">
                    <h4>⚠️ Warnings:</h4>
                    <ul>{guidance.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
                </div>
            )}

            {commands.length > 0 ? (
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', margin: '0 0 12px 0' }}>
                        <h4 style={{ fontSize: '15px', color: '#1e3a5f', margin: 0, fontWeight: 700 }}>CLI Commands</h4>
                        <button onClick={handleCopy} style={{ padding: '7px 14px', background: copied ? '#059669' : '#1e3a5f', color: 'white', border: 'none', borderRadius: '6px', fontSize: '13px', fontWeight: 600, cursor: 'pointer' }}>
                            {copied ? '✓ Copied' : '📄 Copy commands'}
                        </button>
                    </div>
                    <pre style={preStyle}>{commands.join('\n')}</pre>
                    {executable && parameters.length > 0 && (
                        <p style={{ margin: '10px 0 0 0', fontSize: '12px', color: '#6b7280' }}>
                            ℹ️ Values in <code>{'{BRACES}'}</code> are collected in the next step before running.
                        </p>
                    )}
                </div>
            ) : (
                <div className="hardening-info-box">
                    <p style={{ margin: 0 }}>No CLI commands for this check — follow the guidance above.</p>
                </div>
            )}
        </div>
    );

    const renderParams = () => (
        <div className="hardening-params-form">
            <h3 style={{ fontSize: '16px', color: '#1e3a5f', margin: '0 0 16px 0', fontWeight: 700 }}>Configure parameters</h3>
            {parameters.map((p) => (
                <div key={p.name} className="hardening-form-group">
                    <label>
                        {p.label}
                        {p.required ? <span className="hardening-required">*</span>
                                    : <span style={{ color: '#6b7280', fontWeight: 400, marginLeft: '6px' }}>(optional)</span>}
                    </label>
                    {p.type === 'select' ? (
                        <select value={paramValues[p.name] ?? p.default ?? ''} onChange={(e) => handleParamChange(p.name, e.target.value)} style={inputStyle}>
                            {(p.options ?? []).map((o) => <option key={o} value={o}>{o}</option>)}
                        </select>
                    ) : (
                        <input
                            type={p.type === 'password' ? 'password' : (p.type === 'number' ? 'number' : 'text')}
                            value={paramValues[p.name] ?? ''}
                            onChange={(e) => handleParamChange(p.name, e.target.value)}
                            placeholder={p.placeholder || (p.default != null ? `default: ${p.default}` : `Enter ${p.label}`)}
                            autoComplete={p.secret ? 'new-password' : 'off'}
                            style={inputStyle}
                        />
                    )}
                    {p.description && <span style={{ fontSize: '12px', color: '#7f8c8d', display: 'block', marginTop: '4px' }}>{p.description}</span>}
                </div>
            ))}
            <div style={{ marginTop: '8px' }}>
                <h4 style={{ fontSize: '13px', color: '#1e3a5f', margin: '0 0 8px 0', fontWeight: 700 }}>Preview</h4>
                <pre style={preStyle}>{previewCommands.join('\n')}</pre>
            </div>
        </div>
    );

    const renderCredentials = () => (
        <>
            <CredentialsForm
                deviceType="fortinet"
                value={sshCredentials}
                onChange={handleSSHChange}
                errors={credErrors}
                vdomEnabled={vdomEnabled}
                onVdomEnabledChange={setVdomEnabled}
                vdomDiscovery={vdomDiscovery}
                onDetectVdoms={handleDetectVdoms}
                canDetectVdoms={!!assetId && !!sshCredentials.ssh_username && !!sshCredentials.ssh_password}
            />
            <BackupOption checked={createBackup} onChange={setCreateBackup} />
        </>
    );

    const renderExecuting = () => (
        <div className="hardening-modal-executing">
            <div className="hardening-spinner-large"></div>
            <h3>Executing Fix…</h3>
            <p>Applying the remediation on the device. Manual fixes are not auto-verified.</p>
        </div>
    );

    const renderResults = () => {
        if (!result) return <div className="hardening-modal-error"><p>No results available.</p></div>;
        const ok = result.success === true;
        return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div style={{ padding: '20px', borderRadius: '12px', borderLeft: ok ? '5px solid #1e3a5f' : '5px solid #ef4444', background: ok ? 'linear-gradient(135deg,#e8edf5 0%,#f0f4f9 100%)' : 'linear-gradient(135deg,#fee2e2 0%,#fef2f2 100%)' }}>
                    <h3 style={{ fontSize: '18px', margin: '0 0 8px 0', fontWeight: 700, color: ok ? '#1e3a5f' : '#c0392b' }}>
                        {ok ? '✓ Commands applied' : '✗ Execution reported errors'}
                    </h3>
                    <p style={{ margin: 0, color: '#6b7280', fontSize: '13px', lineHeight: 1.6 }}>
                        {ok
                            ? 'The device accepted the remediation. This is a manual control, so it was not automatically re-verified — re-run the audit to confirm compliance.'
                            : 'The device returned one or more errors. Review the output below.'}
                    </p>
                </div>

                {(result.errors ?? []).length > 0 && (
                    <div className="hardening-warnings-box">
                        <h4>Errors:</h4>
                        <ul>{result.errors.map((e, i) => <li key={i}>{e}</li>)}</ul>
                    </div>
                )}

                {result.commands_executed?.length > 0 && (
                    <div>
                        <h4 style={{ fontSize: '14px', color: '#1e3a5f', margin: '0 0 8px 0', fontWeight: 700 }}>Commands executed</h4>
                        <pre style={preStyle}>{result.commands_executed.join('\n')}</pre>
                    </div>
                )}

                {result.output && (
                    <div>
                        <h4 style={{ fontSize: '14px', color: '#1e3a5f', margin: '0 0 8px 0', fontWeight: 700 }}>Device output</h4>
                        <pre style={preStyle}>{result.output}</pre>
                    </div>
                )}

                {result.backup_created && (
                    <div style={{ background: 'linear-gradient(135deg,#e8edf5 0%,#f0f4f9 100%)', borderLeft: '5px solid #1e3a5f', padding: '14px 18px', borderRadius: '10px' }}>
                        <p style={{ margin: 0, color: '#2d4a7c', fontSize: '13px', fontWeight: 600 }}>💾 Configuration backup created before applying.</p>
                    </div>
                )}
            </div>
        );
    };

    const infoText = () => {
        if (step === 1) return 'Review the remediation for this manual check.'
            + (executable ? ' You can apply it below.' : ' Apply the steps on the device manually — nothing is executed for guidance-only checks.');
        if (step === 2) return 'Provide the values for this remediation.';
        if (step === 3) return 'Enter SSH credentials to apply the fix.';
        return '';
    };

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

                {step <= 3 && (
                    <div className="hardening-modal-info">
                        <span className="hardening-info-icon">ℹ️</span>
                        <p>{infoText()}</p>
                    </div>
                )}

                <div className="hardening-modal-body">
                    {loading && (
                        <div className="hardening-modal-loading">
                            <div className="hardening-spinner"></div>
                            <p>Loading remediation…</p>
                        </div>
                    )}
                    {!loading && error && <div className="hardening-modal-error"><p>{error}</p></div>}
                    {!loading && !error && guidance && (
                        <>
                            {step === 1 && renderGuidance()}
                            {step === 2 && renderParams()}
                            {step === 3 && renderCredentials()}
                            {step === 4 && renderExecuting()}
                            {step === 5 && renderResults()}
                        </>
                    )}

                    {formError && step !== 4 && (
                        <div className="hardening-error-message" style={{ marginTop: '16px' }}>
                            <span>⚠</span>
                            <p>{formError}</p>
                        </div>
                    )}
                </div>

                <div className="hardening-modal-footer">
                    {step === 1 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={onClose}>Close</button>
                            {!loading && !error && executable && (
                                <button className="hardening-btn-primary" onClick={startExecute}>⚡ Execute Fix</button>
                            )}
                        </>
                    )}
                    {step === 2 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={() => setStep(1)}>Back</button>
                            <button className="hardening-btn-primary" onClick={handleNextFromParams}>Next</button>
                        </>
                    )}
                    {step === 3 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={() => setStep(parameters.length > 0 ? 2 : 1)}>Back</button>
                            <button className="hardening-btn-primary" onClick={handleExecute} disabled={executing}>⚡ Execute Fix</button>
                        </>
                    )}
                    {step === 5 && (
                        <button className="hardening-btn-primary" onClick={() => { if (onSuccess && result?.success) onSuccess(); onClose(); }}>Finish</button>
                    )}
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

const preStyle = {
    background: '#0f172a',
    color: '#e2e8f0',
    padding: '16px',
    borderRadius: '8px',
    fontSize: '13px',
    lineHeight: 1.7,
    overflowX: 'auto',
    margin: 0,
    fontFamily: "'Consolas','Monaco','Courier New',monospace",
    whiteSpace: 'pre-wrap',
};

const inputStyle = {
    width: '450px',
    maxWidth: '100%',
    padding: '8px 12px',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    fontSize: '13px',
    color: '#111827',
    background: 'white',
};

export default ViewFixModal;
