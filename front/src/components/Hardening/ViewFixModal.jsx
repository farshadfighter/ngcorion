import React, { useEffect, useMemo, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    fetchFortinetManualGuidance,
    executeFortinetManualFix,
    fetchFortinetDeviceOptions,
    discoverFortinetVdoms,
    markCheckHardened,
} from '../../store/hardeningSlice';
import { vdomBadgeLabel, wrapCommandsForDisplay } from './vdomScope';
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
 * copy). Checks the backend marks ``executable`` can also be RUN. Parameters are
 * smart dropdowns populated from real data, not free text:
 *   - source "audit_evidence": options are the failing objects already listed in
 *     the audit evidence (e.g. Policy IDs) — rendered as a multi-select; the
 *     command block repeats per selected target.
 *   - source "device": options are existing device objects fetched live over SSH
 *     (AV profiles, IPS sensors, application lists, interfaces, admins, ...) —
 *     rendered as a dropdown. Because the fetch needs SSH credentials, the
 *     credentials step now comes BEFORE the parameters step.
 *   - no source: values the operator must invent (new passwords, hostnames, IPs)
 *     stay free-text.
 * Manual fixes are never auto-verified.
 */
const ViewFixModal = ({ checkId, checkTitle, resultId, assetId, onClose, onSuccess }) => {
    const dispatch = useDispatch();
    const { vdomDiscovery } = useSelector((state) => state.hardening);

    const [guidance, setGuidance] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [copied, setCopied] = useState(false);

    // Execution flow. step: 1 guidance, 2 credentials, 3 params, 4 executing, 5 results
    const [step, setStep] = useState(1);
    const [paramValues, setParamValues] = useState({});   // multi params hold arrays
    const [extraValues, setExtraValues] = useState({});   // "not listed" additions for multi params
    const [deviceOptions, setDeviceOptions] = useState({}); // option_type -> {loading, options, error}
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
        dispatch(fetchFortinetManualGuidance({ checkId, resultId }))
            .unwrap()
            .then((data) => {
                if (!active) return;
                setGuidance(data);
                // Seed the parameter form: multi-selects start with every failing
                // target selected (they are all non-compliant); others use defaults.
                const seed = {};
                (data.parameters || []).forEach((p) => {
                    seed[p.name] = p.multi ? (p.options || []) : (p.default ?? '');
                });
                setParamValues(seed);
            })
            .catch((err) => { if (active) setError(typeof err === 'string' ? err : 'Failed to load remediation guidance.'); })
            .finally(() => { if (active) setLoading(false); });
        return () => { active = false; };
    }, [dispatch, checkId, resultId]);

    const commands = guidance?.remediation_commands ?? [];
    const parameters = guidance?.parameters ?? [];
    const executable = !!guidance?.executable && !!resultId;
    const title = guidance?.check_title || checkTitle || checkId;
    // VDOM context the fix lands in ("global"/"root"/<name>; null on flat devices).
    const targetVdom = guidance?.target_vdom || null;
    // Display-only: show the scope wrapper the SSH engine adds around the block.
    const forDisplay = (cmds) => wrapCommandsForDisplay(cmds, guidance?.scope, targetVdom);

    // ─── Parameter helpers ──────────────────────────────────────────────────
    const multiSelected = (p) => {
        const v = paramValues[p.name];
        if (Array.isArray(v)) return v;
        return v ? String(v).split(',').map((s) => s.trim()).filter(Boolean) : [];
    };

    const parseExtra = (p) =>
        (extraValues[p.name] || '')
            .split(p.type === 'number' ? /[\s,]+/ : /,/)
            .map((s) => s.trim())
            .filter(Boolean);

    // Final value used for preview + execution (multi -> array of targets).
    const effectiveValue = (p) => {
        if (p.multi) return [...new Set([...multiSelected(p), ...parseExtra(p)])];
        return (paramValues[p.name] ?? p.default ?? '').toString();
    };

    const deviceState = (p) => deviceOptions[p.option_type] || {};

    // Fetched device options, with the catalog default kept as a choice.
    const deviceChoices = (p) => {
        const fetched = deviceState(p).options || [];
        return p.default && !fetched.includes(p.default) ? [p.default, ...fetched] : fetched;
    };

    // Load device-backed dropdowns as soon as the params step opens (credentials
    // were collected in the previous step).
    useEffect(() => {
        if (step !== 3) return;
        const types = [...new Set(
            parameters.filter((p) => p.source === 'device' && p.option_type).map((p) => p.option_type)
        )];
        types.forEach((t) => {
            const cur = deviceOptions[t];
            if (cur?.loading || cur?.options) return;
            setDeviceOptions((prev) => ({ ...prev, [t]: { loading: true } }));
            dispatch(fetchFortinetDeviceOptions({
                auditResultId: resultId,
                optionType: t,
                credentials: buildCredentials('fortinet', sshCredentials, { vdomEnabled }),
            }))
                .unwrap()
                .then((data) => setDeviceOptions((prev) => ({
                    ...prev, [t]: { loading: false, options: data.options || [] },
                })))
                .catch((err) => setDeviceOptions((prev) => ({
                    ...prev,
                    [t]: {
                        loading: false,
                        options: [],
                        error: typeof err === 'string' ? err : 'Could not load options from the device.',
                    },
                })));
        });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [step]);

    // When a device dropdown loads and the current value isn't a valid choice,
    // snap to the default (if listed) or the first option.
    useEffect(() => {
        parameters.forEach((p) => {
            if (p.source !== 'device') return;
            const st = deviceState(p);
            if (st.loading || !st.options || st.error || !st.options.length) return;
            const choices = deviceChoices(p);
            const cur = (paramValues[p.name] ?? '').toString();
            if (!choices.includes(cur)) {
                setParamValues((prev) => ({ ...prev, [p.name]: choices[0] }));
            }
        });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [deviceOptions]);

    // Live preview; a multi parameter repeats the whole command block per target.
    const previewCommands = useMemo(() => {
        if (!parameters.length) return commands;
        const substitute = (vals) => commands.map((line) => {
            let out = line;
            parameters.forEach((p) => {
                const val = vals[p.name] ?? '';
                const shown = p.secret && val ? '********' : val;
                out = out.split(`{${p.name}}`).join(shown);
            });
            return out;
        });
        const base = {};
        parameters.forEach((p) => { if (!p.multi) base[p.name] = effectiveValue(p); });
        const multiParam = parameters.find((p) => p.multi);
        if (!multiParam) return substitute(base);
        const targets = effectiveValue(multiParam);
        if (!targets.length) return substitute({ ...base, [multiParam.name]: `{${multiParam.name}}` });
        return targets.flatMap((t, i) => {
            const block = substitute({ ...base, [multiParam.name]: t });
            return i < targets.length - 1 ? [...block, ''] : block;
        });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [commands, parameters, paramValues, extraValues]);

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

    const toggleMultiValue = (p, value) => {
        const cur = multiSelected(p);
        const next = cur.includes(value) ? cur.filter((v) => v !== value) : [...cur, value];
        setParamValues((prev) => ({ ...prev, [p.name]: next }));
    };

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
        setStep(2);
    };

    const validateParams = () => {
        const missing = parameters
            .filter((p) => {
                const v = effectiveValue(p);
                if (p.multi) return v.length === 0;
                return p.required && !v.trim();
            })
            .map((p) => p.label);
        if (missing.length) {
            setFormError(`Please fill in required field(s): ${missing.join(', ')}`);
            return false;
        }
        setFormError(null);
        return true;
    };

    const handleNextFromCredentials = () => {
        const errs = validateCredentials('fortinet', sshCredentials);
        setCredErrors(errs);
        if (Object.keys(errs).length > 0) return;
        setFormError(null);
        if (parameters.length > 0) setStep(3);
        else handleExecute();
    };

    const handleExecute = async () => {
        const errs = validateCredentials('fortinet', sshCredentials);
        setCredErrors(errs);
        if (Object.keys(errs).length > 0) { setStep(2); return; }
        if (parameters.length > 0 && !validateParams()) return;

        // Multi parameters are sent comma-joined; the backend renders one command
        // block per target and reports per-target success.
        const payloadParams = {};
        parameters.forEach((p) => {
            const v = effectiveValue(p);
            payloadParams[p.name] = p.multi ? v.join(',') : v;
        });

        setFormError(null);
        setExecuting(true);
        setStep(4);
        try {
            const credentials = buildCredentials('fortinet', sshCredentials, { vdomEnabled });
            const data = await dispatch(executeFortinetManualFix({
                auditResultId: resultId,
                parameters: payloadParams,
                credentials,
                skipBackup: !createBackup,
            })).unwrap();
            setResult(data);
            setStep(5);
            if (data?.success) {
                // Tag the row in the results list immediately. Manual fixes are
                // never auto-verified, so the status stays FAIL — the badge says
                // "applied, re-audit to verify" instead of flipping to PASS.
                dispatch(markCheckHardened({
                    resultId,
                    verified: false,
                    targetVdom: data?.target_vdom,
                }));
                if (onSuccess) onSuccess();
            }
        } catch (err) {
            setFormError(typeof err === 'string' ? err : (err?.message || 'Execution failed.'));
            setStep(parameters.length > 0 ? 3 : 2);
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

            {targetVdom && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '12px 16px', background: 'linear-gradient(135deg,#ede9fe 0%,#f5f3ff 100%)', border: '1px solid #c4b5fd', borderLeft: '5px solid #7c3aed', borderRadius: '10px' }}>
                    <span style={{ fontSize: '18px' }}>🎯</span>
                    <span style={{ fontSize: '14px', color: '#4c1d95' }}>
                        Target VDOM: <strong>{vdomBadgeLabel(targetVdom)}</strong>
                        <span style={{ color: '#6b7280', marginLeft: '8px', fontSize: '12px' }}>
                            — the remediation runs inside this context on the device
                        </span>
                    </span>
                </div>
            )}

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
                    <pre style={preStyle}>{forDisplay(commands).join('\n')}</pre>
                    {targetVdom && (
                        <p style={{ margin: '8px 0 0 0', fontSize: '12px', color: '#6b7280' }}>
                            The <code>config global</code> / <code>config vdom</code> wrapper shows the VDOM scope — it is added automatically when executing.
                        </p>
                    )}
                    {executable && parameters.length > 0 && (
                        <p style={{ margin: '10px 0 0 0', fontSize: '12px', color: '#6b7280' }}>
                            ℹ️ Values in <code>{'{BRACES}'}</code> are selected from real device/audit data before running.
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

    // Multi-select over the failing objects parsed from the audit evidence.
    const renderEvidenceMultiParam = (p) => {
        const options = p.options ?? [];
        const selected = multiSelected(p);
        return (
            <>
                {options.length > 0 ? (
                    <div style={multiBoxStyle}>
                        {options.map((o) => (
                            <label key={o} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '4px 2px', fontSize: '13px', fontWeight: 400, cursor: 'pointer' }}>
                                <input
                                    type="checkbox"
                                    checked={selected.includes(o)}
                                    onChange={() => toggleMultiValue(p, o)}
                                />
                                <span>{p.name === 'POLICY_ID' ? `Policy ${o}` : o}</span>
                            </label>
                        ))}
                    </div>
                ) : (
                    <p style={{ margin: '4px 0', fontSize: '12px', color: '#b45309' }}>
                        ⚠️ No failing entries could be read from the audit evidence — enter them manually below.
                    </p>
                )}
                <input
                    type="text"
                    value={extraValues[p.name] ?? ''}
                    onChange={(e) => setExtraValues((prev) => ({ ...prev, [p.name]: e.target.value }))}
                    placeholder={options.length > 0 ? 'Add other values not listed (comma-separated, optional)' : `Enter ${p.label} (comma-separated)`}
                    style={{ ...inputStyle, marginTop: '6px' }}
                />
                {selected.length + parseExtra(p).length > 1 && (
                    <span style={{ fontSize: '12px', color: '#166534', display: 'block', marginTop: '4px' }}>
                        The command block will run once per selected entry ({[...new Set([...selected, ...parseExtra(p)])].length} blocks).
                    </span>
                )}
            </>
        );
    };

    // Dropdown over existing device objects fetched live over SSH.
    const renderDeviceParam = (p) => {
        const st = deviceState(p);
        if (st.loading) {
            return (
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <select disabled style={{ ...inputStyle, color: '#6b7280' }}>
                        <option>Loading from device…</option>
                    </select>
                    <div className="hardening-spinner" style={{ width: '18px', height: '18px' }}></div>
                </div>
            );
        }
        const choices = deviceChoices(p);
        if (st.error || choices.length === 0) {
            return (
                <>
                    <input
                        type="text"
                        value={paramValues[p.name] ?? ''}
                        onChange={(e) => handleParamChange(p.name, e.target.value)}
                        placeholder={p.placeholder || (p.default != null ? `default: ${p.default}` : `Enter ${p.label}`)}
                        style={inputStyle}
                    />
                    <span style={{ fontSize: '12px', color: '#b45309', display: 'block', marginTop: '4px' }}>
                        ⚠️ {st.error || 'The device returned no entries.'} Enter the name manually.
                    </span>
                </>
            );
        }
        return (
            <select
                value={(paramValues[p.name] ?? p.default ?? '').toString()}
                onChange={(e) => handleParamChange(p.name, e.target.value)}
                style={inputStyle}
            >
                {choices.map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
        );
    };

    const renderParams = () => (
        <div className="hardening-params-form">
            <h3 style={{ fontSize: '16px', color: '#1e3a5f', margin: '0 0 16px 0', fontWeight: 700 }}>Configure parameters</h3>
            {parameters.map((p) => (
                <div key={p.name} className="hardening-form-group">
                    <label>
                        {p.label}
                        {p.required || p.multi ? <span className="hardening-required">*</span>
                                    : <span style={{ color: '#6b7280', fontWeight: 400, marginLeft: '6px' }}>(optional)</span>}
                        {p.source === 'audit_evidence' && <span style={{ ...sourceTag, background: '#fef3c7', color: '#92400e' }}>from audit</span>}
                        {p.source === 'device' && <span style={{ ...sourceTag, background: '#dbeafe', color: '#1e40af' }}>from device</span>}
                    </label>
                    {p.source === 'audit_evidence' && p.multi ? renderEvidenceMultiParam(p)
                        : p.source === 'device' ? renderDeviceParam(p)
                        : p.type === 'select' ? (
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
                <h4 style={{ fontSize: '13px', color: '#1e3a5f', margin: '0 0 8px 0', fontWeight: 700 }}>
                    Preview
                    {targetVdom && (
                        <span style={{ marginLeft: '10px', padding: '2px 10px', borderRadius: '999px', fontSize: '11px', fontWeight: 600, background: '#ede9fe', color: '#4c1d95', border: '1px solid #c4b5fd' }}>
                            🎯 VDOM: {vdomBadgeLabel(targetVdom)}
                        </span>
                    )}
                </h4>
                <pre style={preStyle}>{forDisplay(previewCommands).join('\n')}</pre>
            </div>
        </div>
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
        const perTarget = result.per_target ?? [];
        return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div style={{ padding: '20px', borderRadius: '12px', borderLeft: ok ? '5px solid #1e3a5f' : '5px solid #ef4444', background: ok ? 'linear-gradient(135deg,#e8edf5 0%,#f0f4f9 100%)' : 'linear-gradient(135deg,#fee2e2 0%,#fef2f2 100%)' }}>
                    <h3 style={{ fontSize: '18px', margin: '0 0 8px 0', fontWeight: 700, color: ok ? '#1e3a5f' : '#c0392b' }}>
                        {ok ? '✓ Successfully applied' : '✗ Execution reported errors'}
                    </h3>
                    <p style={{ margin: 0, color: '#6b7280', fontSize: '13px', lineHeight: 1.6 }}>
                        {ok
                            ? 'The device accepted the remediation. This is a manual control, so it was not automatically re-verified — re-run the audit to confirm compliance. The results list now marks this check as applied.'
                            : 'The device returned one or more errors. Review the output below.'}
                    </p>
                    {result.target_vdom && (
                        <p style={{ margin: '8px 0 0 0', fontSize: '13px', color: '#4c1d95' }}>
                            🎯 Modified VDOM: <strong>{vdomBadgeLabel(result.target_vdom)}</strong>
                        </p>
                    )}
                </div>

                {perTarget.length > 0 && (
                    <div>
                        <h4 style={{ fontSize: '14px', color: '#1e3a5f', margin: '0 0 8px 0', fontWeight: 700 }}>Per-entry result</h4>
                        <div style={{ border: '1px solid #e5e7eb', borderRadius: '8px', overflow: 'hidden' }}>
                            {perTarget.map((t, i) => (
                                <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '10px 14px', borderTop: i > 0 ? '1px solid #e5e7eb' : 'none', background: t.success ? '#f0fdf4' : '#fef2f2' }}>
                                    <span style={{ fontWeight: 700, color: t.success ? '#166534' : '#b91c1c' }}>{t.success ? '✓' : '✗'}</span>
                                    <div style={{ fontSize: '13px' }}>
                                        <span style={{ fontWeight: 600, color: '#1e3a5f' }}>{t.target}</span>
                                        {!t.success && (t.errors ?? []).length > 0 && (
                                            <div style={{ color: '#b91c1c', marginTop: '2px' }}>{t.errors.join('; ')}</div>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

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
        if (step === 2) return 'Enter SSH credentials. They are also used to read existing profile/object names from the device for the next step.';
        if (step === 3) return 'Pick the values for this remediation — options come from the audit evidence and the live device.';
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
                            {step === 2 && renderCredentials()}
                            {step === 3 && renderParams()}
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
                            <button className="hardening-btn-primary" onClick={handleNextFromCredentials} disabled={executing}>
                                {parameters.length > 0 ? 'Next' : '⚡ Execute Fix'}
                            </button>
                        </>
                    )}
                    {step === 3 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={() => setStep(2)}>Back</button>
                            <button className="hardening-btn-primary" onClick={handleExecute} disabled={executing}>⚡ Execute Fix</button>
                        </>
                    )}
                    {step === 5 && (
                        // onSuccess already fired when execution succeeded (list is
                        // updated live); Finish only closes the modal.
                        <button className="hardening-btn-primary" onClick={onClose}>Finish</button>
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

const sourceTag = {
    display: 'inline-block',
    marginLeft: '8px',
    padding: '2px 8px',
    borderRadius: '999px',
    fontSize: '11px',
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

const multiBoxStyle = {
    width: '450px',
    maxWidth: '100%',
    maxHeight: '180px',
    overflowY: 'auto',
    padding: '8px 12px',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    background: 'white',
};

export default ViewFixModal;
