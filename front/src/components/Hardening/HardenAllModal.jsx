import React, { useState, useEffect, useMemo } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    fetchRequiredParameters,
    autoHardenWithDefaults,
    batchExecuteChecks,
    discoverFortinetVdoms,
    clearRequiredParameters,
    clearMessages
} from '../../store/hardeningSlice';
import CredentialsForm from './CredentialsForm';
import BackupOption from './BackupOption';
import {
    isWindows,
    isMssql,
    isCisco,
    isFortinet,
    isLinux,
    defaultCredentialsState,
    validateCredentials,
    buildCredentials,
} from './hardeningCredentials';
import '../../assets/hardening/Hardenallmodal.css';

const HardenAllModal = ({ sessionId, assetId, deviceType, checks, onClose, onSuccess }) => {
    const dispatch = useDispatch();
    const {
        requiredParameters,
        isFetchingParams,
        isExecuting,
        error,
        vdomDiscovery
    } = useSelector((state) => state.hardening);

    const [vdomEnabled, setVdomEnabled] = useState(false);
    const [createBackup, setCreateBackup] = useState(false);
    const [dryRun, setDryRun] = useState(false); // Linux only: preview commands without executing

    const [step, setStep] = useState(1); // 1: Checks preview, 2: Parameters, 3: Credentials, 4: Executing, 5: Results
    const [paramValues, setParamValues] = useState({});
    const [sshCredentials, setSshCredentials] = useState(defaultCredentialsState);
    const [credErrors, setCredErrors] = useState({});
    const [executionResult, setExecutionResult] = useState(null);

    // Titles for Cisco/Fortinet checks (their categorized-check lists only carry
    // check_number + result_id) — looked up from the already-fetched results list.
    const checksByNumber = useMemo(() => {
        const map = {};
        (checks || []).forEach((c) => { map[c.check_number] = c; });
        return map;
    }, [checks]);

    useEffect(() => {
        if (sessionId && deviceType) {
            dispatch(fetchRequiredParameters({ sessionId, deviceType }));
        }
        return () => {
            dispatch(clearRequiredParameters());
            dispatch(clearMessages());
        };
    }, [dispatch, sessionId, deviceType]);

    // Two backend shapes: Cisco/Fortinet expose `required_parameters`,
    // Linux/Apache/MongoDB/MSSQL/Windows expose aggregated `parameters`
    // ({name: {label, description, default, required, options, checks[]}}).
    const paramEntries = requiredParameters?.required_parameters
        || requiredParameters?.parameters
        || null;

    useEffect(() => {
        if (paramEntries) {
            const initialValues = {};
            Object.entries(paramEntries).forEach(([key, param]) => {
                initialValues[key] = param.default || '';
            });
            // eslint-disable-next-line react-hooks/set-state-in-effect
            setParamValues(prev => {
                const hasChanged = JSON.stringify(prev) !== JSON.stringify(initialValues);
                return hasChanged ? initialValues : prev;
            });
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [requiredParameters]);

    const handleParamChange = (key, value) => setParamValues(prev => ({ ...prev, [key]: value }));

    const handleSSHChange = (e) => {
        const { name, value } = e.target;
        setSshCredentials(prev => ({ ...prev, [name]: value }));
        setCredErrors(prev => (prev[name] ? { ...prev, [name]: undefined } : prev));
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
        if (!paramEntries) return true;
        const errors = [];
        Object.entries(paramEntries).forEach(([key, param]) => {
            // Backend marks user-input params with `required: true` (no `optional`
            // field). Reading `param.optional` was always undefined, so every
            // param was treated as required; key off `required` instead.
            if (param.required && !paramValues[key]?.trim()) errors.push(param.description || key);
        });
        if (errors.length > 0) {
            alert(`Please fill in required fields:\n${errors.join('\n')}`);
            return false;
        }
        return true;
    };

    const validateForm = () => {
        const errs = validateCredentials(deviceType, sshCredentials);
        setCredErrors(errs);
        return Object.keys(errs).length === 0;
    };

    const hasRequiredParams = () =>
        !!paramEntries && Object.keys(paramEntries).length > 0;

    // Step 1 (checks preview) -> step 2 (parameters, skipped when none needed).
    const handleNextFromChecks = () => setStep(hasRequiredParams() ? 2 : 3);

    // Step 2 (parameters) -> step 3 (credentials).
    const handleNextFromParams = () => {
        if (validateParameters()) setStep(3);
    };

    // Normalizes the two backend response shapes into one preview list:
    //   Cisco/Fortinet: { auto_fixable_checks, needs_params_checks, no_template_checks }
    //     — each entry only carries check_number + result_id, so titles are looked
    //     up from the `checks` prop (the results list already loaded by the parent).
    //   Linux/Apache/MongoDB/MSSQL/Windows: { failed_checks: [{check_number, check_title, has_template, ...}] }
    const buildChecksPreview = () => {
        const rp = requiredParameters;
        if (!rp) return { fixable: [], skipped: [] };

        if (rp.auto_fixable_checks || rp.needs_params_checks || rp.no_template_checks) {
            const titleFor = (cn) => checksByNumber[cn]?.check_title || cn;
            return {
                fixable: [
                    ...(rp.auto_fixable_checks || []).map((c) => ({ id: c.check_number, title: titleFor(c.check_number), needsParams: false })),
                    ...(rp.needs_params_checks || []).map((c) => ({ id: c.check_number, title: titleFor(c.check_number), needsParams: true })),
                ],
                skipped: (rp.no_template_checks || []).map((c) => ({ id: c.check_number, title: titleFor(c.check_number), reason: c.reason || 'No remediation template' })),
            };
        }

        if (Array.isArray(rp.failed_checks)) {
            const needsParamsSet = new Set(rp.categorized_checks?.needs_params || []);
            return {
                fixable: rp.failed_checks.filter((c) => c.has_template).map((c) => ({ id: c.check_number, title: c.check_title, needsParams: needsParamsSet.has(c.check_number) })),
                skipped: rp.failed_checks.filter((c) => !c.has_template).map((c) => ({ id: c.check_number, title: c.check_title, reason: 'No remediation template' })),
            };
        }

        return { fixable: [], skipped: [] };
    };

    // Cisco/Fortinet harden via batch-execute (below); other families use the
    // defaults-only auto-harden endpoint.
    const ciscoOrFortinet = isCisco(deviceType) || isFortinet(deviceType);

    // AuditResult IDs of every fixable failed check (auto-fixable + needs-params).
    // no_template checks are excluded — batch-execute can't remediate them.
    const collectFixableCheckIds = () => {
        if (!requiredParameters) return [];
        return [
            ...(requiredParameters.auto_fixable_checks || []),
            ...(requiredParameters.needs_params_checks || []),
        ]
            .map((c) => c.result_id)
            .filter((id) => id != null);
    };

    const handleExecute = async () => {
        if (!validateForm()) return;

        const credentials = buildCredentials(deviceType, sshCredentials, { vdomEnabled });

        // Cisco/Fortinet: harden ALL fixable checks via batch-execute so the
        // parameters entered above are actually applied. auto_harden_with_defaults
        // ignores user params and skips every param-requiring check (e.g. "enable
        // secret"), so it could never fix them. batch_execute_selected merges the
        // submitted parameters with each check's template defaults, so both
        // auto-fixable and param-requiring checks get remediated in one pass.
        if (ciscoOrFortinet) {
            const checkIds = collectFixableCheckIds();
            if (checkIds.length === 0) {
                alert('No fixable checks were found for this session.');
                return;
            }
            setStep(4);
            try {
                const result = await dispatch(batchExecuteChecks({
                    sessionId,
                    assetId,
                    deviceType,
                    credentials,
                    checkIds,
                    parameters: paramValues,
                    skipBackup: !createBackup,
                })).unwrap();
                setExecutionResult(result);
                setStep(5);
            } catch (error) {
                console.error('Error executing hardening fixes:', error);
                setStep(3);
            }
            return;
        }

        // Linux / Apache / MongoDB / MSSQL / Windows.
        setStep(4);
        try {
            let result;
            const aggregated = requiredParameters?.parameters;
            const fixable = (requiredParameters?.failed_checks || []).filter((c) => c.has_template);

            if (aggregated && Object.keys(aggregated).length > 0 && fixable.length > 0) {
                // Param-aware path: batch-execute every templated failed check,
                // attaching each entered parameter to the checks that use it
                // (param metadata carries a `checks` list). Auto-fixable checks
                // ride along with {} — the backend merges template defaults.
                const checksPayload = fixable.map((c) => {
                    const perCheck = {};
                    Object.entries(aggregated).forEach(([name, meta]) => {
                        const value = paramValues[name];
                        if (value?.trim() && (meta.checks || []).includes(c.check_number)) {
                            perCheck[name] = value.trim();
                        }
                    });
                    return { check_id: c.check_number, parameters: perCheck };
                });
                result = await dispatch(batchExecuteChecks({
                    sessionId,
                    assetId,
                    deviceType,
                    credentials,
                    checks: checksPayload,
                    dryRun,
                })).unwrap();
            } else {
                // No user parameters involved: defaults-only auto-harden.
                result = await dispatch(autoHardenWithDefaults({
                    sessionId,
                    assetId,
                    deviceType,
                    credentials,
                    skipBackup: !createBackup,
                    dryRun,
                })).unwrap();
            }

            setExecutionResult(result);
            setStep(5);
        } catch (error) {
            console.error('Error executing hardening fixes:', error);
            setStep(3);
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

    // ─── Renders ──────────────────────────────────────────────────────────────

    // Mirrors FixSingleModal's "Commands to Execute" preview — a numbered card
    // per check — so Fix All shows the same at-a-glance view before executing.
    const renderChecksPreview = () => {
        if (isFetchingParams) {
            return (
                <div className="hardening-modal-loading">
                    <div className="hardening-spinner"></div>
                    <p>Loading checks...</p>
                </div>
            );
        }
        const { fixable, skipped } = buildChecksPreview();
        if (fixable.length === 0 && skipped.length === 0) {
            return (
                <div className="hardening-no-params">
                    <p>No fixable checks were found for this session.</p>
                </div>
            );
        }
        return (
            <div className="hardening-preview-section">
                <h3 style={{ fontSize: '18px', color: '#1e3a5f', margin: '0 0 20px 0', fontWeight: '700', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    📋 Checks to be Hardened ({fixable.length})
                </h3>
                {fixable.length > 0 && (
                    <div style={{ background: 'linear-gradient(135deg, #f8f9fb 0%, #ffffff 100%)', borderRadius: '10px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '10px', border: '1px solid #e8edf5', maxHeight: '340px', overflowY: 'auto' }}>
                        {fixable.map((c, index) => (
                            <div key={`${c.id}-${index}`} style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', padding: '14px', background: 'white', borderRadius: '8px', borderLeft: '4px solid #1e3a5f', boxShadow: '0 2px 6px rgba(30,58,95,0.06)' }}>
                                <div style={{ background: 'linear-gradient(135deg, #1e3a5f 0%, #2d4a7c 100%)', color: 'white', minWidth: '26px', height: '26px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '12px', fontWeight: '700', flexShrink: '0' }}>{index + 1}</div>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ fontSize: '13px', fontWeight: '700', color: '#1f2937' }}>{c.id}</div>
                                    <div style={{ fontSize: '13px', color: '#4b5563', marginTop: '2px' }}>{c.title}</div>
                                </div>
                                {c.needsParams && (
                                    <span style={{ flexShrink: 0, display: 'inline-block', padding: '3px 10px', borderRadius: '999px', fontSize: '11px', fontWeight: 600, background: '#fef3c7', color: '#92400e', border: '1px solid #fcd34d' }}>
                                        Needs parameters
                                    </span>
                                )}
                            </div>
                        ))}
                    </div>
                )}
                {skipped.length > 0 && (
                    <div className="hardening-warnings-box" style={{ marginTop: '16px' }}>
                        <h4>⚠️ {skipped.length} check{skipped.length === 1 ? '' : 's'} will be skipped — no automated remediation:</h4>
                        <ul>{skipped.map((s) => <li key={s.id}>{s.id} — {s.title}</li>)}</ul>
                    </div>
                )}
            </div>
        );
    };

    const renderParametersForm = () => {
        if (isFetchingParams) {
            return (
                <div className="hardening-modal-loading">
                    <div className="hardening-spinner"></div>
                    <p>Loading parameters...</p>
                </div>
            );
        }
        if (!paramEntries || Object.keys(paramEntries).length === 0) {
            return (
                <div className="hardening-no-params">
                    <p>No additional parameters required.</p>
                    <p className="hardening-sub-text">Click Next to proceed with credentials.</p>
                </div>
            );
        }
        return (
            <div className="hardening-params-form">
                {Object.entries(paramEntries).map(([key, param]) => (
                    <div key={key} className="hardening-form-group">
                        <label>
                            {param.label || param.description || key}
                            {param.required && <span className="hardening-required">*</span>}
                        </label>
                        <div className="hardening-input-with-meta">
                            {Array.isArray(param.options) && param.options.length > 0 ? (
                                <select value={paramValues[key] || ''} onChange={(e) => handleParamChange(key, e.target.value)} style={inputStyle}>
                                    <option value="">{param.default ? `default: ${param.default}` : `Select ${key}`}</option>
                                    {param.options.map((opt) => <option key={opt} value={opt}>{opt}</option>)}
                                </select>
                            ) : (
                                <input type="text" value={paramValues[key] || ''} onChange={(e) => handleParamChange(key, e.target.value)} placeholder={param.placeholder || param.default || `Enter ${key}`} style={inputStyle} />
                            )}
                            {param.usage && <span className="hardening-param-usage">{param.usage}</span>}
                        </div>
                        {param.label && param.description && (
                            <span style={{ fontSize: '12px', color: '#6b7280' }}>{param.description}</span>
                        )}
                        {Array.isArray(param.checks) && param.checks.length > 0 && (
                            <span style={{ fontSize: '11px', color: '#9ca3af' }}>Used by: {param.checks.join(', ')}</span>
                        )}
                    </div>
                ))}
            </div>
        );
    };

    const renderCredentialsForm = () => (
        <CredentialsForm
            deviceType={deviceType}
            value={sshCredentials}
            onChange={handleSSHChange}
            errors={credErrors}
            vdomEnabled={vdomEnabled}
            onVdomEnabledChange={setVdomEnabled}
            vdomDiscovery={vdomDiscovery}
            onDetectVdoms={handleDetectVdoms}
            canDetectVdoms={!!assetId && !!sshCredentials.ssh_username && !!sshCredentials.ssh_password}
        />
    );

    const renderBackupOption = () => (
        (isCisco(deviceType) || isFortinet(deviceType)) && (
            <BackupOption checked={createBackup} onChange={setCreateBackup} />
        )
    );

    // Linux only: the backend supports dry_run (command preview, no execution).
    const renderDryRunOption = () => (
        isLinux(deviceType) && (
            <label style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '14px', padding: '12px 16px', background: '#f5f3ff', border: '1px solid #c4b5fd', borderRadius: '10px', cursor: 'pointer', fontSize: '14px', color: '#4c1d95' }}>
                <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
                <span>
                    <strong>Preview only (dry run)</strong> — show the exact commands without connecting to the server or changing anything.
                </span>
            </label>
        )
    );

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

        // Dry run: nothing was executed — show the per-check command preview.
        if (executionResult.dry_run) {
            const rows = Array.isArray(executionResult.results) ? executionResult.results : [];
            return (
                <div>
                    <div style={{ padding: '16px 20px', borderRadius: '10px', borderLeft: '5px solid #7c3aed', background: 'linear-gradient(135deg,#ede9fe 0%,#f5f3ff 100%)', marginBottom: '18px' }}>
                        <p style={{ margin: 0, fontSize: '14px', color: '#4c1d95', fontWeight: 600 }}>
                            🔍 Dry run — no commands were executed and nothing was changed on the server.
                        </p>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', maxHeight: '420px', overflowY: 'auto', paddingRight: '4px' }}>
                        {rows.map((r) => (
                            <div key={r.check_id} style={{ padding: '14px 18px', borderRadius: '10px', border: '1px solid #e8edf5', background: 'white' }}>
                                <div style={{ fontSize: '13px', fontWeight: 700, color: '#1e3a5f' }}>
                                    {r.check_id}{r.check_title ? ` — ${r.check_title}` : ''}
                                </div>
                                {r.error_message ? (
                                    <div style={{ fontSize: '12px', color: '#c0392b', marginTop: '6px' }}>{r.error_message}</div>
                                ) : (
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '8px' }}>
                                        {(r.commands || []).map((cmd, i) => (
                                            <code key={i} style={{ fontFamily: "'Consolas','Monaco','Courier New',monospace", fontSize: '12px', color: '#1f2937', background: '#f8f9fb', padding: '6px 10px', borderRadius: '6px', wordBreak: 'break-word' }}>{cmd}</code>
                                        ))}
                                    </div>
                                )}
                            </div>
                        ))}
                        {rows.length === 0 && <p style={{ color: '#6b7280' }}>No auto-fixable checks to preview.</p>}
                    </div>
                </div>
            );
        }

        // Normalize across the device-family response shapes so the summary and
        // table render for every device type:
        //   Linux/Apache/MongoDB/MSSQL/Windows:
        //     { successful, failed, skipped[], results[{check_id, success, verification_result, error_message}] }
        //   Cisco/Fortinet auto-harden-defaults:
        //     { fixed_count, failed_count, skipped_count, fixed_checks[{check_number}], skipped_checks[{check_number, reason}] }
        //   Cisco/Fortinet batch-execute:
        //     { fixed_count, failed_count, skipped_count, results[{check_number, status, ...}] }
        // The old code only read the Linux shape, so Cisco/Fortinet always showed 0/0/0.
        const successCount = executionResult.successful ?? executionResult.fixed_count  ?? 0;
        const failedCount  = executionResult.failed     ?? executionResult.failed_count ?? 0;

        // Per-check rows. batch-execute (Cisco/Fortinet) returns skipped checks
        // inside results[] with status:"skipped", so route those to the skipped
        // list rather than mislabeling them as failed.
        let fixedRows = [];
        const skippedFromResults = [];
        if (Array.isArray(executionResult.results) && executionResult.results.length > 0) {
            executionResult.results.forEach((r) => {
                const id = r.check_id || r.check_number;
                const status = (r.status || '').toString().toLowerCase();
                if (status === 'skipped') {
                    skippedFromResults.push({ id, reason: r.reason || 'Skipped' });
                    return;
                }
                fixedRows.push({
                    id,
                    title:   r.check_title || id,
                    success: r.success ?? (status === 'success'),
                    detail:  r.error_message || r.verification_result || r.verification_evidence || r.reason || '—',
                });
            });
        } else if (Array.isArray(executionResult.fixed_checks)) {
            fixedRows = executionResult.fixed_checks.map((c) => ({
                id:      c.check_number,
                title:   c.check_title || c.check_number,
                success: true,
                detail:  '—',
            }));
        }

        const skippedRows = [
            ...skippedFromResults,
            ...(Array.isArray(executionResult.skipped_checks)
                ? executionResult.skipped_checks.map((c) => ({ id: c.check_number || c, reason: c.reason || 'Requires user input' }))
                : Array.isArray(executionResult.skipped)
                    ? executionResult.skipped.map((id) => ({ id, reason: 'Not auto-fixable' }))
                    : []),
        ];
        const skippedCount = executionResult.skipped_count ?? skippedRows.length;

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

                {/* Per-check results — same colored-card language as the single-fix
                    result screen, one card per check instead of one big card. */}
                {(fixedRows.length > 0 || skippedRows.length > 0) && (
                    <div style={{ marginTop: '24px', display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '380px', overflowY: 'auto', paddingRight: '4px' }}>
                        {fixedRows.map((r) => (
                            <div key={r.id} style={{
                                display: 'flex', alignItems: 'flex-start', gap: '14px',
                                padding: '14px 18px', borderRadius: '10px',
                                borderLeft: r.success ? '5px solid #1e3a5f' : '5px solid #ef4444',
                                background: r.success ? 'linear-gradient(135deg,#e8edf5 0%,#f0f4f9 100%)' : 'linear-gradient(135deg,#fee2e2 0%,#fef2f2 100%)',
                            }}>
                                <span style={{
                                    background: r.success ? '#1e3a5f' : '#ef4444', color: 'white',
                                    minWidth: '26px', height: '26px', borderRadius: '50%',
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    fontSize: '13px', fontWeight: '700', flexShrink: 0, marginTop: '2px',
                                }}>{r.success ? '✓' : '✗'}</span>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ fontSize: '13px', fontWeight: 700, color: r.success ? '#1e3a5f' : '#c0392b' }}>
                                        {r.id} <span style={{ fontWeight: 400, color: '#374151' }}>— {r.title}</span>
                                    </div>
                                    {r.detail && r.detail !== '—' && (
                                        <div style={{ fontSize: '12px', color: '#6b7280', marginTop: '4px', wordBreak: 'break-word' }}>{r.detail}</div>
                                    )}
                                </div>
                                <span className={`result-badge ${r.success ? 'result-success' : 'result-fail'}`} style={{ flexShrink: 0 }}>
                                    {r.success ? 'Fixed' : 'Failed'}
                                </span>
                            </div>
                        ))}
                        {skippedRows.map((s) => (
                            <div key={s.id} style={{
                                display: 'flex', alignItems: 'flex-start', gap: '14px',
                                padding: '14px 18px', borderRadius: '10px',
                                borderLeft: '5px solid #d1d5db', background: '#f9fafb',
                            }}>
                                <span style={{
                                    background: '#9ca3af', color: 'white', minWidth: '26px', height: '26px',
                                    borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    fontSize: '13px', fontWeight: 700, flexShrink: 0, marginTop: '2px',
                                }}>⊘</span>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ fontSize: '13px', fontWeight: 700, color: '#6b7280' }}>{s.id}</div>
                                    <div style={{ fontSize: '12px', color: '#9ca3af', marginTop: '4px' }}>{s.reason}</div>
                                </div>
                                <span className="result-badge result-unknown" style={{ flexShrink: 0 }}>Skipped</span>
                            </div>
                        ))}
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

                {step <= 3 && (
                    <div className="hardening-modal-info">
                        <span className="hardening-info-icon">ℹ️</span>
                        <p>
                            {step === 1 && 'Review the checks that will be hardened.'}
                            {step === 2 && 'Configure required parameters for hardening all failed checks.'}
                            {step === 3 && credentialStepLabel}
                        </p>
                    </div>
                )}

                <div className="hardening-modal-body">
                    {step === 1 && renderChecksPreview()}
                    {step === 2 && renderParametersForm()}
                    {step === 3 && <>{renderCredentialsForm()}{renderBackupOption()}{renderDryRunOption()}</>}
                    {step === 4 && renderExecuting()}
                    {step === 5 && renderResults()}
                </div>

                <div className="hardening-modal-footer">
                    {step === 1 && (
                        <>
                            <button className="hardening-btn-secondary" onClick={onClose}>Cancel</button>
                            <button className="hardening-btn-primary" onClick={handleNextFromChecks} disabled={isFetchingParams}>Next</button>
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
                            <button className="hardening-btn-secondary" onClick={() => setStep(hasRequiredParams() ? 2 : 1)}>Back</button>
                            <button className="hardening-btn-primary" onClick={handleExecute} disabled={isExecuting}>Execute Hardening</button>
                        </>
                    )}
                    {step === 5 && (
                        <button className="hardening-btn-primary" onClick={handleFinish}>Finish</button>
                    )}
                </div>

                {error && step !== 5 && (
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
