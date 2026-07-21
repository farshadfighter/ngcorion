import React, { useEffect, useMemo, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
    fetchHardenAllPlan,
    executeHardenAll,
    clearHardenAll,
} from '../../store/hardeningSlice';
import '../../assets/hardening/HardenAll.css';

/**
 * Harden All — remediate every failed check in an audit session.
 *
 * The whole wizard is driven by the backend plan
 * (GET /api/hardening/harden-all/session/{id}/plan): which checks are fixable,
 * which are not and why, the parameters to collect, the credential fields to
 * render, and whether this device family supports a config backup or a dry run.
 * There is deliberately no device-type branching in this file — adding a device
 * family is a backend-only change.
 *
 * Props: sessionId (required), onClose, onSuccess.
 */

const STEPS = ['Review', 'Parameters', 'Credentials', 'Results'];

const HardenAllModal = ({ sessionId, onClose, onSuccess }) => {
    const dispatch = useDispatch();
    const { hardenAllPlan: plan, hardenAllResult: result, isLoadingPlan, isHardeningAll, hardenAllError } =
        useSelector((state) => state.hardening);

    const [step, setStep] = useState(0);
    const [fieldErrors, setFieldErrors] = useState({});
    const [createBackup, setCreateBackup] = useState(false);
    const [dryRun, setDryRun] = useState(false);

    // Only the operator's own edits live in state; everything else is derived from
    // the plan. Nothing has to be seeded when the plan arrives, so there is no
    // copy of the plan that can drift out of sync with it.
    const [deselectedIds, setDeselectedIds] = useState([]);
    const [paramEdits, setParamEdits] = useState({});
    const [credEdits, setCredEdits] = useState({});

    useEffect(() => {
        if (sessionId) dispatch(fetchHardenAllPlan({ sessionId }));
        return () => { dispatch(clearHardenAll()); };
    }, [dispatch, sessionId]);

    // ─── Derived ──────────────────────────────────────────────────────────────

    // Every fixable check starts selected; state tracks what the operator turned off.
    const selectedSet = useMemo(() => {
        const off = new Set(deselectedIds);
        return new Set((plan?.fixable || []).map((c) => c.result_id).filter((id) => !off.has(id)));
    }, [plan, deselectedIds]);

    const selectedIds = useMemo(() => Array.from(selectedSet), [selectedSet]);

    // A field's value is the operator's edit if they made one, otherwise its default.
    const valueOf = (field, edits) => {
        const edited = edits[field.name];
        return edited !== undefined ? edited : (field.default ?? '');
    };

    const selectedChecks = useMemo(
        () => (plan?.fixable || []).filter((c) => selectedSet.has(c.result_id)),
        [plan, selectedSet]
    );

    // Only ask for parameters that the currently selected checks actually consume —
    // deselecting the one check that needs a syslog server should drop that field.
    const activeParams = useMemo(() => {
        if (!plan) return [];
        const numbers = new Set(selectedChecks.map((c) => c.check_number));
        return plan.parameters.filter((p) => p.checks.some((cn) => numbers.has(cn)));
    }, [plan, selectedChecks]);

    const toggleCheck = (resultId) => {
        setDeselectedIds((prev) =>
            prev.includes(resultId) ? prev.filter((id) => id !== resultId) : [...prev, resultId]
        );
    };

    const setAllSelected = (all) =>
        setDeselectedIds(all ? [] : (plan?.fixable || []).map((c) => c.result_id));

    // ─── Validation ───────────────────────────────────────────────────────────

    const validate = (fields, edits) => {
        const errors = {};
        fields.forEach((f) => {
            if (f.required && !String(valueOf(f, edits)).trim()) {
                errors[f.name] = `${f.label || f.name} is required`;
            }
        });
        return errors;
    };

    const goToParams = () => {
        if (selectedIds.length === 0) return;
        setFieldErrors({});
        setStep(activeParams.length > 0 ? 1 : 2);
    };

    const goToCredentials = () => {
        const errors = validate(
            activeParams.map((p) => ({ ...p, label: p.label || p.name })),
            paramEdits
        );
        setFieldErrors(errors);
        if (Object.keys(errors).length === 0) setStep(2);
    };

    const handleExecute = async () => {
        const errors = validate(plan.credential_fields, credEdits);
        setFieldErrors(errors);
        if (Object.keys(errors).length > 0) return;

        // Send only the parameters the selected checks use, and drop blanks so the
        // backend template default wins instead of an empty string.
        const parameters = {};
        activeParams.forEach((p) => {
            const value = String(valueOf(p, paramEdits)).trim();
            if (value) parameters[p.name] = value;
        });
        const credentials = {};
        plan.credential_fields.forEach((f) => {
            const value = String(valueOf(f, credEdits)).trim();
            if (value) credentials[f.name] = value;
        });

        setStep(3);
        try {
            await dispatch(executeHardenAll({
                sessionId,
                credentials,
                parameters,
                resultIds: selectedIds,
                createBackup: createBackup && plan.capabilities.backup,
                dryRun: dryRun && plan.capabilities.dry_run,
            })).unwrap();
        } catch {
            // The error banner renders from hardenAllError; go back to credentials
            // so the operator can correct them and retry.
            setStep(2);
        }
    };

    const handleFinish = () => {
        // A dry run changed nothing, so it must not trigger the caller's refresh.
        if (onSuccess && !result?.dry_run) onSuccess();
        onClose();
    };

    // ─── Renders ──────────────────────────────────────────────────────────────

    const renderStepRail = () => (
        <div className="ha-steps">
            {STEPS.map((label, index) => (
                <React.Fragment key={label}>
                    {index > 0 && <span className="ha-step-sep" />}
                    <span className={`ha-step ${index === step ? 'is-active' : index < step ? 'is-done' : ''}`}>
                        <span className="ha-step-dot">{index < step ? '✓' : index + 1}</span>
                        {label}
                    </span>
                </React.Fragment>
            ))}
        </div>
    );

    const renderReview = () => {
        if (isLoadingPlan) {
            return (
                <div className="ha-empty">
                    <div className="ha-spinner-sm" />
                    Loading the hardening plan…
                </div>
            );
        }
        if (!plan) {
            return <div className="ha-empty">{hardenAllError || 'No plan available for this session.'}</div>;
        }
        if (plan.fixable.length === 0) {
            return (
                <div>
                    <div className="ha-empty">
                        {plan.total_failed === 0
                            ? 'This session has no failed checks.'
                            : 'None of the failed checks in this session can be remediated automatically.'}
                    </div>
                    {renderSkipped()}
                </div>
            );
        }
        return (
            <div>
                <h3 className="ha-section-title">
                    <span>Checks to harden</span>
                    <span className="ha-hint">
                        {selectedIds.length} of {plan.fixable.length} selected
                        <button type="button" className="ha-link-btn" onClick={() => setAllSelected(true)}>All</button>
                        <button type="button" className="ha-link-btn" onClick={() => setAllSelected(false)}>None</button>
                    </span>
                </h3>
                <div className="ha-list">
                    {plan.fixable.map((check) => {
                        const selected = selectedSet.has(check.result_id);
                        return (
                            <label key={check.result_id} className={`ha-check ${selected ? '' : 'is-unselected'}`}>
                                <input type="checkbox" checked={selected} onChange={() => toggleCheck(check.result_id)} />
                                <span className="ha-check-body">
                                    <span className="ha-check-id">{check.check_number}</span>
                                    <span className="ha-check-title">{check.check_title || '—'}</span>
                                </span>
                                {check.vdom && <span className="ha-badge ha-badge-vdom">VDOM: {check.vdom}</span>}
                                {check.needs_params && <span className="ha-badge ha-badge-params">Needs parameters</span>}
                            </label>
                        );
                    })}
                </div>
                {renderSkipped()}
            </div>
        );
    };

    const renderSkipped = () => {
        if (!plan?.skipped?.length) return null;
        return (
            <div className="ha-skipped">
                <h4>
                    {plan.skipped.length} failed check{plan.skipped.length === 1 ? '' : 's'} cannot be
                    remediated automatically and will be left unchanged:
                </h4>
                <ul>
                    {plan.skipped.map((s) => (
                        <li key={s.result_id}>
                            {s.check_number}
                            {s.vdom ? ` (${s.vdom})` : ''} — {s.check_title || s.reason}
                        </li>
                    ))}
                </ul>
            </div>
        );
    };

    const renderField = (field, edits, setEdits) => {
        const value = valueOf(field, edits);
        const error = fieldErrors[field.name];
        const onChange = (e) => {
            const next = e.target.value;
            setEdits((prev) => ({ ...prev, [field.name]: next }));
            setFieldErrors((prev) => (prev[field.name] ? { ...prev, [field.name]: undefined } : prev));
        };
        return (
            <div className="ha-field" key={field.name}>
                <label htmlFor={`ha-${field.name}`}>
                    {field.label || field.name}
                    {field.required && <span className="ha-req">*</span>}
                </label>
                {field.options?.length ? (
                    <select id={`ha-${field.name}`} value={value} onChange={onChange}>
                        <option value="">{field.default ? `Default: ${field.default}` : 'Select…'}</option>
                        {field.options.map((opt) => <option key={opt} value={opt}>{opt}</option>)}
                    </select>
                ) : (
                    <input
                        id={`ha-${field.name}`}
                        type={field.type === 'password' ? 'password' : field.type === 'number' ? 'number' : 'text'}
                        className={error ? 'has-error' : ''}
                        value={value}
                        onChange={onChange}
                        placeholder={field.placeholder || field.default || ''}
                        autoComplete={field.type === 'password' ? 'new-password' : 'off'}
                    />
                )}
                {(field.help || field.description) && (
                    <span className="ha-field-help">{field.help || field.description}</span>
                )}
                {field.checks?.length > 0 && (
                    <span className="ha-field-checks">Used by: {field.checks.join(', ')}</span>
                )}
                {error && <span className="ha-field-error">{error}</span>}
            </div>
        );
    };

    const renderParameters = () => (
        <div className="ha-form">
            <h3 className="ha-section-title">
                <span>Remediation parameters</span>
                <span className="ha-hint">Blank optional fields fall back to the CIS default</span>
            </h3>
            {activeParams.map((param) => renderField(param, paramEdits, setParamEdits))}
        </div>
    );

    const renderCredentials = () => (
        <div className="ha-form">
            <h3 className="ha-section-title">
                <span>Connect to {plan.asset_name || plan.target_ip || 'the device'}</span>
                <span className="ha-hint">Used for this run only — never stored</span>
            </h3>
            {plan.credential_fields.map((field) => renderField(field, credEdits, setCredEdits))}

            {plan.capabilities.backup && (
                <label className="ha-toggle">
                    <input type="checkbox" checked={createBackup} onChange={(e) => setCreateBackup(e.target.checked)} />
                    <span><strong>Back up the device configuration first</strong> — saved to Backups before any change is applied.</span>
                </label>
            )}
            {plan.capabilities.dry_run && (
                <label className="ha-toggle is-dry">
                    <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
                    <span><strong>Preview only (dry run)</strong> — show the exact commands without connecting or changing anything.</span>
                </label>
            )}
        </div>
    );

    const renderExecuting = () => (
        <div className="ha-executing">
            <div className="ha-spinner" />
            <h3>{dryRun && plan?.capabilities.dry_run ? 'Building the command preview…' : 'Applying hardening…'}</h3>
            <p>{selectedIds.length} check{selectedIds.length === 1 ? '' : 's'} on {plan?.target_ip || 'the device'}. This can take a few minutes.</p>
        </div>
    );

    const renderResults = () => {
        if (isHardeningAll || !result) return renderExecuting();

        const rows = result.results || [];
        return (
            <div>
                {result.dry_run && (
                    <div className="ha-notice">
                        🔍 Dry run — nothing was executed and nothing changed on the device.
                    </div>
                )}
                {!result.dry_run && (
                    <div className="ha-summary">
                        <div className="ha-stat is-success"><strong>{result.successful}</strong><span>Fixed</span></div>
                        <div className="ha-stat is-failed"><strong>{result.failed}</strong><span>Failed</span></div>
                        <div className="ha-stat is-skipped"><strong>{result.skipped}</strong><span>Skipped</span></div>
                    </div>
                )}
                <div className="ha-list" style={{ maxHeight: '380px' }}>
                    {rows.map((row, index) => (
                        <div key={`${row.result_id ?? row.check_number}-${index}`} className={`ha-result is-${row.status}`}>
                            <span className="ha-check-body">
                                <span className="ha-check-id">
                                    {row.check_number}
                                    {row.vdom ? ` (${row.vdom})` : ''}
                                </span>
                                {row.check_title && <span className="ha-check-title">{row.check_title}</span>}
                                {row.detail && <span className="ha-result-detail">{row.detail}</span>}
                                {row.commands?.length > 0 && (
                                    <span className="ha-commands">
                                        {row.commands.map((cmd, i) => <code key={i}>{cmd}</code>)}
                                    </span>
                                )}
                            </span>
                            <span className={`ha-badge ha-badge-${row.status === 'success' ? 'ok' : row.status === 'failed' ? 'fail' : 'skip'}`}>
                                {result.dry_run && row.status === 'success'
                                    ? 'Preview'
                                    : row.status === 'success' ? 'Fixed' : row.status === 'failed' ? 'Failed' : 'Skipped'}
                            </span>
                        </div>
                    ))}
                    {rows.length === 0 && <div className="ha-empty">The device returned no per-check results.</div>}
                </div>
            </div>
        );
    };

    // ─── Footer ───────────────────────────────────────────────────────────────

    const renderFooter = () => {
        if (step === 3) {
            if (isHardeningAll || !result) return null;
            return <button className="ha-btn ha-btn-primary" onClick={handleFinish}>Finish</button>;
        }

        const canProceed = !!plan && plan.fixable.length > 0;
        return (
            <>
                {step > 0 && selectedIds.length > 0 && (
                    <span className="ha-footer-info">
                        {selectedIds.length} check{selectedIds.length === 1 ? '' : 's'} selected
                    </span>
                )}
                <button
                    className="ha-btn ha-btn-secondary"
                    onClick={step === 0 ? onClose : () => setStep(step === 2 && activeParams.length === 0 ? 0 : step - 1)}
                >
                    {step === 0 ? 'Cancel' : 'Back'}
                </button>
                {step === 0 && (
                    <button className="ha-btn ha-btn-primary" onClick={goToParams} disabled={!canProceed || selectedIds.length === 0}>
                        Next
                    </button>
                )}
                {step === 1 && (
                    <button className="ha-btn ha-btn-primary" onClick={goToCredentials}>Next</button>
                )}
                {step === 2 && (
                    <button className="ha-btn ha-btn-primary" onClick={handleExecute} disabled={isHardeningAll}>
                        {dryRun && plan?.capabilities.dry_run ? 'Preview Commands' : 'Apply Hardening'}
                    </button>
                )}
            </>
        );
    };

    return (
        <div className="ha-overlay" onClick={onClose}>
            <div className="ha-modal" onClick={(e) => e.stopPropagation()}>
                <div className="ha-header">
                    <div>
                        <h2>Harden All Failed Checks</h2>
                        <p className="ha-subtitle">
                            {plan
                                ? `${plan.device_label}${plan.sub_device_type ? ` · ${plan.sub_device_type}` : ''} · ${plan.asset_name || plan.target_ip || `session ${sessionId}`}`
                                : `Session ${sessionId}`}
                        </p>
                    </div>
                    <button className="ha-close" onClick={onClose} aria-label="Close">×</button>
                </div>

                {renderStepRail()}

                <div className="ha-body">
                    {step === 0 && renderReview()}
                    {step === 1 && renderParameters()}
                    {step === 2 && renderCredentials()}
                    {step === 3 && renderResults()}
                </div>

                {hardenAllError && step !== 3 && (
                    <div className="ha-error">⚠ {hardenAllError}</div>
                )}

                <div className="ha-footer">{renderFooter()}</div>
            </div>
        </div>
    );
};

export default HardenAllModal;
