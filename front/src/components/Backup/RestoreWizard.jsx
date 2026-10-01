import React, { useEffect, useMemo, useState } from 'react';

import api from '../../config/api.js';
import {
    ACTIVE_RESTORE_STATUSES, AUTO_REVERT_TEXT, errorText, familyLabel,
    formatDateTime, formatTime, sourceLabel,
} from './restoreConstants.js';
import '../../assets/RestoreWizard.css';
import { n, t as tr } from "../../i18n";
import { tx } from "../../i18n/tx";

/**
 * Restore a configuration backup onto its live device.
 *
 *   1 Connect  - SSH credentials; the device is only read.
 *   2 Review   - the diff between the live configuration and the backup, with
 *                any change that could cut NGCorion off flagged.
 *   3 Confirm  - safety net, auto-revert timer, reason, typed asset name.
 *   4 Restore  - the server-side job, polled until it settles.
 *
 * Credentials live in this component's state only: they are sent with the
 * preview and start requests and are never stored, here or on the server.
 * Every guard shown here (typed name, lock-out acknowledgement, running
 * without auto-revert) is re-checked by the server; the UI only explains it.
 */

const STEPS = [tr("Connect"), tr("Review changes"), tr("Safety & confirm"), tr("Restore")];

const POLL_MS = 2000;
const POLL_RETRY_MS = 5000;

const Icon = ({ d, size = 16, stroke = 'currentColor', width = 2, children }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={stroke}
         strokeWidth={width} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        {d ? <path d={d} /> : children}
    </svg>
);

const RestoreIcon = ({ size = 16, stroke }) => (
    <Icon size={size} stroke={stroke}>
        <path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5" />
    </Icon>
);

const TimerIcon = ({ size = 20 }) => (
    <Icon size={size} stroke="#1e3a5f">
        <circle cx="12" cy="13" r="8" /><path d="M12 9v4l2 2M9 2h6" />
    </Icon>
);

const Check = ({ size = 20, stroke = '#166534' }) => (
    <Icon size={size} stroke={stroke} width={2.4} d="m5 12 5 5 9-10" />
);

const Stepper = ({ current }) => (
    <ol className="rw-stepper">
        {STEPS.map((label, i) => (
            <React.Fragment key={label}>
                {i > 0 && <li className="rw-bar" aria-hidden="true" />}
                <li className={`rw-st ${i < current ? 'done' : i === current ? 'on' : ''}`}
                    aria-current={i === current ? 'step' : undefined}>
                    <span className="rw-n">{i < current ? '✓' : i + 1}</span>{label}
                </li>
            </React.Fragment>
        ))}
    </ol>
);

const lineCount = (text) => (text ? text.split('\n').length : 0);

/* ------------------------------------------------------------------ */
/*  Step 2: the diff                                                   */
/* ------------------------------------------------------------------ */

const DiffView = ({ sections, mode }) => (
    <div className="rw-diff">
        {sections.map((s, si) => (
            <div key={si}>
                <div className="rw-diff-title">{s.title}</div>
                {mode === 'unified' ? (
                    s.lines.map((l, li) => (
                        <div key={li} className={`rw-dl ${l.op === '+' ? 'add' : l.op === '-' ? 'del' : 'ctx'}`}>
                            <span className="rw-sg">{l.op === ' ' ? '' : l.op === '-' ? '−' : '+'}</span>
                            <span className="rw-code">{l.text}</span>
                        </div>
                    ))
                ) : (
                    <div className="rw-split">
                        <div>
                            <div className="rw-split-head">{tr("Live now (removed)")}</div>
                            {s.lines.filter((l) => l.op !== '+').map((l, li) => (
                                <div key={li} className={`rw-dl ${l.op === '-' ? 'del' : 'ctx'}`}>
                                    <span className="rw-sg">{l.op === '-' ? '−' : ''}</span>
                                    <span className="rw-code">{l.text}</span>
                                </div>
                            ))}
                        </div>
                        <div>
                            <div className="rw-split-head">{tr("After restore (set)")}</div>
                            {s.lines.filter((l) => l.op !== '-').map((l, li) => (
                                <div key={li} className={`rw-dl ${l.op === '+' ? 'add' : 'ctx'}`}>
                                    <span className="rw-sg">{l.op === '+' ? '+' : ''}</span>
                                    <span className="rw-code">{l.text}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </div>
        ))}
    </div>
);

const downloadDiff = (preview, name) => {
    const body = preview.sections.map((s) => [
        `## ${s.title}`,
        ...s.lines.map((l) => `${l.op === ' ' ? ' ' : l.op} ${l.text}`),
    ].join('\n')).join('\n\n');
    const blob = new Blob([body + '\n'], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `restore-diff_${(name || 'asset').replace(/\s+/g, '_')}.diff`;
    a.click();
    URL.revokeObjectURL(url);
};

/* ------------------------------------------------------------------ */
/*  Step 4: progress timeline                                          */
/* ------------------------------------------------------------------ */

const TIMELINE = [
    { key: 'connect', title: tr("Connect over SSH"), hint: tr("Re-read the live configuration and check it has not changed since review") },
    { key: 'backup', title: tr("Back up the current configuration"), hint: tr("Saved as a \"Before restore\" backup - the undo point") },
    { key: 'apply', title: tr("Apply the changes"), hint: tr("Only the changed lines are sent; the first rejected command stops the run") },
    { key: 'verify', title: tr("Reconnect and verify"), hint: tr("A new SSH session proves access survived, then the live configuration is compared with the backup") },
    { key: 'save', title: tr("Save on device"), hint: tr("Only after verification succeeds - this cancels the auto-revert timer") },
];

const STATUS_STEP = {
    queued: 'connect', connecting: 'connect', backing_up: 'backup',
    applying: 'apply', verifying: 'verify', saving: 'save', reverting: 'revert',
};

const Timeline = ({ job }) => {
    const events = job.events || [];
    const currentKey = STATUS_STEP[job.status];
    const extras = events.filter((e) => !TIMELINE.some((t) => t.key === e.step));
    return (
        <div className="rw-tl-list">
            {TIMELINE.map((t, i) => {
                const mine = events.filter((e) => e.step === t.key);
                const last = mine[mine.length - 1];
                const failed = mine.some((e) => e.status === 'failed');
                const running = currentKey === t.key;
                const state = failed ? 'failed' : running ? 'running' : last ? 'done' : 'todo';
                return (
                    <div key={t.key} className={`rw-tl ${state}`}>
                        <span className="rw-dot">
                            {state === 'done' ? '✓' : state === 'failed' ? '!' : state === 'running'
                                ? <span className="rw-spin" /> : i + 1}
                        </span>
                        <div>
                            <h3>{t.title}</h3>
                            <p>{last ? last.message : t.hint}</p>
                        </div>
                        <span className="rw-t">{running && !last ? 'now' : formatTime(last?.at)}</span>
                    </div>
                );
            })}
            {extras.map((e, i) => (
                <div key={`x${i}`} className={`rw-tl ${e.status === 'failed' ? 'failed' : 'done'}`}>
                    <span className="rw-dot"><RestoreIcon size={14} /></span>
                    <div><h3>{e.step === 'revert' ? tr("Revert") : tr("Error")}</h3><p>{e.message}</p></div>
                    <span className="rw-t">{formatTime(e.at)}</span>
                </div>
            ))}
        </div>
    );
};

const Countdown = ({ job }) => {
    const applied = (job.events || []).find((e) => e.step === 'apply' && e.status === 'done');
    const [now, setNow] = useState(() => Date.now());
    useEffect(() => {
        const t = setInterval(() => setNow(Date.now()), 1000);
        return () => clearInterval(t);
    }, []);
    if (!applied) return null;
    const total = job.revert_minutes * 60 * 1000;
    const left = Math.max(0, new Date(applied.at).getTime() + total - now);
    const mm = String(Math.floor(left / 60000)).padStart(2, '0');
    const ss = String(Math.floor((left % 60000) / 1000)).padStart(2, '0');
    return (
        <div className="rw-countdown" role="timer">
            <TimerIcon size={22} />
            <div className="rw-countdown-text">
                {left > 0
                    ? <>{tx("The device reverts on its own in {{time}} unless verification completes.", { time: <b>{n(mm)}:{n(ss)}</b> })}</>
                    : <>{tr("The auto-revert timer has expired; waiting for the device to come back.")}</>}
            </div>
            <div className="rw-meter"><div style={{ width: `${Math.min(100, 100 - (left / total) * 100)}%` }} /></div>
        </div>
    );
};

/* ------------------------------------------------------------------ */
/*  Results                                                            */
/* ------------------------------------------------------------------ */

const duration = (job) => {
    if (!job.started_at || !job.finished_at) return '-';
    const s = Math.max(0, Math.round((new Date(job.finished_at) - new Date(job.started_at)) / 1000));
    return s < 90 ? `${s} seconds` : `${Math.round(s / 60)} minutes`;
};

const Result = ({ job }) => {
    const events = job.events || [];
    if (job.status === 'succeeded') {
        const changed = Boolean(job.pre_restore_backup_id);
        const reconnected = events.some((e) => e.step === 'verify' && /Reconnected/.test(e.message));
        return (
            <>
                <div className="rw-result-head">
                    <span className="rw-result-icon ok"><Check size={28} /></span>
                    <div>
                        <h1 className="ok">{changed ? tr("Restore completed and verified") : tr("Nothing to restore")}</h1>
                        <p>{changed
                            ? tr("{{asset}} now matches backup #{{backup_id}} exactly.", { asset: job.asset_name, backup_id: job.backup_id })
                            : tr("{{asset}} already matched backup #{{backup_id}} exactly.", { asset: job.asset_name, backup_id: job.backup_id })}</p>
                    </div>
                </div>
                <div className="rw-rows">
                    <div className="rw-row"><span>{tr("Verification")}</span><b className="ok">{tr("0 differences from backup #{{backup_id}}", { backup_id: job.backup_id })}</b></div>
                    {changed && (
                        <>
                            <div className="rw-row"><span>{tr("Access after restore")}</span>
                                <b>{reconnected ? tr("SSH reconnected successfully") : '-'}</b></div>
                            <div className="rw-row"><span>{tr("Saved on device")}</span>
                                <b>{tr("Yes")}{job.auto_revert === 'armed' ? tr(" · auto-revert timer cancelled") : ''}</b></div>
                            <div className="rw-row"><span>{tr("Undo point")}</span>
                                <b>{tr("Backup #{{pre_restore_backup_id}} \"Before restore\"", { pre_restore_backup_id: job.pre_restore_backup_id })}</b></div>
                        </>
                    )}
                    <div className="rw-row"><span>{tr("Duration")}</span><b>{duration(job)}</b></div>
                    <div className="rw-row"><span>{tr("Performed by")}</span>
                        <b>{job.requested_by_username || '-'} · {formatDateTime(job.created_at)}</b></div>
                    <div className="rw-row last"><span>{tr("Reason")}</span><b className="plain">{job.reason}</b></div>
                </div>
            </>
        );
    }
    const reverted = job.status === 'reverted';
    return (
        <>
            <div className="rw-result-head">
                <span className={`rw-result-icon ${reverted ? 'warn' : 'bad'}`}>
                    {reverted ? <RestoreIcon size={28} stroke="#92400e" />
                        : <Icon size={28} stroke="#991b1b" width={2.4} d="M18 6 6 18M6 6l12 12" />}
                </span>
                <div>
                    <h1 className={reverted ? 'warn' : 'bad'}>
                        {reverted ? tr("Restore reverted") : tr("Restore failed")}
                    </h1>
                    <p>
                        {reverted
                            ? tr("The device is back on its previous configuration. Nothing from backup #{{backup_id}} was kept.", { backup_id: job.backup_id })
                            : job.pre_restore_backup_id
                                ? tr("Backup #{{pre_restore_backup_id}} \"Before restore\" holds the configuration from before this run.", { pre_restore_backup_id: job.pre_restore_backup_id })
                                : tr("Nothing was changed on the device.")}
                    </p>
                </div>
            </div>
            {job.error && <div className="rw-why"><b>{tr("Why:")}</b> {job.error}</div>}
            <div className="rw-events">
                <h2>{tr("Timeline")}</h2>
                {events.map((e, i) => (
                    <div key={i} className={`rw-ev ${e.status}`}>
                        <span>{formatTime(e.at)}</span><div>{e.message}</div>
                    </div>
                ))}
            </div>
        </>
    );
};

/* ------------------------------------------------------------------ */
/*  Wizard                                                             */
/* ------------------------------------------------------------------ */

export const RestoreWizard = ({ backupId, jobId: initialJobId, onClose, onChanged, onOpenBackup }) => {
    const [step, setStep] = useState(initialJobId ? 3 : 0);
    const [openedAt] = useState(() => Date.now());
    const [backup, setBackup] = useState(null);
    const [loadError, setLoadError] = useState(null);

    const [creds, setCreds] = useState({
        ssh_port: 22, ssh_username: '', ssh_password: '', ssh_secret: '', sudo_password: '',
    });
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);

    const [preview, setPreview] = useState(null);
    const [diffMode, setDiffMode] = useState('unified');

    const [revertMinutes, setRevertMinutes] = useState(10);
    const [ackLockout, setAckLockout] = useState(false);
    const [allowNoRevert, setAllowNoRevert] = useState(false);
    const [reason, setReason] = useState('');
    const [confirmName, setConfirmName] = useState('');

    const [jobId, setJobId] = useState(initialJobId || null);
    const [job, setJob] = useState(null);
    const [pollError, setPollError] = useState(null);

    // Backup metadata for the header and step 1.
    useEffect(() => {
        if (!backupId) return undefined;
        let cancelled = false;
        (async () => {
            try {
                const res = await api.get(`/api/backups/${backupId}`);
                if (!cancelled) setBackup(res.data);
            } catch (e) {
                if (!cancelled) setLoadError(errorText(e, tr("Failed to load the backup")));
            }
        })();
        return () => { cancelled = true; };
    }, [backupId]);

    // Poll the job until it settles. The job runs server-side, so closing the
    // wizard never stops it; reopening it from the history resumes polling.
    useEffect(() => {
        if (!jobId) return undefined;
        let cancelled = false;
        let timer;
        // Reopening a job from the history must not refresh the page behind
        // it; only a run this wizard started (or watched finish) changes it.
        let sawActive = jobId !== initialJobId;
        const tick = async () => {
            try {
                const res = await api.get(`/api/backups/restores/${jobId}`);
                if (cancelled) return;
                setJob(res.data);
                setPollError(null);
                if (ACTIVE_RESTORE_STATUSES.includes(res.data.status)) {
                    sawActive = true;
                    timer = setTimeout(tick, POLL_MS);
                } else if (sawActive && onChanged) {
                    sawActive = false;
                    onChanged();
                }
            } catch (e) {
                if (cancelled) return;
                setPollError(errorText(e, tr("Lost contact with the server; retrying…")));
                timer = setTimeout(tick, POLL_RETRY_MS);
            }
        };
        tick();
        return () => { cancelled = true; clearTimeout(timer); };
    }, [jobId, initialJobId, onChanged]);

    const family = (backup?.device_type || job?.device_type || '').toLowerCase();
    const assetName = backup?.asset_name || job?.asset_name || '';
    const isCisco = family === 'cisco';
    const isHost = ['linux', 'apache', 'mongodb'].includes(family);

    const risks = useMemo(() => preview?.risks || [], [preview]);
    const lockouts = risks.filter((r) => r.severity === 'lockout');
    const warnings = risks.filter((r) => r.severity !== 'lockout');
    const autoRevert = preview?.auto_revert || { available: false };
    const changedLines = preview ? preview.summary.added + preview.summary.removed : 0;

    const nameMatches = confirmName.trim() !== '' && confirmName.trim() === (assetName || '').trim();
    const canStart = nameMatches
        && reason.trim().length >= 5
        && (lockouts.length === 0 || ackLockout)
        && (autoRevert.available || allowNoRevert)
        && !busy;

    const setCred = (e) => {
        const { name, value } = e.target;
        setCreds((prev) => ({ ...prev, [name]: value }));
    };

    const connectionBody = () => ({
        ssh_username: creds.ssh_username,
        ssh_password: creds.ssh_password,
        ssh_port: parseInt(creds.ssh_port, 10) || 22,
        ssh_secret: isCisco && creds.ssh_secret ? creds.ssh_secret : undefined,
        sudo_password: isHost && creds.sudo_password ? creds.sudo_password : undefined,
    });

    const runPreview = async (e) => {
        e.preventDefault();
        if (!creds.ssh_username || !creds.ssh_password) {
            setError(tr("SSH username and password are required."));
            return;
        }
        setBusy(true);
        setError(null);
        try {
            const res = await api.post(`/api/backups/${backupId}/restore/preview`, connectionBody());
            setPreview(res.data);
            setAckLockout(false);
            setAllowNoRevert(false);
            setStep(1);
        } catch (err) {
            setError(errorText(err, tr("Could not read the device. Check the SSH credentials and connectivity.")));
        } finally {
            setBusy(false);
        }
    };

    const startRestore = async () => {
        setBusy(true);
        setError(null);
        try {
            const res = await api.post(`/api/backups/${backupId}/restore`, {
                ...connectionBody(),
                reason: reason.trim(),
                confirm_name: confirmName.trim(),
                revert_minutes: revertMinutes,
                live_fingerprint: preview.live_fingerprint,
                acknowledge_lockout: ackLockout,
                allow_without_auto_revert: !autoRevert.available && allowNoRevert,
            });
            // Credentials are not needed any more; drop them from memory.
            setCreds((prev) => ({ ...prev, ssh_password: '', ssh_secret: '', sudo_password: '' }));
            setJob(res.data);
            setJobId(res.data.id);
            setStep(3);
            if (onChanged) onChanged();
        } catch (err) {
            setError(errorText(err, tr("The restore could not be started.")));
        } finally {
            setBusy(false);
        }
    };

    const finished = job && !ACTIVE_RESTORE_STATUSES.includes(job.status);
    const age = backup?.created_at
        ? Math.max(0, Math.floor((openedAt - new Date(backup.created_at).getTime()) / 86400000))
        : null;

    const subtitle = (() => {
        if (step === 0) return tr("{{assetName}} · from backup #{{backupId}}", { assetName, backupId });
        if (step === 1) return tr("{{assetName}} · live configuration (now) → backup #{{backupId}}", { assetName, backupId });
        if (step === 2) return tr("{{assetName}} · {{count}} changed lines from backup #{{backupId}}", { assetName, count: changedLines, backupId });
        return tr("You can close this window - the restore continues and stays listed under Restores for this asset.");
    })();

    const wide = step === 1;

    return (
        <div className="rw-overlay" role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget && !busy) onClose(); }}>
            <section className={`rw-modal ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby="rw-title">
                {finished ? (
                    <div className="rw-result"><Result job={job} /></div>
                ) : (
                    <>
                        <header className="rw-head">
                            <div>
                                <h1 id="rw-title">
                                    {step === 3 ? tr("Restoring {{assetName}}…", { assetName }) : tr("Restore configuration")}
                                </h1>
                                <p>{subtitle}</p>
                            </div>
                            <button className="rw-close" aria-label={tr("Close")} onClick={onClose} disabled={busy}>
                                <Icon size={18} d="M18 6 6 18M6 6l12 12" />
                            </button>
                        </header>
                        <Stepper current={step} />
                    </>
                )}

                {error && <div className="rw-alert" role="alert">{error}</div>}

                {/* ---- Step 1: connect ---- */}
                {step === 0 && (
                    <form className="rw-form" onSubmit={runPreview}>
                        <div className="rw-body">
                            {loadError ? (
                                <div className="rw-alert" role="alert">{loadError}</div>
                            ) : !backup ? (
                                <div className="rw-loading"><span className="rw-spin" /> {" "}{tr("Loading backup…")}</div>
                            ) : (
                                <div className="rw-kv-grid">
                                    <div className="rw-kv"><span>{tr("Asset")}</span><b>{backup.asset_name || tr("Asset #{{asset_id}}", { asset_id: backup.asset_id })}</b></div>
                                    <div className="rw-kv"><span>{tr("Device type")}</span><b>{familyLabel(backup.device_type)}</b></div>
                                    <div className="rw-kv"><span>{tr("Backup")}</span><b>{tr("#{{id}} · {{count}} lines", { id: backup.id, count: lineCount(backup.config_content) })}</b></div>
                                    <div className="rw-kv"><span>{tr("Taken")}</span><b>{formatDateTime(backup.created_at)}</b></div>
                                    <div className="rw-kv"><span>{tr("Source")}</span><b>{sourceLabel(backup.source)}</b></div>
                                    <div className="rw-kv"><span>{tr("Taken by")}</span><b>{backup.created_by_username || '-'}</b></div>
                                    <div className="rw-kv"><span>{tr("Age")}</span><b>{age === null ? '-' : age === 0 ? tr("Today") : tr("{{count}} days", { count: age })}</b></div>
                                    <div className="rw-kv"><span>{tr("Host")}</span><b>{backup.device_ip || '-'}</b></div>
                                </div>
                            )}
                            <div>
                                <h2 className="rw-h2">{tr("SSH connection")}</h2>
                                <p className="rw-muted">
                                    {tr("NGCorion first reads the device's live configuration to show exactly what will change. Nothing is written yet.")}
                                </p>
                                <div className="rw-fields">
                                    <div className="rw-field span2">
                                        <label htmlFor="rw-host">{tr("Host")}</label>
                                        <input id="rw-host" value={backup?.device_ip || ''} readOnly className="ro" />
                                    </div>
                                    <div className="rw-field">
                                        <label htmlFor="rw-port">{tr("SSH port")}</label>
                                        <input id="rw-port" name="ssh_port" type="number" min={1} max={65535}
                                               value={creds.ssh_port} onChange={setCred} />
                                    </div>
                                    <div className="rw-field" />
                                    <div className="rw-field span2">
                                        <label htmlFor="rw-user">{tr("Username")}</label>
                                        <input id="rw-user" name="ssh_username" autoComplete="username"
                                               value={creds.ssh_username} onChange={setCred} required />
                                    </div>
                                    <div className="rw-field span2">
                                        <label htmlFor="rw-pass">{tr("Password")}</label>
                                        <input id="rw-pass" name="ssh_password" type="password" autoComplete="current-password"
                                               value={creds.ssh_password} onChange={setCred} required />
                                    </div>
                                    {isCisco && (
                                        <div className="rw-field span2">
                                            <label htmlFor="rw-secret">{tr("Enable secret")}{" "} <span className="rw-opt">{tr("(optional)")}</span></label>
                                            <input id="rw-secret" name="ssh_secret" type="password" autoComplete="off"
                                                   value={creds.ssh_secret} onChange={setCred} />
                                        </div>
                                    )}
                                    {isHost && (
                                        <div className="rw-field span2">
                                            <label htmlFor="rw-sudo">{tr("Sudo password")}{" "} <span className="rw-opt">{tr("(if different from SSH password)")}</span></label>
                                            <input id="rw-sudo" name="sudo_password" type="password" autoComplete="off"
                                                   value={creds.sudo_password} onChange={setCred} />
                                        </div>
                                    )}
                                </div>
                            </div>
                            <p className="rw-note">
                                <Icon stroke="#1e3a5f"><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></Icon>
                                {tr("Credentials are used for this restore only and are never stored.")}
                            </p>
                        </div>
                        <footer className="rw-foot">
                            <button type="button" className="rw-btn" onClick={onClose} disabled={busy}>{tr("Cancel")}</button>
                            <button type="submit" className="rw-btn primary" disabled={busy || !backup}>
                                {busy ? <><span className="rw-spin light" /> {" "}{tr("Reading live configuration…")}</> : tr("Connect & compare →")}
                            </button>
                        </footer>
                    </form>
                )}

                {/* ---- Step 2: review ---- */}
                {step === 1 && preview && (
                    <>
                        <div className="rw-body tight">
                            <div className="rw-review-bar">
                                <div className="rw-chips">
                                    <span className="rw-chip add">{tr("+ {{added}} will be set", { added: preview.summary.added })}</span>
                                    <span className="rw-chip del">{tr("− {{removed}} will be removed", { removed: preview.summary.removed })}</span>
                                    {risks.length > 0 && (
                                        <span className="rw-chip warn">{tr("⚠ {{count}} affect management access", { count: risks.length })}</span>
                                    )}
                                    <span className="rw-chip">{tr("{{count}} sections", { count: preview.summary.sections })}</span>
                                </div>
                                {!preview.no_changes && (
                                    <div className="rw-seg" role="group" aria-label={tr("Diff view")}>
                                        <button className={diffMode === 'unified' ? 'on' : ''} aria-pressed={diffMode === 'unified'}
                                                onClick={() => setDiffMode('unified')}>{tr("Unified")}</button>
                                        <button className={diffMode === 'split' ? 'on' : ''} aria-pressed={diffMode === 'split'}
                                                onClick={() => setDiffMode('split')}>{tr("Side by side")}</button>
                                    </div>
                                )}
                            </div>
                            {lockouts.map((r, i) => (
                                <div key={`l${i}`} className="rw-banner">
                                    <Icon size={20} stroke="#c2410c"><path d="M12 3 2 21h20L12 3Z" /><path d="M12 10v5m0 3v.01" /></Icon>
                                    <div>
                                        <b>{tr("Possible lock-out.")}</b> {r.message}
                                        {autoRevert.available && <>{" "}{tr("The safety timer in the next step reverts the device automatically if that happens.")}</>}
                                    </div>
                                </div>
                            ))}
                            {warnings.length > 0 && (
                                <ul className="rw-warnings">
                                    {warnings.map((r, i) => <li key={`w${i}`}>{r.message}</li>)}
                                </ul>
                            )}
                            {preview.no_changes ? (
                                <div className="rw-same">
                                    <Check />
                                    <div><b>{tr("The device already matches this backup.")}</b> {" "}{tr("There is nothing to restore.")}</div>
                                </div>
                            ) : (
                                <DiffView sections={preview.sections} mode={diffMode} />
                            )}
                            {preview.truncated && (
                                <p className="rw-muted">{tr("The preview is truncated; the full change set is applied.")}</p>
                            )}
                            {preview.skipped?.length > 0 && (
                                <details className="rw-skipped">
                                    <summary>{tr("{{count}} items cannot be restored and will be left as they are", { count: preview.skipped.length })}</summary>
                                    <ul>{preview.skipped.map((s, i) => <li key={i}><code>{s}</code></li>)}</ul>
                                </details>
                            )}
                        </div>
                        <footer className="rw-foot">
                            <button className="rw-btn" onClick={() => { setError(null); setStep(0); }}>{tr("← Back")}</button>
                            <div className="rw-foot-right">
                                {!preview.no_changes && (
                                    <button className="rw-btn" onClick={() => downloadDiff(preview, assetName)}>{tr("Download diff")}</button>
                                )}
                                {preview.no_changes ? (
                                    <button className="rw-btn primary" onClick={onClose}>{tr("Close")}</button>
                                ) : (
                                    <button className="rw-btn primary" onClick={() => { setError(null); setStep(2); }}>{tr("Continue →")}</button>
                                )}
                            </div>
                        </footer>
                    </>
                )}

                {/* ---- Step 3: safety & confirm ---- */}
                {step === 2 && preview && (
                    <>
                        <div className="rw-body">
                            <h2 className="rw-h2">{tr("Safety net")}</h2>
                            <div className="rw-safe">
                                <Check />
                                <div><h3>{tr("Back up the current configuration first")}</h3>
                                    <p>{tr("Saved as a \"Before restore\" backup, so this restore can itself be undone.")}</p></div>
                                <span className="rw-lock">{tr("Always on")}</span>
                            </div>
                            {autoRevert.available ? (
                                <div className="rw-safe blue">
                                    <TimerIcon />
                                    <div><h3>{tr("Auto-revert if NGCorion loses the device")}</h3>
                                        <p>{AUTO_REVERT_TEXT[family]}</p></div>
                                    <div className="rw-field timer">
                                        <label htmlFor="rw-timer">{tr("Timer")}</label>
                                        <select id="rw-timer" value={revertMinutes}
                                                onChange={(e) => setRevertMinutes(parseInt(e.target.value, 10))}>
                                            {[5, 10, 15].map((m) => <option key={m} value={m}>{tr("{{m}} minutes", { m })}</option>)}
                                        </select>
                                    </div>
                                </div>
                            ) : (
                                <div className="rw-safe amber">
                                    <Icon size={20} stroke="#c2410c"><path d="M12 3 2 21h20L12 3Z" /><path d="M12 10v5m0 3v.01" /></Icon>
                                    <div><h3>{tr("Auto-revert is not available on this device")}</h3>
                                        <p>{autoRevert.reason || tr("The device cannot revert on its own.")} {" "}{tr("If NGCorion loses access after the changes, the device will not recover by itself.")}</p></div>
                                    <span className="rw-lock off">{tr("Unavailable")}</span>
                                </div>
                            )}
                            <div className="rw-safe">
                                <Check />
                                <div><h3>{tr("Verify after restore")}</h3>
                                    <p>{autoRevert.available
                                        ? tr("Re-read the live configuration and compare it with backup #{{backupId}}. Any difference is reported and reverted.", { backupId })
                                        : tr("Re-read the live configuration and compare it with backup #{{backupId}}. Any difference is reported.", { backupId })}</p></div>
                                <span className="rw-lock">{tr("Always on")}</span>
                            </div>
                            <div className="rw-safe">
                                <Check />
                                <div><h3>{tr("Stop at the first error")}</h3>
                                    <p>{autoRevert.available
                                        ? tr("If the device rejects a command, nothing more is sent and the changes are reverted.")
                                        : tr("If the device rejects a command, nothing more is sent.")}</p></div>
                                <span className="rw-lock">{tr("Always on")}</span>
                            </div>

                            {lockouts.length > 0 && (
                                <label className="rw-ack">
                                    <input type="checkbox" checked={ackLockout} onChange={(e) => setAckLockout(e.target.checked)} />
                                    <span>
                                        {tr("I understand that {{what}} may block NGCorion{{ip}}: {{reason}}", {
                                            what: lockouts.length === 1 ? tr("this restore") : tr("these {{count}} changes", { count: lockouts.length }),
                                            ip: preview.source_ip ? ` (${preview.source_ip})` : "",
                                            reason: lockouts[0].message })}
                                    </span>
                                </label>
                            )}
                            {!autoRevert.available && (
                                <label className="rw-ack">
                                    <input type="checkbox" checked={allowNoRevert} onChange={(e) => setAllowNoRevert(e.target.checked)} />
                                    <span>{tr("I understand there is no automatic revert, and will restore backup \"Before restore\" by hand if needed.")}</span>
                                </label>
                            )}

                            <div className="rw-fields two">
                                <div className="rw-field">
                                    <label htmlFor="rw-reason">{tr("Reason (required, saved in the audit log)")}</label>
                                    <textarea id="rw-reason" rows={2} maxLength={1000} value={reason}
                                              onChange={(e) => setReason(e.target.value)}
                                              placeholder={tr("Why is this configuration being restored?")} />
                                </div>
                                <div className="rw-field">
                                    <label htmlFor="rw-confirm">{tr("Type the asset name to confirm")}</label>
                                    <input id="rw-confirm" value={confirmName} autoComplete="off"
                                           className={confirmName ? (nameMatches ? 'match' : 'nomatch') : ''}
                                           onChange={(e) => setConfirmName(e.target.value)} placeholder={assetName} />
                                    {confirmName && (
                                        <span className={`rw-match ${nameMatches ? 'ok' : 'bad'}`}>
                                            {nameMatches ? tr("✓ Matches") : tr("Does not match")}
                                        </span>
                                    )}
                                </div>
                            </div>
                        </div>
                        <footer className="rw-foot">
                            <button className="rw-btn" onClick={() => { setError(null); setStep(1); }} disabled={busy}>{tr("← Back")}</button>
                            <div className="rw-foot-right">
                                <span className="rw-muted small">{tr("Admin or Manager only")}</span>
                                <button className="rw-btn danger" onClick={startRestore} disabled={!canStart}>
                                    {busy ? <span className="rw-spin light" /> : <RestoreIcon />}
                                    {tr("Restore {{assetName}}", { assetName })}
                                </button>
                            </div>
                        </footer>
                    </>
                )}

                {/* ---- Step 4: running ---- */}
                {step === 3 && !finished && (
                    <>
                        <div className="rw-body">
                            {pollError && <div className="rw-alert" role="alert">{pollError}</div>}
                            {job ? <Timeline job={job} /> : <div className="rw-loading"><span className="rw-spin" /> {" "}{tr("Loading…")}</div>}
                            {job && job.auto_revert === 'armed' && ['applying', 'verifying', 'saving'].includes(job.status) && (
                                <Countdown job={job} />
                            )}
                        </div>
                        <footer className="rw-foot">
                            <button className="rw-btn" onClick={onClose}>{tr("Close (keeps running)")}</button>
                        </footer>
                    </>
                )}

                {finished && (
                    <footer className="rw-foot">
                        <div className="rw-foot-left">
                            {job.pre_restore_backup_id && job.status !== 'reverted' && onOpenBackup && (
                                <button className="rw-btn" onClick={() => onOpenBackup(job.pre_restore_backup_id)}>
                                    {job.status === 'succeeded'
                                        ? tr("Undo — restore backup #{{id}}", { id: job.pre_restore_backup_id })
                                        : tr("Restore backup #{{pre_restore_backup_id}}", { pre_restore_backup_id: job.pre_restore_backup_id })}
                                </button>
                            )}
                        </div>
                        <div className="rw-foot-right">
                            {job.status !== 'succeeded' && job.backup_id && onOpenBackup && (
                                <button className="rw-btn" onClick={() => onOpenBackup(job.backup_id)}>{tr("Review changes again")}</button>
                            )}
                            <button className="rw-btn primary" onClick={onClose}>
                                {job.status === 'succeeded' ? tr("Done") : tr("Close")}
                            </button>
                        </div>
                    </footer>
                )}
            </section>
        </div>
    );
};

export default RestoreWizard;
