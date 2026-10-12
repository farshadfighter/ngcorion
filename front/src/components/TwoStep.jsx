/**
 * Two-step sign-in (TOTP) for the signed-in user: the setup wizard (password → QR code → first
 * code → recovery codes), and the account dialog to move it to a new phone, make new recovery codes
 * or turn it off. With `forced`, the role requires it and the dashboard shows nothing else until
 * it is set up (the server refuses every other request: 403 X-MFA-Enrollment-Required).
 *
 * Turning it on, moving it or turning it off ends the user's other sessions; the server answers
 * with a fresh token for this one (sessionReplaced).
 */
import { useEffect, useState } from "react";
import { useDispatch } from "react-redux";
import QRCode from "qrcode";

import api from "../config/api";
import { logoutUser, sessionReplaced } from "../store/authSlice";
import { n, t } from "../i18n";
import { tb } from "../i18n/backendText";
import { formatDate } from "../utils/dates";
import { asciiDigits } from "../utils/digits";
import "../assets/TwoStep.css";


const errorText = (err, fallback) => {
    const detail = err.response?.data?.detail;
    if (typeof detail === "string") return tb(detail);
    if (err.response?.status === 429) return t("Too many failed login attempts. Please wait before trying again.");
    return fallback;
};

const CodeInput = ({ id, value, onChange, allowRecovery = false, autoFocus = false }) => (
    <input id={id} className="ts-code" dir="ltr" type="text" autoComplete="one-time-code"
           inputMode={allowRecovery ? "text" : "numeric"} maxLength={allowRecovery ? 12 : 6}
           placeholder={allowRecovery ? "123456 / XXXX-XXXX" : "123456"} autoFocus={autoFocus}
           value={value}
           onChange={(e) => {
               const v = asciiDigits(e.target.value);
               onChange(allowRecovery ? v.toUpperCase() : v.replace(/\D/g, ""));
           }} />
);

/** The recovery codes, shown once, with copy and save. */
export const RecoveryCodes = ({ codes, username }) => {
    const [copied, setCopied] = useState(false);
    const text = `NGCorion — ${username}\n${t("Recovery codes (each works once)")}\n\n${codes.join("\n")}\n`;
    const copy = async () => {
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
        } catch {
            setCopied(false); // no clipboard on plain http: the codes are on screen and can be saved
        }
    };
    const save = () => {
        const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
        const a = document.createElement("a");
        a.href = url;
        a.download = `ngcorion-recovery-codes-${username}.txt`;
        a.click();
        URL.revokeObjectURL(url);
    };
    return (
        <div className="ts-codes-box">
            <ol className="ts-codes" dir="ltr">
                {codes.map((c) => <li key={c}><code>{c}</code></li>)}
            </ol>
            <div className="ts-codes-actions">
                <button type="button" className="ts-btn ts-btn-ghost" onClick={copy}>
                    <i className={`fa-solid ${copied ? "fa-check" : "fa-copy"}`} aria-hidden="true" /> {copied ? t("Copied") : t("Copy")}
                </button>
                <button type="button" className="ts-btn ts-btn-ghost" onClick={save}>
                    <i className="fa-solid fa-download" aria-hidden="true" /> {t("Save as a file")}
                </button>
            </div>
        </div>
    );
};

const Steps = ({ at }) => {
    const names = [t("Confirm it is you"), t("Scan the code"), t("Save the recovery codes")];
    return (
        <ol className="ts-steps" aria-label={t("Steps")}>
            {names.map((name, i) => (
                <li key={name} className={i < at ? "done" : i === at ? "now" : ""} aria-current={i === at ? "step" : undefined}>
                    <span className="ts-step-n">{i < at ? <i className="fa-solid fa-check" aria-hidden="true" /> : n(i + 1)}</span>
                    {name}
                </li>
            ))}
        </ol>
    );
};

/**
 * The setup wizard. `replacing`: the account already has an app and moves to a new one (a code
 * from the current app is asked too).
 */
export const TwoStepSetup = ({ username, forced = false, replacing = false, deadline = null, onClose }) => {
    const dispatch = useDispatch();
    const [step, setStep] = useState(0);
    const [password, setPassword] = useState("");
    const [oldCode, setOldCode] = useState("");
    const [setup, setSetup] = useState(null);
    const [qr, setQr] = useState(null);
    const [code, setCode] = useState("");
    const [codes, setCodes] = useState(null);
    const [saved, setSaved] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);
    const [showKey, setShowKey] = useState(false);

    useEffect(() => {
        if (!setup) return;
        QRCode.toDataURL(setup.otpauth_uri, { margin: 1, width: 196, errorCorrectionLevel: "M" })
            .then(setQr).catch(() => setQr(null));
    }, [setup]);

    const start = async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        try {
            const { data } = await api.post("/auth/me/mfa/setup", { password, code: replacing ? oldCode : null });
            setSetup(data);
            setPassword("");
            setStep(1);
        } catch (err) {
            setError(errorText(err, t("Something went wrong. Please try again.")));
        } finally {
            setBusy(false);
        }
    };

    const confirm = async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        try {
            const { data } = await api.post("/auth/me/mfa/confirm", { code });
            // The other sessions (this one's old token included) ended: use the new token at once,
            // so nothing in the background signs this browser out while the codes are shown.
            dispatch(sessionReplaced(data.session));
            setCodes(data.recovery_codes);
            setSetup(null);
            setQr(null);
            setStep(2);
        } catch (err) {
            setCode("");
            setError(errorText(err, t("Something went wrong. Please try again.")));
        } finally {
            setBusy(false);
        }
    };
    const finish = () => onClose(true);

    const groupedKey = setup ? setup.secret.match(/.{1,4}/g).join(" ") : "";

    return (
        <div className="ts-overlay" onClick={forced || step === 2 ? undefined : () => onClose(false)}>
            <div className="ts-dialog" role="dialog" aria-modal="true" aria-labelledby="ts-title" onClick={(e) => e.stopPropagation()}>
                <div className="ts-head">
                    <div className="ts-head-icon" aria-hidden="true"><i className="fa-solid fa-shield-halved" /></div>
                    <div>
                        <h2 id="ts-title">{replacing ? t("Move two-step sign-in to a new phone") : t("Set up two-step sign-in")}</h2>
                        <p className="ts-sub">
                            {forced
                                ? t("Your role must use two-step sign-in. Set it up to continue; it takes about a minute.")
                                : t("After your password, NGCorion will ask for a code from an app on your phone.")}
                        </p>
                    </div>
                    {!forced && step < 2 && (
                        <button type="button" className="ts-x" onClick={() => onClose(false)} aria-label={t("Close")}>✕</button>
                    )}
                </div>
                <Steps at={step} />

                {step === 0 && (
                    <form className="ts-body" onSubmit={start}>
                        {forced && deadline && (
                            <p className="ts-note">{t("The deadline to set it up was {{date}}.", { date: formatDate(deadline) })}</p>
                        )}
                        <p className="ts-p">{t("You need an authenticator app on your phone, for example Google Authenticator, Microsoft Authenticator or FreeOTP. They work offline.")}</p>
                        <label className="ts-label" htmlFor="ts-pw">{t("Your password")}</label>
                        <input id="ts-pw" className="ts-input" type="password" autoComplete="current-password" autoFocus
                               value={password} onChange={(e) => setPassword(e.target.value)} />
                        {replacing && (
                            <>
                                <label className="ts-label" htmlFor="ts-old">{t("A code from your current app (or a recovery code)")}</label>
                                <CodeInput id="ts-old" value={oldCode} onChange={setOldCode} allowRecovery />
                            </>
                        )}
                        {error && <p className="ts-error" role="alert">{error}</p>}
                        <div className="ts-actions">
                            {forced ? (
                                <button type="button" className="ts-btn ts-btn-ghost" onClick={() => dispatch(logoutUser())}>{t("Logout")}</button>
                            ) : (
                                <button type="button" className="ts-btn ts-btn-ghost" onClick={() => onClose(false)}>{t("Cancel")}</button>
                            )}
                            <button type="submit" className="ts-btn ts-btn-primary" disabled={busy || !password || (replacing && !oldCode)}>
                                {busy ? t("Checking…") : t("Continue")}
                            </button>
                        </div>
                    </form>
                )}

                {step === 1 && setup && (
                    <form className="ts-body" onSubmit={confirm}>
                        <div className="ts-scan">
                            <div className="ts-qr">
                                {qr ? <img src={qr} width="196" height="196" alt={t("QR code for the authenticator app")} />
                                    : <span className="ts-qr-wait">{t("Loading…")}</span>}
                            </div>
                            <div className="ts-scan-text">
                                <p className="ts-p"><b>{n(1)}.</b> {t("In the app, add an account and scan this code.")}</p>
                                <button type="button" className="ts-link" onClick={() => setShowKey(!showKey)} aria-expanded={showKey}>
                                    {t("Cannot scan? Enter the key by hand")}
                                </button>
                                {showKey && (
                                    <div className="ts-key">
                                        <code dir="ltr">{groupedKey}</code>
                                        <span>{t("Account: {{name}} · Type: time-based · 6 digits", { name: `NGCorion:${username}` })}</span>
                                    </div>
                                )}
                                <p className="ts-p"><b>{n(2)}.</b> {t("Enter the 6-digit code the app shows.")}</p>
                                <CodeInput id="ts-code" value={code} onChange={setCode} autoFocus />
                            </div>
                        </div>
                        {error && <p className="ts-error" role="alert">{error}</p>}
                        <div className="ts-actions">
                            <button type="button" className="ts-btn ts-btn-ghost" onClick={() => { setStep(0); setSetup(null); setCode(""); setError(null); }}>
                                {t("Back")}
                            </button>
                            <button type="submit" className="ts-btn ts-btn-primary" disabled={busy || code.length !== 6}>
                                {busy ? t("Checking…") : replacing ? t("Move to this phone") : t("Turn on")}
                            </button>
                        </div>
                    </form>
                )}

                {step === 2 && codes && (
                    <div className="ts-body">
                        <p className="ts-ok"><i className="fa-solid fa-circle-check" aria-hidden="true" /> {replacing
                            ? t("Two-step sign-in now uses the new phone. Your other sessions have ended.")
                            : t("Two-step sign-in is on. Your other sessions have ended.")}</p>
                        <p className="ts-p">{t("If you lose your phone, each of these codes lets you sign in once. Keep them somewhere safe, away from the phone. They are shown only now.")}</p>
                        <RecoveryCodes codes={codes} username={username} />
                        <label className="ts-check">
                            <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
                            {t("I have saved the recovery codes")}
                        </label>
                        <div className="ts-actions">
                            <button type="button" className="ts-btn ts-btn-primary" disabled={!saved} onClick={finish}>{t("Done")}</button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

/** The account dialog: state and actions for the signed-in user. */
export const TwoStepAccount = ({ username, onClose }) => {
    const dispatch = useDispatch();
    const [state, setState] = useState(null);
    const [mode, setMode] = useState(null); // "setup" | "replace" | "codes" | "off"
    const [password, setPassword] = useState("");
    const [code, setCode] = useState("");
    const [newCodes, setNewCodes] = useState(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(null);

    const load = () => api.get("/auth/me/mfa").then(({ data }) => setState(data)).catch(() => setState(false));
    useEffect(() => { load(); }, []);

    const act = async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        try {
            if (mode === "codes") {
                const { data } = await api.post("/auth/me/mfa/recovery-codes", { password, code });
                setNewCodes(data.recovery_codes);
            } else {
                const { data } = await api.post("/auth/me/mfa/disable", { password, code });
                dispatch(sessionReplaced(data));
                setMode(null);
                load();
            }
            setPassword("");
            setCode("");
        } catch (err) {
            setError(errorText(err, t("Something went wrong. Please try again.")));
        } finally {
            setBusy(false);
        }
    };

    if (mode === "setup" || mode === "replace") {
        return <TwoStepSetup username={username} replacing={mode === "replace"}
                             onClose={(done) => { setMode(null); if (done) load(); }} />;
    }

    return (
        <div className="ts-overlay" onClick={() => onClose()}>
            <div className="ts-dialog ts-dialog-sm" role="dialog" aria-modal="true" aria-labelledby="ts-acc-title" onClick={(e) => e.stopPropagation()}>
                <div className="ts-head">
                    <div className="ts-head-icon" aria-hidden="true"><i className="fa-solid fa-shield-halved" /></div>
                    <div>
                        <h2 id="ts-acc-title">{t("Two-step sign-in")}</h2>
                        <p className="ts-sub">{t("A code from your phone after your password, so a stolen password alone cannot open your account.")}</p>
                    </div>
                    <button type="button" className="ts-x" onClick={() => onClose()} aria-label={t("Close")}>✕</button>
                </div>
                <div className="ts-body">
                    {state === null && <p className="ts-p">{t("Loading…")}</p>}
                    {state === false && <p className="ts-error">{t("Something went wrong. Please try again.")}</p>}
                    {state && (
                        <>
                            <div className={`ts-state ${state.enabled ? "on" : "off"}`}>
                                <i className={`fa-solid ${state.enabled ? "fa-lock" : "fa-lock-open"}`} aria-hidden="true" />
                                <div>
                                    <b>{state.enabled ? t("On") : t("Off")}</b>
                                    {state.enabled && state.enabled_at && <span>{t("Since {{date}}", { date: formatDate(state.enabled_at) })}</span>}
                                    {!state.enabled && state.required && state.deadline && (
                                        <span>{t("Your role must use it. Set it up by {{date}}.", { date: formatDate(state.deadline) })}</span>
                                    )}
                                </div>
                            </div>
                            {state.enabled && (
                                <p className={`ts-p ${state.recovery_codes_left <= 2 ? "ts-warn" : ""}`}>
                                    {t("Recovery codes left: {{left}} of {{all}}", { left: state.recovery_codes_left, all: 8 })}
                                </p>
                            )}

                            {newCodes ? (
                                <>
                                    <p className="ts-ok"><i className="fa-solid fa-circle-check" aria-hidden="true" /> {t("New recovery codes. The old ones no longer work.")}</p>
                                    <RecoveryCodes codes={newCodes} username={username} />
                                    <div className="ts-actions">
                                        <button type="button" className="ts-btn ts-btn-primary" onClick={() => { setNewCodes(null); setMode(null); load(); }}>{t("Done")}</button>
                                    </div>
                                </>
                            ) : mode ? (
                                <form onSubmit={act}>
                                    <p className="ts-p"><b>{mode === "codes" ? t("Make new recovery codes") : t("Turn off two-step sign-in")}</b></p>
                                    <label className="ts-label" htmlFor="ts-acc-pw">{t("Your password")}</label>
                                    <input id="ts-acc-pw" className="ts-input" type="password" autoComplete="current-password" autoFocus
                                           value={password} onChange={(e) => setPassword(e.target.value)} />
                                    <label className="ts-label" htmlFor="ts-acc-code">{t("A code from your app (or a recovery code)")}</label>
                                    <CodeInput id="ts-acc-code" value={code} onChange={setCode} allowRecovery />
                                    {error && <p className="ts-error" role="alert">{error}</p>}
                                    <div className="ts-actions">
                                        <button type="button" className="ts-btn ts-btn-ghost" onClick={() => { setMode(null); setError(null); }}>{t("Cancel")}</button>
                                        <button type="submit" className={`ts-btn ${mode === "off" ? "ts-btn-danger" : "ts-btn-primary"}`}
                                                disabled={busy || !password || code.length < 6}>
                                            {busy ? t("Checking…") : mode === "codes" ? t("Make new codes") : t("Turn off")}
                                        </button>
                                    </div>
                                </form>
                            ) : state.enabled ? (
                                <div className="ts-menu">
                                    <button type="button" onClick={() => setMode("replace")}>
                                        <i className="fa-solid fa-mobile-screen" aria-hidden="true" />
                                        <span><b>{t("Move to a new phone")}</b><small>{t("Scan a new code; the old phone stops working.")}</small></span>
                                    </button>
                                    <button type="button" onClick={() => setMode("codes")}>
                                        <i className="fa-solid fa-key" aria-hidden="true" />
                                        <span><b>{t("Make new recovery codes")}</b><small>{t("When you have used some or lost the list.")}</small></span>
                                    </button>
                                    {!state.required && (
                                        <button type="button" className="danger" onClick={() => setMode("off")}>
                                            <i className="fa-solid fa-lock-open" aria-hidden="true" />
                                            <span><b>{t("Turn off two-step sign-in")}</b><small>{t("Your password alone will open your account again.")}</small></span>
                                        </button>
                                    )}
                                    {state.required && <p className="ts-note">{t("Your role must use two-step sign-in, so it cannot be turned off.")}</p>}
                                </div>
                            ) : (
                                <div className="ts-actions">
                                    <button type="button" className="ts-btn ts-btn-primary" onClick={() => setMode("setup")}>{t("Set up two-step sign-in")}</button>
                                </div>
                            )}
                        </>
                    )}
                </div>
            </div>
        </div>
    );
};
