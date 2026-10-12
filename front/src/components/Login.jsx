/**
 * Login page.
 */
import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate, useLocation } from "react-router-dom";
import { loginUser, loginMfa, cancelMfa, clearError } from "../store/authSlice";
import UserIcon from "../assets/UserIcon.jsx";
import LockIcon from "../assets/LockIcon.jsx";
import { currentLanguage, LANGUAGES, setLanguage, t } from "../i18n";
import api from "../config/api";
import { IDLE_MINUTES_KEY, IDLE_NOTICE_KEY } from "../utils/idle";
import { asciiDigits } from "../utils/digits";

// Shown under the form before anyone signs in, unless the server sets its own (LOGIN_BANNER).
// (One literal on purpose: the i18n extractor only sees whole strings.)
const DEFAULT_BANNER = () => t("Authorised use only. This system is monitored: every sign-in and every action is recorded with your user name and address. Unauthorised access is prohibited and may be prosecuted.");

export const Login = () => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [showErrorDialog, setShowErrorDialog] = useState(false);
    const [banner, setBanner] = useState(null);
    const [idleNotice] = useState(() => sessionStorage.getItem(IDLE_NOTICE_KEY) === "1");

    const dispatch = useDispatch();
    const navigate = useNavigate();
    const location = useLocation();
    const { isLoading, error, token, mfaChallenge } = useSelector((state) => state.auth);
    // Two-step sign-in: the code from the app, or a recovery code instead.
    const [code, setCode] = useState("");
    const [useRecovery, setUseRecovery] = useState(false);

    // The notice before sign-in, and the idle timeout the app signs out after.
    useEffect(() => {
        sessionStorage.removeItem(IDLE_NOTICE_KEY);
        api.get("/auth/login-banner")
            .then(({ data }) => {
                setBanner(data?.banner || "");
                if (data?.idle_timeout_minutes) localStorage.setItem(IDLE_MINUTES_KEY, String(data.idle_timeout_minutes));
            })
            .catch(() => setBanner(""));
    }, []);

    useEffect(() => {
        if (token) {
            // Return to the originally requested URL (set by ProtectedRoute),
            // falling back to the overview home page.
            const dest = location.state?.from?.pathname || "/overview";
            navigate(dest, { replace: true });
        }
    }, [token, navigate, location]);

    // A new error opens the dialog (adjusted during render, not in an effect).
    const [shownError, setShownError] = useState(null);
    if (error && error !== shownError) {
        setShownError(error);
        setShowErrorDialog(true);
    }

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!username.trim() || !password.trim()) {
            return;
        }
        try {
            await dispatch(loginUser({ username, password })).unwrap();
        } catch {
            // rejection is surfaced via the `error` selector + dialog effect
        }
    };

    const handleCode = async (e) => {
        e.preventDefault();
        if (!code.trim()) return;
        try {
            await dispatch(loginMfa({ mfaToken: mfaChallenge.token, code })).unwrap();
        } catch {
            setCode("");
        }
    };

    const backToPassword = () => {
        setCode("");
        setUseRecovery(false);
        setPassword("");
        dispatch(cancelMfa());
    };

    const getErrorMessage = () => {
        if (!error) return null;
        if (typeof error === "string") return error;
        if (typeof error === "object" && error.detail) return error.detail;
        return t("Invalid username or password");
    };

    const closeDialog = () => {
        setShowErrorDialog(false);
        dispatch(clearError());
    };

    return (
        <div className="login-page">
            <div className="login-lang" role="group" aria-label="Language / زبان">
                {LANGUAGES.map((l) => (
                    <button key={l.code} type="button" lang={l.code} dir={l.dir}
                            aria-pressed={currentLanguage() === l.code}
                            className={currentLanguage() === l.code ? "is-on" : ""}
                            onClick={() => setLanguage(l.code)}>
                        {l.label}
                    </button>
                ))}
            </div>
            {mfaChallenge ? (
            <form className="login-form" onSubmit={handleCode}>
                <div className="logo-wrapper">
                    <img className="log-logo" src="/logo2.png" alt="logo" />
                </div>
                <div className="login-mfa">
                    <h2 className="login-mfa-title">{t("Two-step sign-in")}</h2>
                    <p className="login-mfa-hint">
                        {useRecovery
                            ? t("Enter one of the recovery codes you saved when you set up two-step sign-in. Each code works once.")
                            : t("Open the authenticator app on your phone and enter the 6-digit code for NGCorion.")}
                    </p>
                    <p className="login-mfa-user"><i className="fa-solid fa-user" aria-hidden="true"></i> {mfaChallenge.username}</p>
                </div>
                <div className="input-wrapper">
                    <LockIcon />
                    <input
                        key={useRecovery ? "recovery" : "totp"}
                        type="text"
                        className="password-input login-code-input"
                        dir="ltr"
                        aria-label={useRecovery ? t("Recovery code") : t("6-digit code")}
                        placeholder={useRecovery ? "XXXX-XXXX" : "123456"}
                        inputMode={useRecovery ? "text" : "numeric"}
                        autoComplete="one-time-code"
                        maxLength={useRecovery ? 12 : 6}
                        value={code}
                        onChange={(e) => {
                            const v = asciiDigits(e.target.value);
                            setCode(useRecovery ? v.toUpperCase() : v.replace(/\D/g, ""));
                        }}
                        disabled={isLoading}
                        autoFocus
                    />
                </div>
                <button type="submit" className="log-button" disabled={isLoading || (!useRecovery && code.length !== 6)}>
                    {isLoading ? t("Checking…") : t("Verify")}
                </button>
                <button type="button" className="login-link" onClick={() => { setUseRecovery(!useRecovery); setCode(""); }}
                        disabled={isLoading}>
                    {useRecovery ? t("Use the code from the app") : t("Lost your phone? Use a recovery code")}
                </button>
                <button type="button" className="login-link" onClick={backToPassword} disabled={isLoading}>
                    {t("Back to sign-in")}
                </button>
            </form>
            ) : (
            <form className="login-form" onSubmit={handleSubmit}>

                {/* LOGO BOX */}
                <div className="logo-wrapper">
                    <img className="log-logo" src="/logo2.png" alt="logo" />
                </div>

                {/* USERNAME */}
                <div className="input-wrapper">
                    <UserIcon />
                    <input
                        type="text"
                        className="user-input"
                        placeholder={t("Enter your username")}
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        disabled={isLoading}
                    />
                </div>

                {/* PASSWORD */}
                <div className="input-wrapper">
                    <LockIcon />
                    <input
                        type="password"
                        className="password-input"
                        placeholder={t("Enter your password")}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        disabled={isLoading}
                    />
                </div>

                {/* BUTTON */}
                <button
                    type="submit"
                    className="log-button"
                    disabled={isLoading}
                >
                    {isLoading ? t("Logging in...") : t("Login")}
                </button>

                {/* FORGOT PASSWORD */}
                <button
                    type="button"
                    className="login-link"
                    onClick={() => navigate("/forgot-password")}
                    disabled={isLoading}
                >
                    {t("Forgot password?")}
                </button>

                {idleNotice && (
                    <p className="login-idle-notice" role="status">
                        {t("You were signed out after a period of inactivity.")}
                    </p>
                )}
                {banner !== null && (
                    <p className="login-banner" role="note">{banner || DEFAULT_BANNER()}</p>
                )}
            </form>
            )}

            {showErrorDialog && error && (
                <div
                    className="login-dialog-overlay"
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="login-dialog-title"
                    onClick={closeDialog}
                >
                    <div className="login-dialog" onClick={(e) => e.stopPropagation()}>
                        <h2 id="login-dialog-title" className="login-dialog-title">
                            {t("Login failed")}
                        </h2>
                        <p className="login-dialog-message">{getErrorMessage()}</p>
                        <div className="login-dialog-actions">
                            <button
                                type="button"
                                className="login-dialog-button"
                                onClick={closeDialog}
                                autoFocus
                            >
                                {t("OK")}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};
