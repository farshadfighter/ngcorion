import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate, useLocation } from "react-router-dom";
import { loginUser, clearError } from "../store/authSlice";
import UserIcon from "../assets/UserIcon.jsx";
import LockIcon from "../assets/LockIcon.jsx";
import { currentLanguage, LANGUAGES, setLanguage, t } from "../i18n";

export const Login = () => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [showErrorDialog, setShowErrorDialog] = useState(false);

    const dispatch = useDispatch();
    const navigate = useNavigate();
    const location = useLocation();
    const { isLoading, error, token } = useSelector((state) => state.auth);

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
            </form>

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
