import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import api from "../config/api";
import LockIcon from "../assets/LockIcon.jsx";
import UserIcon from "../assets/UserIcon.jsx";

// Mirror of the backend password rules, so the user gets immediate feedback.
const validatePassword = (pwd) => {
    if (pwd.length < 8) return "Password must be at least 8 characters long";
    if (!/[A-Z]/.test(pwd)) return "Password must contain at least one uppercase letter";
    if (!/[a-z]/.test(pwd)) return "Password must contain at least one lowercase letter";
    if (!/\d/.test(pwd)) return "Password must contain at least one digit";
    if (!/[!@#$%^&*()_+=\-[\]{};':"\\|,.<>/?]/.test(pwd))
        return "Password must contain at least one special character";
    return null;
};

export const ResetPassword = () => {
    const location = useLocation();
    // Email is normally carried over from the "forgot password" step; fall back
    // to an editable field if the user landed here directly.
    const [email, setEmail] = useState(location.state?.email || "");
    const [otp, setOtp] = useState("");
    const [password, setPassword] = useState("");
    const [confirm, setConfirm] = useState("");
    const [error, setError] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [done, setDone] = useState(false);

    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError("");

        if (!email.trim()) {
            setError("Please enter your email.");
            return;
        }
        if (!/^\d{6}$/.test(otp)) {
            setError("Enter the 6-digit code from your email.");
            return;
        }
        const pwdError = validatePassword(password);
        if (pwdError) {
            setError(pwdError);
            return;
        }
        if (password !== confirm) {
            setError("Passwords do not match.");
            return;
        }

        setIsLoading(true);
        try {
            await api.post("/auth/reset-password", {
                email,
                otp,
                new_password: password,
            });
            setDone(true);
            setTimeout(() => navigate("/"), 2500);
        } catch (err) {
            const detail = err.response?.data?.detail;
            setError(
                typeof detail === "string"
                    ? detail
                    : "Could not reset your password. The code may be invalid or expired."
            );
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="login-page">
            <form className="login-form" onSubmit={handleSubmit}>
                <div className="logo-wrapper">
                    <img className="log-logo" src="/logo2.png" alt="logo" />
                </div>

                <h1 className="login-heading">Reset password</h1>

                {done ? (
                    <>
                        <p className="login-message">
                            Your password has been reset. Redirecting to login...
                        </p>
                        <button
                            type="button"
                            className="login-link"
                            onClick={() => navigate("/")}
                        >
                            Go to login
                        </button>
                    </>
                ) : (
                    <>
                        <p className="login-subtext">
                            Enter the code we emailed you, then choose a new password.
                        </p>

                        <div className="input-wrapper">
                            <UserIcon />
                            <input
                                type="email"
                                className="user-input"
                                placeholder="Email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                disabled={isLoading}
                            />
                        </div>

                        <div className="input-wrapper">
                            <LockIcon />
                            <input
                                type="text"
                                inputMode="numeric"
                                maxLength={6}
                                className="user-input"
                                placeholder="6-digit code"
                                value={otp}
                                onChange={(e) =>
                                    setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))
                                }
                                disabled={isLoading}
                            />
                        </div>

                        <div className="input-wrapper">
                            <LockIcon />
                            <input
                                type="password"
                                className="password-input"
                                placeholder="New password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                disabled={isLoading}
                            />
                        </div>

                        <div className="input-wrapper">
                            <LockIcon />
                            <input
                                type="password"
                                className="password-input"
                                placeholder="Confirm new password"
                                value={confirm}
                                onChange={(e) => setConfirm(e.target.value)}
                                disabled={isLoading}
                            />
                        </div>

                        {error && <p className="login-field-error">{error}</p>}

                        <button type="submit" className="log-button" disabled={isLoading}>
                            {isLoading ? "Resetting..." : "Reset password"}
                        </button>

                        <button
                            type="button"
                            className="login-link"
                            onClick={() => navigate("/")}
                        >
                            Back to login
                        </button>
                    </>
                )}
            </form>
        </div>
    );
};
