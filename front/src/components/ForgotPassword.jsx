import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../config/api";
import UserIcon from "../assets/UserIcon.jsx";

export const ForgotPassword = () => {
    const [email, setEmail] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState("");

    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!email.trim()) return;
        setError("");
        setIsLoading(true);
        try {
            await api.post("/auth/forgot-password", { email });
            // Code sent — go to the reset page carrying the email.
            navigate("/reset-password", { state: { email } });
        } catch (err) {
            const detail = err.response?.data?.detail;
            setError(
                typeof detail === "string"
                    ? detail
                    : "Could not send a reset code. Please try again."
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

                <h1 className="login-heading">Forgot password</h1>

                <p className="login-subtext">
                    Enter your email and we'll send you a code to reset your password.
                </p>

                <div className="input-wrapper">
                    <UserIcon />
                    <input
                        type="email"
                        className="user-input"
                        placeholder="Enter your email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        disabled={isLoading}
                    />
                </div>

                {error && <p className="login-field-error">{error}</p>}

                <button type="submit" className="log-button" disabled={isLoading}>
                    {isLoading ? "Sending..." : "Send code"}
                </button>

                <button
                    type="button"
                    className="login-link"
                    onClick={() => navigate("/")}
                >
                    Back to login
                </button>
            </form>
        </div>
    );
};
