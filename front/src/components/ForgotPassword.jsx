import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../config/api";
import UserIcon from "../assets/UserIcon.jsx";

export const ForgotPassword = () => {
    const [email, setEmail] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [submitted, setSubmitted] = useState(false);
    const [message, setMessage] = useState("");

    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!email.trim()) return;
        setIsLoading(true);
        try {
            const res = await api.post("/auth/forgot-password", { email });
            setMessage(
                res.data?.message ||
                "If an account with that email exists, a password reset link has been sent."
            );
        } catch {
            // The endpoint returns a generic success; on the rare error (e.g. rate
            // limit) we still avoid revealing account existence.
            setMessage(
                "If an account with that email exists, a password reset link has been sent."
            );
        } finally {
            setSubmitted(true);
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

                {submitted ? (
                    <p className="login-message">{message}</p>
                ) : (
                    <>
                        <p className="login-subtext">
                            Enter your email and we'll send you a link to reset your password.
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

                        <button type="submit" className="log-button" disabled={isLoading}>
                            {isLoading ? "Sending..." : "Send reset link"}
                        </button>
                    </>
                )}

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
