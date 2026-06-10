import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../config/api";
import UserIcon from "../assets/UserIcon.jsx";

export const ForgotPassword = () => {
    const [email, setEmail] = useState("");
    const [isLoading, setIsLoading] = useState(false);

    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!email.trim()) return;
        setIsLoading(true);
        try {
            await api.post("/auth/forgot-password", { email });
        } catch {
            // The endpoint returns a generic success; even on error (e.g. rate
            // limit) we proceed identically so account existence isn't revealed.
        } finally {
            // Go to the reset page carrying the email so the user can enter the
            // code we (may have) emailed. We navigate regardless of whether the
            // account exists, to avoid leaking that.
            navigate("/reset-password", { state: { email } });
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
