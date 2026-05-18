import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { loginUser } from "../store/authSlice";
import UserIcon from "../assets/UserIcon.jsx";
import LockIcon from "../assets/LockIcon.jsx";

export const Login = () => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");

    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { isLoading, error, token } = useSelector((state) => state.auth);

    useEffect(() => {
        if (token) {
            navigate("/dashboard");
        }
    }, [token, navigate]);

    const handleSubmit = (e) => {
        e.preventDefault();
        if (username.trim() && password.trim()) {
            dispatch(loginUser({ username, password }));
            console.log("Login result:", result);

        }
    };

    const getErrorMessage = () => {
        if (!error) return null;
        if (typeof error === "string") return error;
        if (typeof error === "object" && error.detail) return error.detail;
        return "Invalid username or password";
    };

    return (
        <div className="login-page">
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
                        placeholder="Enter your username"
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
                        placeholder="Enter your password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        disabled={isLoading}
                    />
                </div>

                {/* ERROR */}
                {error && (
                    <div className="login-error">
                        {getErrorMessage()}
                    </div>
                )}

                {/* BUTTON */}
                <button
                    type="submit"
                    className="log-button"
                    disabled={isLoading}
                >
                    {isLoading ? "Logging in..." : "Login"}
                </button>
            </form>
        </div>
    );
};