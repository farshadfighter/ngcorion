<<<<<<< HEAD
import { useState, useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { loginUser, clearError } from "../store/authSlice";
import UserIcon from "../assets/UserIcon.jsx";
import LockIcon from "../assets/LockIcon.jsx";

export const Login = () => {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [showErrorDialog, setShowErrorDialog] = useState(false);

    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { isLoading, error, token } = useSelector((state) => state.auth);

    useEffect(() => {
        if (token) {
            navigate("/dashboard");
        }
    }, [token, navigate]);

    useEffect(() => {
        if (error) setShowErrorDialog(true);
    }, [error]);

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
        return "Invalid username or password";
    };

    const closeDialog = () => {
        setShowErrorDialog(false);
        dispatch(clearError());
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

                {/* BUTTON */}
                <button
                    type="submit"
                    className="log-button"
                    disabled={isLoading}
                >
                    {isLoading ? "Logging in..." : "Login"}
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
                            Login failed
                        </h2>
                        <p className="login-dialog-message">{getErrorMessage()}</p>
                        <div className="login-dialog-actions">
                            <button
                                type="button"
                                className="login-dialog-button"
                                onClick={closeDialog}
                                autoFocus
                            >
                                OK
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};
=======
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
>>>>>>> cc77a55 (login fix)
