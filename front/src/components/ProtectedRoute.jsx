import { Navigate, useLocation } from "react-router-dom";
import { useSelector } from "react-redux";

export const ProtectedRoute = ({ children }) => {
    const { token } = useSelector((state) => state.auth);
    const location = useLocation();

    if (!token) {
        // Remember where the user was headed so login can return them there.
        return <Navigate to="/" replace state={{ from: location }} />;
    }

    return children;
};