import { Navigate } from "react-router-dom";
import { useSelector } from "react-redux";

export const ProtectedRoute = ({ children }) => {
    const { token } = useSelector((state) => state.auth);

    if (!token) {
        return <Navigate to="/" replace />;
    }

    return children;
};