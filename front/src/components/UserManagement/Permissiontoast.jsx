import { useEffect, useState } from "react";

/**
 * PermissionToast
 *
 * گوش میده به event "permission-denied" که از api.js میاد
 * و یه toast نشون میده که بعد 4 ثانیه محو میشه.
 *
 * استفاده: فقط یه بار توی App.jsx اضافه کن:
 *   <PermissionToast />
 */
export const PermissionToast = () => {
    const [toast, setToast] = useState(null); // { message: string }
    const [visible, setVisible] = useState(false);

    useEffect(() => {
        const handlePermissionDenied = (e) => {
            const message = e.detail?.message || "You do not have permission to perform this action.";

            setToast({ message });
            setVisible(true);

            // بعد از 4 ثانیه محو میشه
            setTimeout(() => {
                setVisible(false);
                setTimeout(() => setToast(null), 300); // بعد از fade-out پاک میشه
            }, 4000);
        };

        window.addEventListener("permission-denied", handlePermissionDenied);
        return () => window.removeEventListener("permission-denied", handlePermissionDenied);
    }, []);

    if (!toast) return null;

    return (
        <>
            <style>{`
                @keyframes slideIn {
                    from { transform: translateX(110%); opacity: 0; }
                    to   { transform: translateX(0);    opacity: 1; }
                }
                @keyframes fadeOut {
                    from { opacity: 1; }
                    to   { opacity: 0; }
                }
                .permission-toast {
                    position: fixed;
                    bottom: 24px;
                    right: 24px;
                    z-index: 9999;
                    display: flex;
                    align-items: flex-start;
                    gap: 12px;
                    background: #1F2937;
                    color: #F9FAFB;
                    padding: 14px 18px;
                    border-radius: 10px;
                    box-shadow: 0 8px 24px rgba(0,0,0,0.25);
                    max-width: 360px;
                    animation: slideIn 0.3s ease forwards;
                    border-left: 4px solid #EF4444;
                }
                .permission-toast.hide {
                    animation: fadeOut 0.3s ease forwards;
                }
                .permission-toast-icon {
                    font-size: 20px;
                    flex-shrink: 0;
                    margin-top: 1px;
                }
                .permission-toast-body {
                    display: flex;
                    flex-direction: column;
                    gap: 3px;
                }
                .permission-toast-title {
                    font-size: 14px;
                    font-weight: 600;
                    color: #F9FAFB;
                }
                .permission-toast-message {
                    font-size: 13px;
                    color: #9CA3AF;
                    line-height: 1.4;
                }
                .permission-toast-close {
                    margin-left: auto;
                    background: none;
                    border: none;
                    color: #6B7280;
                    cursor: pointer;
                    font-size: 16px;
                    padding: 0;
                    flex-shrink: 0;
                    line-height: 1;
                }
                .permission-toast-close:hover {
                    color: #F9FAFB;
                }
            `}</style>

            <div className={`permission-toast ${!visible ? "hide" : ""}`}>
                <span className="permission-toast-icon">🔒</span>
                <div className="permission-toast-body">
                    <div className="permission-toast-title">Access Denied</div>
                    <div className="permission-toast-message">{toast.message}</div>
                </div>
                <button
                    className="permission-toast-close"
                    onClick={() => {
                        setVisible(false);
                        setTimeout(() => setToast(null), 300);
                    }}
                >
                    ✕
                </button>
            </div>
        </>
    );
};