import { useEffect, useState } from "react";

export const QuotaExhaustedModal = () => {
    const [isOpen, setIsOpen] = useState(false);
    const [message, setMessage] = useState("");

    useEffect(() => {
        const handleQuotaExhausted = (event) => {
            setMessage(event.detail.message);
            setIsOpen(true);
        };

        window.addEventListener("quota-exhausted", handleQuotaExhausted);

        return () => {
            window.removeEventListener("quota-exhausted", handleQuotaExhausted);
        };
    }, []);

    if (!isOpen) return null;

    return (
        <div
            style={{
                position: "fixed",
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                backgroundColor: "rgba(0, 0, 0, 0.5)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                zIndex: 9999,
                padding: "20px",
            }}
            onClick={() => setIsOpen(false)}
        >
            <div
                style={{
                    backgroundColor: "#ffffff",
                    borderRadius: "12px",
                    padding: "32px",
                    maxWidth: "480px",
                    width: "100%",
                    boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)",
                }}
                onClick={(e) => e.stopPropagation()}
            >
                {/* Icon */}
                <div
                    style={{
                        width: "56px",
                        height: "56px",
                        borderRadius: "50%",
                        backgroundColor: "#FEF2F2",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        margin: "0 auto 20px",
                    }}
                >
                    <svg
                        width="28"
                        height="28"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="#DC2626"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                    >
                        <circle cx="12" cy="12" r="10" />
                        <line x1="12" y1="8" x2="12" y2="12" />
                        <line x1="12" y1="16" x2="12.01" y2="16" />
                    </svg>
                </div>

                {/* Title */}
                <h2
                    style={{
                        fontSize: "20px",
                        fontWeight: "600",
                        color: "#111827",
                        textAlign: "center",
                        marginBottom: "12px",
                    }}
                >
                    Quota Limit Reached
                </h2>

                {/* Message */}
                <p
                    style={{
                        fontSize: "14px",
                        color: "#6B7280",
                        textAlign: "center",
                        lineHeight: "1.6",
                        marginBottom: "24px",
                    }}
                >
                    {message}
                </p>

                {/* Actions */}
                <div style={{ display: "flex", gap: "12px" }}>
                    <button
                        onClick={() => setIsOpen(false)}
                        style={{
                            flex: 1,
                            padding: "12px 24px",
                            borderRadius: "8px",
                            border: "1px solid #E5E7EB",
                            backgroundColor: "#ffffff",
                            color: "#374151",
                            fontSize: "14px",
                            fontWeight: "600",
                            cursor: "pointer",
                            transition: "background-color 0.2s",
                        }}
                        onMouseEnter={(e) => {
                            e.target.style.backgroundColor = "#F9FAFB";
                        }}
                        onMouseLeave={(e) => {
                            e.target.style.backgroundColor = "#ffffff";
                        }}
                    >
                        Close
                    </button>
                    <button
                        onClick={() => {
                            setIsOpen(false);
                            // TODO: Navigate to upgrade page or contact admin
                            alert("Please contact your administrator to upgrade your plan.");
                        }}
                        style={{
                            flex: 1,
                            padding: "12px 24px",
                            borderRadius: "8px",
                            border: "none",
                            backgroundColor: "#111827",
                            color: "#ffffff",
                            fontSize: "14px",
                            fontWeight: "600",
                            cursor: "pointer",
                            transition: "background-color 0.2s",
                        }}
                        onMouseEnter={(e) => {
                            e.target.style.backgroundColor = "#1F2937";
                        }}
                        onMouseLeave={(e) => {
                            e.target.style.backgroundColor = "#111827";
                        }}
                    >
                        Upgrade Plan
                    </button>
                </div>
            </div>
        </div>
    );
};
