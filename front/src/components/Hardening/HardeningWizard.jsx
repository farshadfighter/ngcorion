import { useState } from "react";
import { useDispatch } from "react-redux";
import { clearCurrentSession } from "../../store/hardeningSlice";
import { HardeningConnectionForm } from "./HardeningConnectionForm";
import { HardeningProcess } from "./HardeningProcess";
import { HardeningSuccess } from "./HardeningSuccess";
import { HardeningResults } from "./HardeningResults";

// ==========================================
// کامپوننت صفحه Fail
// ==========================================

const HardeningFailed = ({ sessionData, onRetry, onClose }) => (
    <div style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "48px 32px",
        gap: "20px",
        background: "linear-gradient(135deg, #FEF2F2 0%, #FFF5F5 100%)",
        borderRadius: "16px",
        minHeight: "320px",
    }}>
        {/* آیکون ضربدر قرمز */}
        <div style={{
            width: "72px",
            height: "72px",
            borderRadius: "50%",
            background: "#EF4444",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: "36px",
            color: "white",
            boxShadow: "0 8px 24px rgba(239,68,68,0.35)",
        }}>
            ✕
        </div>

        <div style={{ textAlign: "center", gap: "8px", display: "flex", flexDirection: "column" }}>
            <h2 style={{
                fontSize: "22px",
                fontWeight: "700",
                color: "#991B1B",
                margin: 0,
            }}>
                Connection Failed
            </h2>
            <p style={{
                fontSize: "14px",
                color: "#B91C1C",
                margin: 0,
                lineHeight: "1.6",
            }}>
                Could not connect to <strong>{sessionData?.asset_name || "the device"}</strong>
                {sessionData?.target_ip ? ` (${sessionData.target_ip})` : ""}.
                <br />
                Please check your credentials and try again.
            </p>
        </div>

        {/* دکمه‌ها */}
        <div style={{ display: "flex", gap: "12px", marginTop: "8px" }}>
            <button
                onClick={onRetry}
                style={{
                    padding: "10px 28px",
                    background: "#EF4444",
                    color: "white",
                    border: "none",
                    borderRadius: "8px",
                    fontSize: "14px",
                    fontWeight: "600",
                    cursor: "pointer",
                    transition: "all 0.2s",
                }}
                onMouseOver={(e) => e.target.style.background = "#DC2626"}
                onMouseOut={(e) => e.target.style.background = "#EF4444"}
            >
                Try Again
            </button>
            <button
                onClick={onClose}
                style={{
                    padding: "10px 28px",
                    background: "white",
                    color: "#374151",
                    border: "1px solid #D1D5DB",
                    borderRadius: "8px",
                    fontSize: "14px",
                    fontWeight: "600",
                    cursor: "pointer",
                    transition: "all 0.2s",
                }}
                onMouseOver={(e) => e.target.style.background = "#F9FAFB"}
                onMouseOut={(e) => e.target.style.background = "white"}
            >
                Close
            </button>
        </div>
    </div>
);

// ==========================================
// Wizard اصلی
// ==========================================

export const HardeningWizard = ({ isOpen, onClose, onNavigateToAuditing }) => {
    const dispatch = useDispatch();
    const [currentStep, setCurrentStep] = useState(1);
    const [sessionData, setSessionData] = useState(null);
    const [hasFailed, setHasFailed] = useState(false);

    const handleFormSubmit = (data) => {
        dispatch(clearCurrentSession());
        setSessionData(data);
        setHasFailed(false);
        setCurrentStep(2);
    };

    const handleProcessComplete = () => {
        setHasFailed(false);
        setCurrentStep(3);
    };

    const handleProcessError = () => {
        setHasFailed(true);
        setCurrentStep(3);
    };

    // برگشت به step 1 برای تلاش مجدد
    const handleRetry = () => {
        dispatch(clearCurrentSession());
        setHasFailed(false);
        setSessionData(null);
        setCurrentStep(1);
    };

    const handleSuccessNext = () => {
        setCurrentStep(4);
    };

    const handleClose = () => {
        setCurrentStep(1);
        setSessionData(null);
        setHasFailed(false);
        onClose();
    };

    if (!isOpen) return null;

    return (
        <div className="modal-overlay wizard-overlay">
            <div className="wizard-modal">
                {/* Stepper */}
                <div className="wizard-stepper">
                    {/* Step 1: Connection */}
                    <div className={`stepper-item ${currentStep >= 1 ? "active" : ""} ${currentStep > 1 ? "completed" : ""}`}>
                        <div className="stepper-circle">
                            <div className="stepper-icon">1</div>
                        </div>
                        <div className="stepper-label">Connection</div>
                    </div>

                    <div className={`stepper-line ${currentStep >= 2 ? "active" : ""} ${hasFailed && currentStep >= 3 ? "failed" : ""}`}></div>

                    {/* Step 2: Process */}
                    <div className={`stepper-item ${currentStep >= 2 ? "active" : ""} ${currentStep > 2 && !hasFailed ? "completed" : ""} ${hasFailed && currentStep >= 3 ? "failed" : ""}`}>
                        <div className="stepper-circle">
                            <div className="stepper-icon">2</div>
                        </div>
                        <div className="stepper-label">Process</div>
                    </div>

                    <div className={`stepper-line ${currentStep >= 3 ? "active" : ""} ${hasFailed && currentStep >= 3 ? "failed" : ""}`}></div>

                    {/* Step 3: Result */}
                    <div className={`stepper-item ${currentStep >= 3 ? "active" : ""} ${currentStep > 3 ? "completed" : ""} ${hasFailed && currentStep >= 3 ? "failed" : ""}`}>
                        <div className="stepper-circle">
                            <div className="stepper-icon">{hasFailed ? "✕" : "3"}</div>
                        </div>
                        <div className="stepper-label">Result</div>
                    </div>

                    <div className={`stepper-line ${currentStep >= 4 ? "active" : ""}`}></div>

                    {/* Step 4: Harden */}
                    <div className={`stepper-item ${currentStep >= 4 ? "active" : ""}`}>
                        <div className="stepper-circle">
                            <div className="stepper-icon">🛡</div>
                        </div>
                        <div className="stepper-label">Harden</div>
                    </div>
                </div>

                {/* Step Content */}
                <div className="wizard-content">
                    {currentStep === 1 && (
                        <HardeningConnectionForm
                            onSubmit={handleFormSubmit}
                            onCancel={handleClose}
                        />
                    )}

                    {currentStep === 2 && sessionData && (
                        <HardeningProcess
                            sessionData={sessionData}
                            onComplete={handleProcessComplete}
                            onError={handleProcessError}
                        />
                    )}

                    {/* ✅ Success */}
                    {currentStep === 3 && sessionData && !hasFailed && (
                        <HardeningSuccess
                            sessionData={sessionData}
                            onNext={handleSuccessNext}
                        />
                    )}

                    {/* ✅ Failed — قبلاً اینجا هیچی نبود */}
                    {currentStep === 3 && hasFailed && (
                        <HardeningFailed
                            sessionData={sessionData}
                            onRetry={handleRetry}
                            onClose={handleClose}
                        />
                    )}

                    {currentStep === 4 && sessionData && (
                        <HardeningResults
                            sessionData={sessionData}
                            onClose={handleClose}
                            onNavigateToAuditing={onNavigateToAuditing}
                        />
                    )}
                </div>
            </div>
        </div>
    );
};