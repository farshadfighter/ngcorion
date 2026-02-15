import { useState } from "react";
import { FixUnsuccessfulConnectionForm } from "./FixUnsuccessfulConnectionForm";
import { FixUnsuccessfulProcess } from "./FixUnsuccessfulProcess";
import { FixUnsuccessfulSuccess } from "./FixUnsuccessfulSuccess";
import { FixUnsuccessfulResults } from "./FixUnsuccessfulResults";

export const FixUnsuccessfulWizard = ({ isOpen, onClose }) => {
    const [currentStep, setCurrentStep] = useState(1);
    const [sessionData, setSessionData] = useState(null);
    const [hasFailed, setHasFailed] = useState(false);

    const handleFormSubmit = (data) => {
        console.log("📥 FixUnsuccessful Form Data:", data); // Debug
        setSessionData(data.session); // ذخیره session
        setHasFailed(false);
        setCurrentStep(2); // Go to Process immediately
    };

    const handleProcessComplete = () => {
        console.log("✅ Process completed"); // Debug
        setHasFailed(false);
        setCurrentStep(3); // Go to Success
    };

    const handleProcessError = () => {
        console.log("❌ Process failed"); // Debug
        setHasFailed(true);
        setCurrentStep(3); // Go to Failed state
    };

    const handleSuccessNext = () => {
        console.log("➡️ Going to Results"); // Debug
        setCurrentStep(4); // Go to Results
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
                    <div className={`stepper-item ${currentStep >= 2 ? "active" : ""} ${currentStep > 2 ? "completed" : ""} ${hasFailed && currentStep >= 3 ? "failed" : ""}`}>
                        <div className="stepper-circle">
                            <div className="stepper-icon">2</div>
                        </div>
                        <div className="stepper-label">process</div>
                    </div>

                    <div className={`stepper-line ${currentStep >= 3 ? "active" : ""} ${hasFailed && currentStep >= 3 ? "failed" : ""}`}></div>

                    {/* Step 3: Result/Harden */}
                    <div className={`stepper-item ${currentStep >= 3 ? "active" : ""} ${hasFailed && currentStep >= 3 ? "failed" : ""}`}>
                        <div className="stepper-circle">
                            <div className="stepper-icon">{hasFailed ? "✕" : (currentStep >= 4 ? "🛡️" : "✓")}</div>
                        </div>
                        <div className="stepper-label">harden</div>
                    </div>
                </div>

                {/* Step Content */}
                <div className="wizard-content">
                    {currentStep === 1 && (
                        <FixUnsuccessfulConnectionForm
                            onSubmit={handleFormSubmit}
                            onCancel={handleClose}
                        />
                    )}

                    {currentStep === 2 && sessionData && (
                        <FixUnsuccessfulProcess
                            sessionData={sessionData}
                            onComplete={handleProcessComplete}
                            onError={handleProcessError}
                        />
                    )}

                    {currentStep === 3 && sessionData && !hasFailed && (
                        <FixUnsuccessfulSuccess
                            sessionData={sessionData}
                            onNext={handleSuccessNext}
                        />
                    )}

                    {currentStep === 4 && sessionData && (
                        <FixUnsuccessfulResults
                            sessionData={sessionData}
                            onClose={handleClose}
                        />
                    )}
                </div>
            </div>
        </div>
    );
};

export default FixUnsuccessfulWizard;