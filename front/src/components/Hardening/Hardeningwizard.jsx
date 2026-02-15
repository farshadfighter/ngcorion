import { useState } from "react";
import { HardeningConnectionForm } from "./HardeningConnectionForm";
import { HardeningProcess } from "./HardeningProcess";
import { HardeningSuccess } from "./HardeningSuccess";
import { HardeningResults } from "./HardeningResults";

export const HardeningWizard = ({ isOpen, onClose, onNavigateToAuditing }) => {
    const [currentStep, setCurrentStep] = useState(1);
    const [sessionData, setSessionData] = useState(null);
    const [hasFailed, setHasFailed] = useState(false);

    const handleFormSubmit = (data) => {
        setSessionData(data);
        setHasFailed(false);
        setCurrentStep(2); // Go to Process immediately
    };

    const handleProcessComplete = () => {
        setHasFailed(false);
        setCurrentStep(3); // Go to Success
    };

    const handleProcessError = () => {
        setHasFailed(true);
        setCurrentStep(3); // Go to Failed state
    };

    const handleSuccessNext = () => {
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

                    {/* Step 3: Result */}
                    <div className={`stepper-item ${currentStep >= 3 ? "active" : ""} ${currentStep > 3 ? "completed" : ""} ${hasFailed && currentStep >= 3 ? "failed" : ""}`}>
                        <div className="stepper-circle">
                            <div className="stepper-icon">{hasFailed ? "✕" : "3"}</div>
                        </div>
                        <div className="stepper-label">result</div>
                    </div>

                    <div className={`stepper-line ${currentStep >= 4 ? "active" : ""}`}></div>

                    {/* Step 4: Harden */}
                    <div className={`stepper-item ${currentStep >= 4 ? "active" : ""}`}>
                        <div className="stepper-circle">
                            <div className="stepper-icon">🛡</div>
                        </div>
                        <div className="stepper-label">harden</div>
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

                    {currentStep === 3 && sessionData && !hasFailed && (
                        <HardeningSuccess
                            sessionData={sessionData}
                            onNext={handleSuccessNext}
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