import { useState } from "react";
import { AuditingForm } from "./AuditingForm";
import { AuditingProcess } from "./AuditingProcess";
import { AuditingSuccess } from "./AuditingSuccess";
import { AuditingFailed } from "./AuditingFailed";
import { AuditingResultModal } from "./AuditingResultModal";

export const AuditingWizard = ({ isOpen, onClose, onComplete }) => {
    const [currentStep, setCurrentStep] = useState(1);
    const [sessionData, setSessionData] = useState(null);
    const [jobName, setJobName] = useState("");
    const [hasFailed, setHasFailed] = useState(false);
    const [showResultModal, setShowResultModal] = useState(false); // ✅ NEW

    const handleFormSubmit = (data, name) => {
        setSessionData(data);
        setJobName(name);
        setHasFailed(false); // Reset failed state
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

    const handleSuccess = () => {
        if (sessionData && sessionData.session_id) {
            onComplete(sessionData.session_id, jobName);
        }
        onClose();
    };

    // ✅ NEW: Handler for See Result button
    const handleSeeResult = () => {
        console.log("🔍 Opening result modal for session:", sessionData);
        setShowResultModal(true);
    };

    const handleClose = () => {
        setCurrentStep(1);
        setSessionData(null);
        setJobName("");
        setHasFailed(false);
        setShowResultModal(false); // ✅ Reset modal state
        onClose();
    };

    if (!isOpen) return null;

    return (
        <div className="modal-overlay wizard-overlay">
            <div className="wizard-modal">
                {/* Stepper */}
                <div className="wizard-stepper">
                    <div className={`stepper-item ${currentStep >= 1 ? "active" : ""} ${currentStep > 1 ? "completed" : ""}`}>
                        <div className="stepper-circle">
                            <div className="stepper-icon">1</div>
                        </div>
                        <div className="stepper-label">information</div>
                        <div className="stepper-number">1</div>
                    </div>

                    <div className={`stepper-line ${currentStep >= 2 ? "active" : ""} ${hasFailed && currentStep === 3 ? "failed" : ""}`}></div>

                    <div className={`stepper-item ${currentStep >= 2 ? "active" : ""} ${currentStep > 2 ? "completed" : ""} ${hasFailed && currentStep === 3 ? "failed" : ""}`}>
                        <div className="stepper-circle">
                            <div className="stepper-icon">2</div>
                        </div>
                        <div className="stepper-label">process</div>
                        <div className="stepper-number">2</div>
                    </div>

                    <div className={`stepper-line ${currentStep >= 3 ? "active" : ""} ${hasFailed && currentStep === 3 ? "failed" : ""}`}></div>

                    <div className={`stepper-item ${currentStep >= 3 ? "active" : ""} ${hasFailed && currentStep === 3 ? "failed" : ""}`}>
                        <div className="stepper-circle">
                            <div className="stepper-icon">{hasFailed && currentStep === 3 ? "✕" : "✓"}</div>
                        </div>
                        <div className="stepper-label">result</div>
                        <div className="stepper-number">3</div>
                    </div>
                </div>

                {/* Step Content */}
                <div className="wizard-content">
                    {currentStep === 1 && (
                        <AuditingForm
                            onSubmit={handleFormSubmit}
                            onCancel={handleClose}
                        />
                    )}

                    {currentStep === 2 && sessionData && (
                        <AuditingProcess
                            sessionData={sessionData}
                            jobName={jobName}
                            onComplete={handleProcessComplete}
                            onError={handleProcessError}
                        />
                    )}

                    {currentStep === 3 && sessionData && !hasFailed && (
                        <AuditingSuccess
                            sessionData={sessionData}
                            jobName={jobName}
                            onBackToHome={handleSuccess}
                            onSeeResult={handleSeeResult}  // ✅ FIXED!
                        />
                    )}

                    {currentStep === 3 && sessionData && hasFailed && (
                        <AuditingFailed
                            sessionData={sessionData}
                            jobName={jobName}
                            errorMessage="Audit process failed"
                            onBackToHome={handleClose}
                        />
                    )}
                </div>
            </div>

            {/* ✅ Result Modal - Opens when See Result is clicked */}
            {showResultModal && sessionData && (
                <AuditingResultModal
                    session={sessionData}
                    isOpen={showResultModal}
                    onClose={() => {
                        setShowResultModal(false);
                        // Stay in wizard after closing modal
                    }}
                />
            )}
        </div>
    );
};

export default AuditingWizard;