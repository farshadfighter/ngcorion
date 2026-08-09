import { useState } from "react";
import { useDispatch } from "react-redux";
import { clearCurrentSession } from "../../store/auditSlice";
import { AuditingForm } from "./AuditingForm";
import { AuditingProcess } from "./AuditingProcess";
import { AuditingSuccess } from "./AuditingSuccess";
import { AuditingFailed } from "./AuditingFailed";
import { AuditingResultModal } from "./AuditingResultModal";

export const AuditingWizard = ({ isOpen, onClose, onComplete }) => {
    const dispatch = useDispatch();
    const [currentStep, setCurrentStep] = useState(1);
    const [sessionData, setSessionData] = useState(null);
    const [jobName, setJobName] = useState("");
    const [hasFailed, setHasFailed] = useState(false);
    const [errorMessage, setErrorMessage] = useState("");
    const [showResultModal, setShowResultModal] = useState(false);

    const handleFormSubmit = (data, name) => {
        dispatch(clearCurrentSession());
        setSessionData(data);
        setJobName(name);
        setHasFailed(false);
        setErrorMessage("");
        setCurrentStep(2);
    };

    // ✅ یک handler برای همه خطاها - از فرم یا از process
    const handleError = (message) => {
        setHasFailed(true);
        setErrorMessage(
            message ||
            "An error occurred. Please check your connection and try again."
        );
        setCurrentStep(3);
    };

    const handleProcessComplete = () => {
        setHasFailed(false);
        setErrorMessage("");
        setCurrentStep(3);
    };

    const handleSuccess = () => {
        if (sessionData && sessionData.session_id) {
            onComplete(sessionData.session_id, jobName);
        }
        onClose();
    };

    const handleSeeResult = () => {
        setShowResultModal(true);
    };

    const handleClose = () => {
        setCurrentStep(1);
        setSessionData(null);
        setJobName("");
        setHasFailed(false);
        setErrorMessage("");
        setShowResultModal(false);
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
                            onError={handleError}
                        />
                    )}

                    {currentStep === 2 && sessionData && (
                        <AuditingProcess
                            sessionData={sessionData}
                            jobName={jobName}
                            onComplete={handleProcessComplete}
                            onError={handleError}
                        />
                    )}

                    {currentStep === 3 && sessionData && !hasFailed && (
                        <AuditingSuccess
                            sessionData={sessionData}
                            jobName={jobName}
                            onBackToHome={handleSuccess}
                            onSeeResult={handleSeeResult}
                        />
                    )}

                    {currentStep === 3 && sessionData && hasFailed && (
                        <AuditingFailed
                            sessionData={sessionData}
                            jobName={jobName}
                            errorMessage={errorMessage}
                            onBackToHome={handleClose}
                        />
                    )}
                </div>
            </div>

            {/* Result Modal — closing it ends the wizard and returns to the job
                table. Without this the wizard is still mounted behind the modal
                and the success step reappears instead of the list. */}
            {showResultModal && sessionData && (
                <AuditingResultModal
                    session={sessionData}
                    isOpen={showResultModal}
                    onClose={() => {
                        setShowResultModal(false);
                        handleSuccess();
                    }}
                />
            )}
        </div>
    );
};

export default AuditingWizard;