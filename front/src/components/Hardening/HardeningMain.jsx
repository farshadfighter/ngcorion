import { useState } from "react";
import { HardeningWizard } from "./HardeningWizard";
import { FixUnsuccessfulWizard } from "./FixUnsuccessfulWizard";
import { LicenseBadge } from "../License/LicenseBadge";
import { LicenseLimitModal } from "../License/LicenseLimitModal";
import "../../assets/hardening/FixAll.css";

export const HardeningMain = ({ onNavigateToAuditing, onNavigateToLicence }) => {
    const [showWizard, setShowWizard] = useState(false);
    const [wizardMode, setWizardMode] = useState(null);
    const [showLicenseModal, setShowLicenseModal] = useState(false);

    const handleFixAllClick = () => {
        console.log("🛡️ Fix All clicked");
        setWizardMode("fix-all");
        setShowWizard(true);
    };

    const handleFixUnsuccessfulClick = () => {
        console.log("🔧 Fix Unsuccessful clicked");
        setWizardMode("fix-unsuccessful");
        setShowWizard(true);
    };

    const handleWizardClose = () => {
        console.log("❌ Wizard closed");
        setShowWizard(false);
        setWizardMode(null);
    };

    const handleLicenseLimitReached = () => {
        setShowLicenseModal(true);
    };

    const handleLicenseModalClose = () => {
        setShowLicenseModal(false);
    };

    return (
        <div className="hardening-main-container">
            {/* License Badge */}
            <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "16px" }}>
                <LicenseBadge
                    module="hardening"
                    onLimitReached={handleLicenseLimitReached}
                />
            </div>
            {/* دو باکس انتخاب */}
            <div className="hardening-options-container">
                {/* باکس 1: Fix All Section */}
                <div className="hardening-option-box" onClick={handleFixAllClick}>
                    <div >
                        <img src="/" alt="" style={{ width: "160px", height: "160px" }} />
                    </div>
                    <div className="hardening-option-title">Fix all section</div>
                    <div className="hardening-option-description">
                        Hardening all section by CIS Benchmark
                    </div>
                    <button className="hardening-option-button">Next</button>
                </div>

                {/* باکس 2: Fix Unsuccessful */}
                <div className="hardening-option-box" onClick={handleFixUnsuccessfulClick}>
                    <div className="hardening-option-icon"><img src="/icons/audit.svg" alt="icon" /></div>
                    <div className="hardening-option-title">Fix Unsuccessful section</div>
                    <div className="hardening-option-description">
                        Hardening Unsuccessful section by Auditing
                    </div>
                    <button className="hardening-option-button">Next</button>
                </div>
            </div>

            {/* Wizard Modals */}
            {showWizard && wizardMode === "fix-all" && (
                <HardeningWizard
                    isOpen={showWizard}
                    mode={wizardMode}
                    onClose={handleWizardClose}
                    onNavigateToAuditing={onNavigateToAuditing}
                />
            )}

            {showWizard && wizardMode === "fix-unsuccessful" && (
                <FixUnsuccessfulWizard
                    isOpen={showWizard}
                    onClose={handleWizardClose}
                    onNavigateToAuditing={onNavigateToAuditing}
                />
            )}

            {/* License Limit Modal */}
            <LicenseLimitModal
                isOpen={showLicenseModal}
                onClose={handleLicenseModalClose}
                module="hardening"
                onGoToLicence={onNavigateToLicence}
            />
        </div>
    );
};

export default HardeningMain;
