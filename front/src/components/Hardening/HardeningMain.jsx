import { useState } from "react";
import { HardeningWizard } from "./HardeningWizard";
import { FixUnsuccessfulWizard } from "./FixUnsuccessfulWizard";
import { LicenseLimitModal } from "../License/LicenseLimitModal";
import { useDispatch } from "react-redux";
import { getLicenseStatusThunk } from "../../store/licenseSlice";

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

    const dispatch = useDispatch();

    const handleWizardClose = () => {
        setShowWizard(false);
        setWizardMode(null);
        dispatch(getLicenseStatusThunk()); // ✅
    };

    const handleLicenseLimitReached = () => {
        setShowLicenseModal(true);
    };

    const handleLicenseModalClose = () => {
        setShowLicenseModal(false);
    };

    return (
        <div className="hardening-main-container">

            {/* دو باکس انتخاب */}
            <div className="hardening-options-container">
                {/* باکس 1: Fix All Section */}
                <div className="hardening-option-box" onClick={handleFixAllClick}>
                    <div className="hardening-option-icon" >
                        <img src="/icons/haedenIcon.svg" alt="" style={{ width: "160px", height: "160px" }} />
                    </div>
                    <div className="hardening-option-title">Fix all section</div>
                    <div className="hardening-option-description">
                        Hardening all section by CIS Benchmark
                    </div>
                    <button className="hardening-option-button">Next</button>
                </div>

                {/* باکس 2: Fix Unsuccessful */}
                <div className="hardening-option-box" onClick={handleFixUnsuccessfulClick}>
                    <div className="hardening-option-icon" >    <img src="/icons/haedenIcon.svg" alt="" style={{ width: "160px", height: "160px" }} /></div>
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
