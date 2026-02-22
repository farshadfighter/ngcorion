import { useState } from "react";
import { HardeningWizard } from "./HardeningWizard";
import { FixUnsuccessfulWizard } from "./FixUnsuccessfulWizard";
import "../../assets/hardening/FixAll.css";

export const HardeningMain = ({ onNavigateToAuditing }) => {
    const [showWizard, setShowWizard] = useState(false);
    const [wizardMode, setWizardMode] = useState(null);

    const handleFixAllClick = () => {
        console.log("🛡️ Fix All clicked"); // Debug
        setWizardMode("fix-all");
        setShowWizard(true);
    };

    const handleFixUnsuccessfulClick = () => {
        console.log("🔧 Fix Unsuccessful clicked"); // Debug
        setWizardMode("fix-unsuccessful");
        setShowWizard(true);
    };

    const handleWizardClose = () => {
        console.log("❌ Wizard closed"); // Debug
        setShowWizard(false);
        setWizardMode(null);
    };

    return (
        <div className="hardening-main-container">
            {/* دو باکس انتخاب */}
            <div className="hardening-options-container">
                {/* باکس 1: Fix All Section */}
                <div className="hardening-option-box" onClick={handleFixAllClick}>
                    <div className="hardening-option-icon"><img src="/icons/audit.svg" alt="" className="btn-icon" /></div>
                    <div className="hardening-option-title">Fix all section</div>
                    <div className="hardening-option-description">
                        Hardening all section by CIS Benchmark
                    </div>
                    <button className="hardening-option-button">Next</button>
                </div>

                {/* باکس 2: Fix Unsuccessful - فعال شد! */}
                <div className="hardening-option-box" onClick={handleFixUnsuccessfulClick}>
                    <div className="hardening-option-icon"><img src="/icons/audit.svg" alt="" className="btn-icon" /></div>
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
                />
            )}
        </div>
    );
};

export default HardeningMain;