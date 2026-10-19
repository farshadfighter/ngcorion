/**
 * Hardening landing page: Fix All (audit then harden) or Fix Unsuccessful (harden an earlier
 * audit).
 */
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { HardeningWizard } from "./HardeningWizard";
import { FixUnsuccessfulWizard } from "./FixUnsuccessfulWizard";
import { useDispatch } from "react-redux";
import { getLicenseStatusThunk } from "../../store/licenseSlice";

import "../../assets/hardening/FixAll.css";
import { t } from "../../i18n";

// ?mode=fix-all | fix-unsuccessful (the hardening overview's buttons) opens that wizard
const MODES = ["fix-all", "fix-unsuccessful"];

export const HardeningMain = ({ onNavigateToAuditing }) => {
    const [params] = useSearchParams();
    const linked = MODES.includes(params.get("mode")) ? params.get("mode") : null;
    const [showWizard, setShowWizard] = useState(Boolean(linked));
    const [wizardMode, setWizardMode] = useState(linked);
    const handleFixAllClick = () => {
        console.log("Fix All clicked");
        setWizardMode("fix-all");
        setShowWizard(true);
    };

    const handleFixUnsuccessfulClick = () => {
        console.log("Fix Unsuccessful clicked");
        setWizardMode("fix-unsuccessful");
        setShowWizard(true);
    };

    const dispatch = useDispatch();

    const handleWizardClose = () => {
        setShowWizard(false);
        setWizardMode(null);
        dispatch(getLicenseStatusThunk()); // ✅
    };


    return (
        <div className="hardening-main-container">

            {/* دو باکس انتخاب */}
            <div className="hardening-options-container">
                {/* باکس 1: Fix All Section */}
                <div className="hardening-option-box" onClick={handleFixAllClick}>
                    <div className="hardening-option-icon" >
                        <img src="/icons/haedenIcon.svg" alt="" style={{ width: "64px", height: "64px" }} />
                    </div>
                    <div className="hardening-option-title">{t("Fix all section")}</div>
                    <div className="hardening-option-description">
                        {t("Hardening all section by CIS Benchmark")}
                    </div>
                    <button className="hardening-option-button">{t("Next")}</button>
                </div>

                {/* باکس 2: Fix Unsuccessful */}
                <div className="hardening-option-box" onClick={handleFixUnsuccessfulClick}>
                    <div className="hardening-option-icon" >    <img src="/icons/haedenIcon.svg" alt="" style={{ width: "64px", height: "64px" }} /></div>
                    <div className="hardening-option-title">{t("Fix Unsuccessful section")}</div>
                    <div className="hardening-option-description">
                        {t("Hardening Unsuccessful section by Auditing")}
                    </div>
                    <button className="hardening-option-button">{t("Next")}</button>
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
        </div>
    );
};

export default HardeningMain;
