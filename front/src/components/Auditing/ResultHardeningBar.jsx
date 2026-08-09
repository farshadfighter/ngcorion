/**
 * "Go to Hardening to fix Unsuccessful Section" bar, sitting between the
 * summary cards and the results table (Figma: 1229x180 card, rx 30, with a
 * 338x67 #14213D button).
 *
 * Opens FixUnsuccessfulWizard, which was already wired into the result modal
 * with preselectedSessionId but had nothing to trigger it.
 */
export const ResultHardeningBar = ({ onHarden, disabled }) => (
    <div className="result-harden-bar">
        <div className="result-harden-title">
            <i className="fa-solid fa-circle-exclamation" aria-hidden="true"></i>
            <span>Go to Hardening to fix Unsuccessful Section</span>
        </div>
        <button
            type="button"
            className="result-harden-btn"
            onClick={onHarden}
            disabled={disabled}
            title={
                disabled
                    ? "No unsuccessful checks to fix"
                    : "Harden the failed checks from this audit"
            }
        >
            <i className="fa-solid fa-screwdriver-wrench" aria-hidden="true"></i>
            Hardening
        </button>
    </div>
);

export default ResultHardeningBar;
