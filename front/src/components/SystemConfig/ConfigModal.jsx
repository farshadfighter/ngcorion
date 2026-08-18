import React from "react";

/**
 * Shared shell for the six configuration dialogs: title bar with a close X, a
 * scrollable body, and a footer whose primary button is the save action.
 *
 * The Figma labels that button "Next"; it saves and closes, so it is labelled
 * "Save" here — the dialogs are independent, not steps in a wizard.
 */
export const ConfigModal = ({
    title,
    children,
    onClose,
    onSave,
    isSaving,
    isLoading,
    error,
    warning,
    saveLabel = "Save",
    saveDisabled = false,
}) => (
    <div className="modal-overlay" onClick={onClose}>
        <div className="sc-modal" onClick={(e) => e.stopPropagation()}>
            <div className="sc-modal-header">
                <h3>{title}</h3>
                <button
                    type="button"
                    className="sc-modal-close"
                    onClick={onClose}
                    aria-label="Close"
                >
                    <i className="fa-solid fa-xmark" />
                </button>
            </div>

            <div className="sc-modal-body">
                {isLoading ? (
                    <p className="sc-state">Loading…</p>
                ) : (
                    <>
                        {children}
                        {error && <p className="sc-error">{error}</p>}
                        {/* Saved, but the host-level apply step reported a
                            problem — distinct from a failed save. */}
                        {warning && <p className="sc-warning">{warning}</p>}
                    </>
                )}
            </div>

            <div className="sc-modal-footer">
                <button
                    type="button"
                    className="sc-btn sc-btn-ghost"
                    onClick={onClose}
                    disabled={isSaving}
                >
                    Cancel
                </button>
                <button
                    type="button"
                    className="sc-btn sc-btn-primary"
                    onClick={onSave}
                    disabled={isSaving || isLoading || saveDisabled}
                >
                    {isSaving ? (
                        <>
                            <i className="fa-solid fa-spinner fa-spin" /> Saving…
                        </>
                    ) : (
                        saveLabel
                    )}
                </button>
            </div>
        </div>
    </div>
);

export default ConfigModal;
