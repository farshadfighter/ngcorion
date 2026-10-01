import React from "react";
import { t } from "../../i18n";

/**
 * Appears only once rows are ticked, so the toolbar stays quiet in the normal
 * case and the destructive action is never a click away by accident.
 */
export const BulkDeleteBar = ({ count, onDelete, onClear, isDeleting }) => {
    if (count === 0) return null;

    return (
        <div className="bulk-bar">
            <span className="bulk-bar-count">
                {t("{{count}} selected", { count })}
            </span>
            <div className="bulk-bar-actions">
                <button
                    type="button"
                    className="bulk-bar-clear"
                    onClick={onClear}
                    disabled={isDeleting}
                >
                    {t("Clear")}
                </button>
                <button
                    type="button"
                    className="bulk-bar-delete"
                    onClick={onDelete}
                    disabled={isDeleting}
                >
                    {isDeleting ? (
                        <>
                            <i className="fa-solid fa-spinner fa-spin" /> {" "}{t("Deleting…")}
                        </>
                    ) : (
                        <>
                            <i className="fa-solid fa-trash" /> {" "}{t("Delete selected")}
                        </>
                    )}
                </button>
            </div>
        </div>
    );
};

export default BulkDeleteBar;
