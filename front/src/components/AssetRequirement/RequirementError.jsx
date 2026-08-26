import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";

import { clearMessages } from "../../store/requirementSlice";

/**
 * Surfaces failures from the requirement tabs' add/edit/delete calls.
 *
 * Without this the thunks reject into the store and nothing renders it, so a
 * refused delete looks exactly like a click that did nothing — which is what
 * "I can't delete anything" turned out to be.
 */
export const RequirementError = () => {
    const dispatch = useDispatch();
    const error = useSelector((state) => state.requirements.error);

    // Transient: clear it so a stale message does not outlive the next action.
    useEffect(() => {
        if (!error) return;
        const timer = setTimeout(() => dispatch(clearMessages()), 6000);
        return () => clearTimeout(timer);
    }, [error, dispatch]);

    if (!error) return null;

    const text = typeof error === "string" ? error : "Request failed";
    // A 403 arrives as a bare detail string; say what to do about it.
    const isPermission = /permission|not authorized|forbidden|admin/i.test(text);

    return (
        <div className="requirement-error" role="alert">
            <i className="fa-solid fa-circle-exclamation" aria-hidden="true" />
            <span>
                {text}
                {isPermission && " — this action needs an administrator account."}
            </span>
            <button
                type="button"
                className="requirement-error-close"
                onClick={() => dispatch(clearMessages())}
                aria-label="Dismiss"
            >
                ×
            </button>
        </div>
    );
};

export default RequirementError;
