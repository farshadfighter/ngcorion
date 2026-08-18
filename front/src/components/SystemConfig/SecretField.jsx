import React from "react";

/** What the backend returns in place of a stored secret. Sending it back
 *  unchanged keeps the stored value (the routers call service.unmask). */
export const MASK = "********";

/**
 * Password input that will not silently discard a stored secret.
 *
 * While the value is still the server's mask the input is read-only and a
 * "Change" button sits beside it; only pressing that clears the field for a new
 * value. Clearing on focus instead would wipe the real password whenever
 * someone merely tabbed through the field.
 */
export const SecretField = ({ label, value, onChange, maxLength = 255 }) => {
    const masked = value === MASK;

    return (
        <label className="sc-field">
            <span>{label}</span>
            <div className="sc-secret">
                <input
                    type="password"
                    value={value}
                    onChange={(e) => onChange(e.target.value)}
                    readOnly={masked}
                    maxLength={maxLength}
                    autoComplete="new-password"
                />
                {masked && (
                    <button
                        type="button"
                        className="sc-secret-btn"
                        onClick={() => onChange("")}
                    >
                        Change
                    </button>
                )}
            </div>
        </label>
    );
};

export default SecretField;
