/**
 * BoolInput - Toggle/checkbox for boolean fields
 */

const BoolInput = ({
    input,
    value,
    onChange,
    error,
    disabled = false,
}) => {
    const inputId = `input-${input.name}`;
    const isChecked = value === true || value === 'true';

    return (
        <div className={`form-group bool-input ${error ? 'has-error' : ''}`}>
            <label className="checkbox-label">
                <input
                    type="checkbox"
                    id={inputId}
                    checked={isChecked}
                    onChange={(e) => onChange(e.target.checked)}
                    disabled={disabled}
                />
                <span className="checkbox-text">
                    {input.label || input.name}
                    {input.required && <span className="required-marker"> *</span>}
                </span>
            </label>
            {input.hint && !error && (
                <small className="form-hint">{input.hint}</small>
            )}
            {input.default !== undefined && (
                <small className="form-hint default-hint">
                    Default: {input.default ? 'Yes' : 'No'}
                </small>
            )}
            {error && (
                <small className="form-error">{error}</small>
            )}
        </div>
    );
};

export default BoolInput;
