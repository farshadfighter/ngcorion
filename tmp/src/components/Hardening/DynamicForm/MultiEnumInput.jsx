/**
 * MultiEnumInput - Multi-select checkboxes
 */

const MultiEnumInput = ({
    input,
    value,
    onChange,
    error,
    disabled = false,
}) => {
    const options = input.options || [];
    const selectedValues = Array.isArray(value) ? value : [];

    const handleToggle = (option) => {
        if (selectedValues.includes(option)) {
            onChange(selectedValues.filter(v => v !== option));
        } else {
            onChange([...selectedValues, option]);
        }
    };

    const handleSelectAll = () => {
        onChange([...options]);
    };

    const handleClearAll = () => {
        onChange([]);
    };

    return (
        <div className={`form-group multi-enum-input ${error ? 'has-error' : ''}`}>
            <label>
                {input.label || input.name}
                {input.required && <span className="required-marker"> *</span>}
            </label>

            {input.hint && (
                <small className="form-hint">{input.hint}</small>
            )}

            <div className="multi-enum-actions">
                <button
                    type="button"
                    className="link-btn"
                    onClick={handleSelectAll}
                    disabled={disabled}
                >
                    Select All
                </button>
                <span className="separator">|</span>
                <button
                    type="button"
                    className="link-btn"
                    onClick={handleClearAll}
                    disabled={disabled}
                >
                    Clear All
                </button>
            </div>

            <div className="multi-enum-options">
                {options.map(option => (
                    <label key={option} className="checkbox-option">
                        <input
                            type="checkbox"
                            checked={selectedValues.includes(option)}
                            onChange={() => handleToggle(option)}
                            disabled={disabled}
                        />
                        <span>{option}</span>
                    </label>
                ))}
            </div>

            {selectedValues.length > 0 && (
                <small className="form-hint">
                    Selected: {selectedValues.join(', ')}
                </small>
            )}

            {error && (
                <small className="form-error">{error}</small>
            )}
        </div>
    );
};

export default MultiEnumInput;
