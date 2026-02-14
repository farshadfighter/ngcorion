/**
 * EnumInput - Single-select dropdown for enum fields
 */

const EnumInput = ({
    input,
    value,
    onChange,
    error,
    disabled = false,
}) => {
    const inputId = `input-${input.name}`;
    const options = input.options || [];

    return (
        <div className={`form-group ${error ? 'has-error' : ''}`}>
            <label htmlFor={inputId}>
                {input.label || input.name}
                {input.required && <span className="required-marker"> *</span>}
            </label>
            <select
                id={inputId}
                value={value || input.default || ''}
                onChange={(e) => onChange(e.target.value)}
                disabled={disabled}
                className={error ? 'input-error' : ''}
            >
                <option value="">-- Select --</option>
                {options.map(option => (
                    <option key={option} value={option}>
                        {option}
                    </option>
                ))}
            </select>
            {input.hint && !error && (
                <small className="form-hint">{input.hint}</small>
            )}
            {error && (
                <small className="form-error">{error}</small>
            )}
        </div>
    );
};

export default EnumInput;
