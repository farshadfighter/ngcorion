/**
 * IntInput - Number input with min/max validation
 */

const IntInput = ({
    input,
    value,
    onChange,
    error,
    disabled = false,
}) => {
    const inputId = `input-${input.name}`;

    const handleChange = (e) => {
        const val = e.target.value;
        // Allow empty string for clearing
        if (val === '') {
            onChange('');
        } else {
            const num = parseInt(val, 10);
            if (!isNaN(num)) {
                onChange(num);
            }
        }
    };

    return (
        <div className={`form-group ${error ? 'has-error' : ''}`}>
            <label htmlFor={inputId}>
                {input.label || input.name}
                {input.required && <span className="required-marker"> *</span>}
            </label>
            <input
                type="number"
                id={inputId}
                value={value ?? (input.default ?? '')}
                onChange={handleChange}
                min={input.min}
                max={input.max}
                placeholder={input.hint || ''}
                disabled={disabled}
                className={error ? 'input-error' : ''}
            />
            {(input.min !== undefined || input.max !== undefined) && (
                <small className="form-hint">
                    Range: {input.min ?? 'N/A'} - {input.max ?? 'N/A'}
                </small>
            )}
            {input.hint && (
                <small className="form-hint">{input.hint}</small>
            )}
            {error && (
                <small className="form-error">{error}</small>
            )}
        </div>
    );
};

export default IntInput;
