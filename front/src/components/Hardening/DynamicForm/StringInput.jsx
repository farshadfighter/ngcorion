/**
 * StringInput - Text input for string fields
 */

const StringInput = ({
    input,
    value,
    onChange,
    error,
    disabled = false,
}) => {
    const inputId = `input-${input.name}`;

    return (
        <div className={`form-group ${error ? 'has-error' : ''}`}>
            <label htmlFor={inputId}>
                {input.label || input.name}
                {input.required && <span className="required-marker"> *</span>}
            </label>
            <input
                type="text"
                id={inputId}
                value={value || ''}
                onChange={(e) => onChange(e.target.value)}
                placeholder={input.hint || ''}
                disabled={disabled}
                className={error ? 'input-error' : ''}
            />
            {input.hint && !error && (
                <small className="form-hint">{input.hint}</small>
            )}
            {input.default !== undefined && input.default !== null && (
                <small className="form-hint default-hint">
                    Default: {String(input.default)}
                </small>
            )}
            {error && (
                <small className="form-error">{error}</small>
            )}
        </div>
    );
};

export default StringInput;
