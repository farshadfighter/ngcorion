/**
 * TextMultilineInput - Textarea for multiline text fields
 */

const TextMultilineInput = ({
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
            <textarea
                id={inputId}
                value={value || ''}
                onChange={(e) => onChange(e.target.value)}
                placeholder={input.hint || ''}
                disabled={disabled}
                rows={5}
                className={error ? 'input-error' : ''}
            />
            {input.hint && !error && (
                <small className="form-hint">{input.hint}</small>
            )}
            {error && (
                <small className="form-error">{error}</small>
            )}
        </div>
    );
};

export default TextMultilineInput;
