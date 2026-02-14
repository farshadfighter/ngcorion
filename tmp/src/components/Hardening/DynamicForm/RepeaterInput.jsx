/**
 * RepeaterInput - Repeating field groups for array of objects
 *
 * Supports nested fields with their own types and dependencies.
 */

import { useMemo } from 'react';
import InputRenderer from './InputRenderer';

/**
 * Check if a nested field's dependency is met within the item
 */
const isNestedDependencyMet = (dependsOn, itemValues) => {
    if (!dependsOn) return true;

    if (dependsOn.field) {
        const fieldValue = itemValues[dependsOn.field];

        if (dependsOn.equals !== undefined) {
            return fieldValue === dependsOn.equals;
        }

        if (dependsOn.not_equals !== undefined) {
            return fieldValue !== dependsOn.not_equals;
        }
    }

    return true;
};

const RepeaterInput = ({
    input,
    value,
    onChange,
    error,
    disabled = false,
    allValues = {},
    sharedFieldValues = {},
}) => {
    const items = Array.isArray(value) ? value : [];
    const itemSchema = input.item_schema;
    const fields = itemSchema?.fields || [];

    // Add new empty item
    const handleAddItem = () => {
        const newItem = {};
        // Initialize with defaults
        fields.forEach(field => {
            if (field.default !== undefined) {
                newItem[field.name] = field.default;
            }
        });
        onChange([...items, newItem]);
    };

    // Remove item at index
    const handleRemoveItem = (index) => {
        const newItems = items.filter((_, i) => i !== index);
        onChange(newItems);
    };

    // Update field in item
    const handleFieldChange = (index, fieldName, fieldValue) => {
        const newItems = [...items];
        newItems[index] = {
            ...newItems[index],
            [fieldName]: fieldValue,
        };
        onChange(newItems);
    };

    // Get error for a specific item field
    const getFieldError = (index, fieldName) => {
        if (!error) return null;
        // Error might be array of item errors or object with field keys
        if (typeof error === 'string') return null;
        const itemErrorKey = `${input.name}[${index}].${fieldName}`;
        return error[itemErrorKey];
    };

    return (
        <div className={`form-group repeater-input ${error && typeof error === 'string' ? 'has-error' : ''}`}>
            <label>
                {input.label || input.name}
                {input.required && <span className="required-marker"> *</span>}
            </label>

            {input.hint && (
                <small className="form-hint">{input.hint}</small>
            )}

            <div className="repeater-items">
                {items.map((item, index) => (
                    <div key={index} className="repeater-item">
                        <div className="repeater-item-header">
                            <span className="item-number">#{index + 1}</span>
                            <button
                                type="button"
                                className="btn btn-small btn-danger"
                                onClick={() => handleRemoveItem(index)}
                                disabled={disabled}
                            >
                                Remove
                            </button>
                        </div>
                        <div className="repeater-item-fields">
                            {fields.map(field => {
                                // Check nested dependency
                                if (!isNestedDependencyMet(field.depends_on, item)) {
                                    return null;
                                }

                                // Create input config from field definition
                                const fieldInput = {
                                    name: `${input.name}[${index}].${field.name}`,
                                    type: field.type,
                                    required: field.required,
                                    label: field.label || field.name,
                                    hint: field.hint,
                                    default: field.default,
                                    options: field.options,
                                    min: field.min,
                                    max: field.max,
                                };

                                return (
                                    <div key={field.name} className="repeater-field">
                                        <InputRenderer
                                            input={fieldInput}
                                            value={item[field.name]}
                                            onChange={(val) => handleFieldChange(index, field.name, val)}
                                            error={getFieldError(index, field.name)}
                                            disabled={disabled}
                                            allValues={item}
                                            sharedFieldValues={sharedFieldValues}
                                        />
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                ))}

                {items.length === 0 && (
                    <div className="repeater-empty">
                        No items added yet. Click "Add" to add an entry.
                    </div>
                )}
            </div>

            <button
                type="button"
                className="btn btn-secondary btn-small add-item-btn"
                onClick={handleAddItem}
                disabled={disabled}
            >
                + Add {input.label || 'Item'}
            </button>

            {error && typeof error === 'string' && (
                <small className="form-error">{error}</small>
            )}
        </div>
    );
};

export default RepeaterInput;
