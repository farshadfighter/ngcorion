/**
 * DynamicForm - Main form container with dependency resolution
 *
 * Renders control inputs dynamically based on schema definitions.
 * Handles conditional field visibility and ref resolution.
 */

import { useMemo, useCallback } from 'react';
import InputRenderer from './InputRenderer';

/**
 * Check if a field's dependency is met
 */
const isDependencyMet = (dependsOn, values, sharedFields = {}) => {
    if (!dependsOn) return true;

    // Simple field equals/not_equals dependency
    if (dependsOn.field) {
        const fieldValue = values[dependsOn.field] ?? sharedFields[dependsOn.field];

        if (dependsOn.equals !== undefined) {
            return fieldValue === dependsOn.equals;
        }

        if (dependsOn.not_equals !== undefined) {
            return fieldValue !== dependsOn.not_equals;
        }
    }

    // Array includes any check
    if (dependsOn.any_in && dependsOn.values_include_any) {
        for (const fieldName of dependsOn.any_in) {
            const fieldValue = values[fieldName] ?? sharedFields[fieldName];
            if (Array.isArray(fieldValue)) {
                for (const checkVal of dependsOn.values_include_any) {
                    if (fieldValue.includes(checkVal)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    return true;
};

/**
 * Resolve ref type inputs to their shared field definition
 */
const resolveInput = (input, sharedFields) => {
    if (input.type === 'ref' && input.ref) {
        const parts = input.ref.split('.');
        if (parts.length === 2 && parts[0] === 'shared_fields') {
            const sharedField = sharedFields.find(sf => sf.name === parts[1]);
            if (sharedField) {
                return {
                    ...input,
                    type: sharedField.type,
                    label: input.label || sharedField.label,
                    hint: sharedField.hint,
                    default: sharedField.default,
                    options: sharedField.options,
                    _isSharedField: true,
                    _sharedFieldName: parts[1],
                };
            }
        }
    }
    return input;
};

export const DynamicForm = ({
    inputs = [],
    values = {},
    onChange,
    sharedFields = [],
    sharedFieldValues = {},
    onSharedFieldChange,
    errors = {},
    disabled = false,
    controlId = null,
}) => {
    // Resolve all inputs (handle ref types)
    const resolvedInputs = useMemo(() => {
        return inputs.map(input => resolveInput(input, sharedFields));
    }, [inputs, sharedFields]);

    // Handle value changes
    const handleChange = useCallback((inputName, value, isSharedField = false) => {
        if (isSharedField && onSharedFieldChange) {
            onSharedFieldChange(inputName, value);
        } else if (onChange) {
            onChange(inputName, value);
        }
    }, [onChange, onSharedFieldChange]);

    // Filter visible inputs based on dependencies
    const visibleInputs = useMemo(() => {
        return resolvedInputs.filter(input => {
            return isDependencyMet(input.depends_on, values, sharedFieldValues);
        });
    }, [resolvedInputs, values, sharedFieldValues]);

    if (visibleInputs.length === 0) {
        return (
            <div className="dynamic-form-empty">
                <p className="no-inputs-message">No configuration required for this control.</p>
            </div>
        );
    }

    return (
        <div className="dynamic-form">
            {visibleInputs.map(input => {
                const isSharedField = input._isSharedField;
                const inputValue = isSharedField
                    ? sharedFieldValues[input._sharedFieldName]
                    : values[input.name];
                const inputError = errors[input.name];

                return (
                    <div key={input.name} className="dynamic-form-field">
                        <InputRenderer
                            input={input}
                            value={inputValue}
                            onChange={(value) => handleChange(
                                isSharedField ? input._sharedFieldName : input.name,
                                value,
                                isSharedField
                            )}
                            error={inputError}
                            disabled={disabled}
                            allValues={values}
                            sharedFieldValues={sharedFieldValues}
                            controlId={controlId}
                        />
                    </div>
                );
            })}
        </div>
    );
};

export default DynamicForm;
