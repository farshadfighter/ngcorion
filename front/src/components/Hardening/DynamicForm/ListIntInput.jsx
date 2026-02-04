/**
 * ListIntInput - Add/remove list of integers
 *
 * Supports min/max validation for each item.
 */

import { useState } from 'react';

const ListIntInput = ({
    input,
    value,
    onChange,
    error,
    disabled = false,
}) => {
    const [newItem, setNewItem] = useState('');
    const [itemError, setItemError] = useState(null);
    const items = Array.isArray(value) ? value : [];
    const validation = input.item_validation || {};

    const handleAddItem = () => {
        if (!newItem.trim()) return;

        const num = parseInt(newItem.trim(), 10);
        if (isNaN(num)) {
            setItemError('Must be a valid integer');
            return;
        }

        // Validate min/max
        if (validation.min !== undefined && num < validation.min) {
            setItemError(`Must be at least ${validation.min}`);
            return;
        }
        if (validation.max !== undefined && num > validation.max) {
            setItemError(`Must be at most ${validation.max}`);
            return;
        }

        // Check for duplicates
        if (items.includes(num)) {
            setItemError('Value already exists');
            return;
        }

        onChange([...items, num]);
        setNewItem('');
        setItemError(null);
    };

    const handleRemoveItem = (index) => {
        const newItems = items.filter((_, i) => i !== index);
        onChange(newItems);
    };

    const handleKeyPress = (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            handleAddItem();
        }
    };

    // Get placeholder based on validation
    const getPlaceholder = () => {
        if (input.hint) return input.hint;
        if (validation.min !== undefined && validation.max !== undefined) {
            return `Enter number (${validation.min}-${validation.max})`;
        }
        return 'Enter number and press Enter';
    };

    return (
        <div className={`form-group list-int-input ${error ? 'has-error' : ''}`}>
            <label>
                {input.label || input.name}
                {input.required && <span className="required-marker"> *</span>}
            </label>

            {input.hint && (
                <small className="form-hint">{input.hint}</small>
            )}

            <div className="list-items">
                {items.map((item, index) => (
                    <div key={index} className="list-item">
                        <span className="item-value">{item}</span>
                        <button
                            type="button"
                            className="remove-item-btn"
                            onClick={() => handleRemoveItem(index)}
                            disabled={disabled}
                            title="Remove"
                        >
                            ×
                        </button>
                    </div>
                ))}
            </div>

            <div className="list-input-row">
                <input
                    type="number"
                    value={newItem}
                    onChange={(e) => {
                        setNewItem(e.target.value);
                        setItemError(null);
                    }}
                    onKeyPress={handleKeyPress}
                    placeholder={getPlaceholder()}
                    disabled={disabled}
                    min={validation.min}
                    max={validation.max}
                    className={itemError ? 'input-error' : ''}
                />
                <button
                    type="button"
                    className="btn btn-secondary btn-small"
                    onClick={handleAddItem}
                    disabled={disabled || !newItem.trim()}
                >
                    Add
                </button>
            </div>

            {itemError && (
                <small className="form-error">{itemError}</small>
            )}

            {error && typeof error === 'string' && (
                <small className="form-error">{error}</small>
            )}

            {validation.min !== undefined && validation.max !== undefined && (
                <small className="form-hint">
                    Valid range: {validation.min} - {validation.max}
                </small>
            )}

            {items.length === 0 && !error && !itemError && (
                <small className="form-hint empty-list-hint">
                    No items added yet
                </small>
            )}
        </div>
    );
};

export default ListIntInput;
