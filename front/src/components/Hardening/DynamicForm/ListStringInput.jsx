/**
 * ListStringInput - Add/remove list of strings
 *
 * Supports item validation for IP addresses, CIDR, etc.
 */

import { useState } from 'react';

// Validation patterns
const IP_PATTERN = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const CIDR_PATTERN = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$/;
const FQDN_PATTERN = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$/;

const validateItem = (value, validation) => {
    if (!validation || !validation.type) return null;

    switch (validation.type) {
        case 'ip_address':
            if (!IP_PATTERN.test(value)) {
                return 'Must be a valid IP address';
            }
            break;

        case 'cidr_or_ip':
            if (!CIDR_PATTERN.test(value)) {
                return 'Must be a valid IP address or CIDR notation';
            }
            break;

        case 'ip_or_fqdn':
            if (!IP_PATTERN.test(value) && !FQDN_PATTERN.test(value)) {
                return 'Must be a valid IP address or hostname';
            }
            break;
    }

    return null;
};

const ListStringInput = ({
    input,
    value,
    onChange,
    error,
    disabled = false,
}) => {
    const [newItem, setNewItem] = useState('');
    const [itemError, setItemError] = useState(null);
    const items = Array.isArray(value) ? value : [];

    const handleAddItem = () => {
        if (!newItem.trim()) return;

        // Validate the new item
        const validationError = validateItem(newItem.trim(), input.item_validation);
        if (validationError) {
            setItemError(validationError);
            return;
        }

        // Check for duplicates
        if (items.includes(newItem.trim())) {
            setItemError('Item already exists');
            return;
        }

        onChange([...items, newItem.trim()]);
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

    // Get placeholder based on validation type
    const getPlaceholder = () => {
        if (input.hint) return input.hint;
        if (input.item_validation?.type === 'ip_address') return 'e.g., 192.168.1.1';
        if (input.item_validation?.type === 'cidr_or_ip') return 'e.g., 10.0.0.0/24';
        if (input.item_validation?.type === 'ip_or_fqdn') return 'e.g., server.example.com';
        return 'Enter value and press Enter';
    };

    return (
        <div className={`form-group list-string-input ${error ? 'has-error' : ''}`}>
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
                    type="text"
                    value={newItem}
                    onChange={(e) => {
                        setNewItem(e.target.value);
                        setItemError(null);
                    }}
                    onKeyPress={handleKeyPress}
                    placeholder={getPlaceholder()}
                    disabled={disabled}
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

            {items.length === 0 && !error && (
                <small className="form-hint empty-list-hint">
                    No items added yet
                </small>
            )}
        </div>
    );
};

export default ListStringInput;
