/**
 * OrderedMultiEnumInput - Drag-and-drop ordered multi-select
 *
 * Selected items can be reordered. Order matters for the final value.
 */

import { useState } from 'react';

const OrderedMultiEnumInput = ({
    input,
    value,
    onChange,
    error,
    disabled = false,
}) => {
    const options = input.options || [];
    const selectedValues = Array.isArray(value) ? value : [];
    const [draggedIndex, setDraggedIndex] = useState(null);

    // Add option to selected
    const handleAdd = (option) => {
        if (!selectedValues.includes(option)) {
            onChange([...selectedValues, option]);
        }
    };

    // Remove from selected
    const handleRemove = (option) => {
        onChange(selectedValues.filter(v => v !== option));
    };

    // Move item up in order
    const handleMoveUp = (index) => {
        if (index === 0) return;
        const newValues = [...selectedValues];
        [newValues[index - 1], newValues[index]] = [newValues[index], newValues[index - 1]];
        onChange(newValues);
    };

    // Move item down in order
    const handleMoveDown = (index) => {
        if (index === selectedValues.length - 1) return;
        const newValues = [...selectedValues];
        [newValues[index], newValues[index + 1]] = [newValues[index + 1], newValues[index]];
        onChange(newValues);
    };

    // Drag and drop handlers
    const handleDragStart = (e, index) => {
        setDraggedIndex(index);
        e.dataTransfer.effectAllowed = 'move';
    };

    const handleDragOver = (e, index) => {
        e.preventDefault();
        if (draggedIndex === null || draggedIndex === index) return;
    };

    const handleDrop = (e, dropIndex) => {
        e.preventDefault();
        if (draggedIndex === null || draggedIndex === dropIndex) {
            setDraggedIndex(null);
            return;
        }

        const newValues = [...selectedValues];
        const [removed] = newValues.splice(draggedIndex, 1);
        newValues.splice(dropIndex, 0, removed);
        onChange(newValues);
        setDraggedIndex(null);
    };

    const handleDragEnd = () => {
        setDraggedIndex(null);
    };

    // Available options (not yet selected)
    const availableOptions = options.filter(opt => !selectedValues.includes(opt));

    return (
        <div className={`form-group ordered-multi-enum-input ${error ? 'has-error' : ''}`}>
            <label>
                {input.label || input.name}
                {input.required && <span className="required-marker"> *</span>}
            </label>

            {input.hint && (
                <small className="form-hint">{input.hint}</small>
            )}

            <div className="ordered-multi-container">
                {/* Available Options */}
                <div className="available-options">
                    <div className="section-title">Available</div>
                    <div className="options-list">
                        {availableOptions.map(option => (
                            <div key={option} className="option-item available">
                                <span>{option}</span>
                                <button
                                    type="button"
                                    className="add-btn"
                                    onClick={() => handleAdd(option)}
                                    disabled={disabled}
                                    title="Add"
                                >
                                    +
                                </button>
                            </div>
                        ))}
                        {availableOptions.length === 0 && (
                            <div className="empty-list">All options selected</div>
                        )}
                    </div>
                </div>

                {/* Arrow */}
                <div className="arrow-separator">→</div>

                {/* Selected Options (ordered) */}
                <div className="selected-options">
                    <div className="section-title">Selected (in order)</div>
                    <div className="options-list">
                        {selectedValues.map((option, index) => (
                            <div
                                key={option}
                                className={`option-item selected ${draggedIndex === index ? 'dragging' : ''}`}
                                draggable={!disabled}
                                onDragStart={(e) => handleDragStart(e, index)}
                                onDragOver={(e) => handleDragOver(e, index)}
                                onDrop={(e) => handleDrop(e, index)}
                                onDragEnd={handleDragEnd}
                            >
                                <span className="drag-handle" title="Drag to reorder">⋮⋮</span>
                                <span className="order-number">{index + 1}.</span>
                                <span className="option-text">{option}</span>
                                <div className="option-actions">
                                    <button
                                        type="button"
                                        className="move-btn"
                                        onClick={() => handleMoveUp(index)}
                                        disabled={disabled || index === 0}
                                        title="Move up"
                                    >
                                        ↑
                                    </button>
                                    <button
                                        type="button"
                                        className="move-btn"
                                        onClick={() => handleMoveDown(index)}
                                        disabled={disabled || index === selectedValues.length - 1}
                                        title="Move down"
                                    >
                                        ↓
                                    </button>
                                    <button
                                        type="button"
                                        className="remove-btn"
                                        onClick={() => handleRemove(option)}
                                        disabled={disabled}
                                        title="Remove"
                                    >
                                        ×
                                    </button>
                                </div>
                            </div>
                        ))}
                        {selectedValues.length === 0 && (
                            <div className="empty-list">No options selected</div>
                        )}
                    </div>
                </div>
            </div>

            {selectedValues.length > 0 && (
                <small className="form-hint order-preview">
                    Order: {selectedValues.join(' → ')}
                </small>
            )}

            {error && (
                <small className="form-error">{error}</small>
            )}
        </div>
    );
};

export default OrderedMultiEnumInput;
