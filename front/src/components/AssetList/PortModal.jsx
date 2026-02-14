import React, { useState, useEffect } from "react";
import { useDispatch } from "react-redux";
import { createAssetPort, updateAssetPort, fetchAssetPorts } from "../../store/assetSlice";

export const PortModal = ({ asset, port, onClose }) => {
    const dispatch = useDispatch();
    const [formData, setFormData] = useState({
        protocol: "TCP",
        port_number: "",
    });
    const [errors, setErrors] = useState({});
    const [isSubmitting, setIsSubmitting] = useState(false);

    useEffect(() => {
        if (port) {
            setFormData({
                protocol: port.protocol,
                port_number: port.port_number,
            });
        }
    }, [port]);

    const validateForm = () => {
        const newErrors = {};

        if (!formData.port_number) {
            newErrors.port_number = "Port number is required";
        } else {
            const portNum = parseInt(formData.port_number);
            if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
                newErrors.port_number = "Port must be between 1 and 65535";
            }
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validateForm()) return;

        setIsSubmitting(true);

        const portData = {
            protocol: formData.protocol,
            port_number: parseInt(formData.port_number),
        };

        try {
            if (port) {
                // Edit existing port
                await dispatch(updateAssetPort({
                    assetId: asset.id,
                    portId: port.id,
                    portData
                })).unwrap();
            } else {
                // Add new port
                await dispatch(createAssetPort({
                    assetId: asset.id,
                    portData
                })).unwrap();
            }


            // Refresh ports list
            await dispatch(fetchAssetPorts(asset.id));

            onClose();
        } catch (error) {
            console.error("❌ Failed to save port:", error);
            setErrors({ submit: error.message || "Failed to save port" });
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
        if (errors[name]) {
            setErrors(prev => ({ ...prev, [name]: "" }));
        }
    };

    return (
        <div
            style={{
                position: 'fixed',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                background: 'rgba(0, 0, 0, 0.6)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 10001  // بالاتر از ManagePortsModal
            }}
            onClick={(e) => {
                if (e.target === e.currentTarget) onClose();
            }}
        >
            <div
                style={{
                    background: 'white',
                    borderRadius: '12px',
                    width: '90%',
                    maxWidth: '450px',
                    boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.2)'
                }}
                onClick={(e) => e.stopPropagation()}
            >
                {/* Header */}
                <div style={{
                    padding: '20px 24px',
                    borderBottom: '1px solid #e5e7eb',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between'
                }}>
                    <h3 style={{
                        fontSize: '16px',
                        fontWeight: '600',
                        color: '#111827',
                        margin: 0
                    }}>
                        {port ? "Edit Port" : "Add Port"}
                    </h3>
                    <button
                        onClick={onClose}
                        style={{
                            background: 'none',
                            border: 'none',
                            padding: '4px',
                            cursor: 'pointer',
                            color: '#6b7280',
                            display: 'flex',
                            alignItems: 'center'
                        }}
                    >
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M18 6L6 18M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                {/* Form */}
                <form onSubmit={handleSubmit}>
                    <div style={{ padding: '24px' }}>
                        {/* Protocol Field */}
                        <div style={{ marginBottom: '20px' }}>
                            <label
                                htmlFor="protocol"
                                style={{
                                    display: 'block',
                                    fontSize: '14px',
                                    fontWeight: '500',
                                    color: '#374151',
                                    marginBottom: '8px'
                                }}
                            >
                                Protocol
                            </label>
                            <select
                                id="protocol"
                                name="protocol"
                                value={formData.protocol}
                                onChange={handleChange}
                                style={{
                                    width: '100%',
                                    padding: '10px 12px',
                                    border: '1px solid #d1d5db',
                                    borderRadius: '8px',
                                    fontSize: '14px',
                                    color: '#111827',
                                    background: 'white',
                                    cursor: 'pointer',
                                    outline: 'none'
                                }}
                            >
                                <option value="TCP">TCP</option>
                                <option value="UDP">UDP</option>
                            </select>
                        </div>

                        {/* Port Number Field */}
                        <div style={{ marginBottom: '8px' }}>
                            <label
                                htmlFor="port_number"
                                style={{
                                    display: 'block',
                                    fontSize: '14px',
                                    fontWeight: '500',
                                    color: '#374151',
                                    marginBottom: '8px'
                                }}
                            >
                                Port Number <span style={{ color: '#ef4444' }}>*</span>
                            </label>
                            <input
                                type="number"
                                id="port_number"
                                name="port_number"
                                value={formData.port_number}
                                onChange={handleChange}
                                placeholder="e.g., 8000"
                                min="1"
                                max="65535"
                                style={{
                                    width: '100%',
                                    padding: '10px 12px',
                                    border: `1px solid ${errors.port_number ? '#ef4444' : '#d1d5db'}`,
                                    borderRadius: '8px',
                                    fontSize: '14px',
                                    color: '#111827',
                                    outline: 'none',
                                    boxSizing: 'border-box'
                                }}
                            />
                            {errors.port_number && (
                                <p style={{
                                    margin: '6px 0 0 0',
                                    fontSize: '13px',
                                    color: '#ef4444'
                                }}>
                                    {errors.port_number}
                                </p>
                            )}
                        </div>

                        {/* Submit Error */}
                        {errors.submit && (
                            <div style={{
                                marginTop: '16px',
                                padding: '12px 16px',
                                background: '#fef2f2',
                                border: '1px solid #fca5a5',
                                borderRadius: '8px',
                                color: '#dc2626',
                                fontSize: '13px'
                            }}>
                                {errors.submit}
                            </div>
                        )}
                    </div>

                    {/* Footer */}
                    <div style={{
                        padding: '16px 24px',
                        borderTop: '1px solid #e5e7eb',
                        display: 'flex',
                        gap: '12px',
                        justifyContent: 'flex-end'
                    }}>
                        <button
                            type="button"
                            onClick={onClose}
                            disabled={isSubmitting}
                            style={{
                                background: 'white',
                                color: '#6b7280',
                                border: '1px solid #d1d5db',
                                padding: '10px 20px',
                                borderRadius: '8px',
                                fontSize: '14px',
                                fontWeight: '500',
                                cursor: isSubmitting ? 'not-allowed' : 'pointer',
                                opacity: isSubmitting ? 0.6 : 1
                            }}
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            disabled={isSubmitting}
                            style={{
                                background: isSubmitting ? '#9ca3af' : '#1e3a5f',
                                color: 'white',
                                border: 'none',
                                padding: '10px 20px',
                                borderRadius: '8px',
                                fontSize: '14px',
                                fontWeight: '500',
                                cursor: isSubmitting ? 'not-allowed' : 'pointer',
                                minWidth: '80px'
                            }}
                        >
                            {isSubmitting ? 'Saving...' : (port ? 'Update' : 'Add')}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};