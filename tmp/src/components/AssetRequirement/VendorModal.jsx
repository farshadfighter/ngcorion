import { useState } from "react";
import { useDispatch } from "react-redux";
import { createVendor } from "../../store/requirementSlice";

export const VendorModal = ({ onClose }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        vendor_name: "",
        vendor_type: "",
    });

    const [errors, setErrors] = useState({});

    const validateForm = () => {
        const newErrors = {};

        if (!formData.vendor_name.trim()) {
            newErrors.vendor_name = "Vendor name is required";
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validateForm()) return;

        try {
            await dispatch(createVendor(formData)).unwrap();
            onClose();
        } catch (error) {
            console.error("Failed to create vendor:", error);
        }
    };

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));
        if (errors[name]) {
            setErrors((prev) => ({ ...prev, [name]: "" }));
        }
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content modal-small" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>Add Vendor</h2>
                    <button className="modal-close" onClick={onClose}>
                        ×
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="modal-body">
                    <div className="form-group">
                        <label>
                            Vendor Name <span className="required">*</span>
                        </label>
                        <input
                            type="text"
                            name="vendor_name"
                            value={formData.vendor_name}
                            onChange={handleChange}
                            placeholder="Enter vendor name"
                            className={errors.vendor_name ? "error" : ""}
                        />
                        {errors.vendor_name && (
                            <span className="error-message">{errors.vendor_name}</span>
                        )}
                    </div>

                    <div className="form-group">
                        <label>Vendor Type</label>
                        <input
                            type="text"
                            name="vendor_type"
                            value={formData.vendor_type}
                            onChange={handleChange}
                            placeholder="Enter vendor type (e.g., Hardware, Software)"
                        />
                    </div>

                    <div className="modal-footer">
                        <button type="button" className="btn-cancel" onClick={onClose}>
                            Cancel
                        </button>
                        <button type="submit" className="btn-submit">
                            Create
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};