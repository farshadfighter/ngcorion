import { useState } from "react";
import { useDispatch } from "react-redux";
import { createOS } from "../../store/requirementSlice";

export const OSCatalogModal = ({ onClose }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        os_name: "",
    });

    const [errors, setErrors] = useState({});

    const validateForm = () => {
        const newErrors = {};

        if (!formData.os_name.trim()) {
            newErrors.os_name = "OS name is required";
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (!validateForm()) return;

        try {
            await dispatch(createOS(formData)).unwrap();
            onClose();
        } catch (error) {
            console.error("Failed to create OS:", error);
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
                    <h2>Add OS</h2>
                    <button className="modal-close" onClick={onClose}>
                        ×
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="modal-body">
                    <div className="form-group">
                        <label>
                            OS Name <span className="required">*</span>
                        </label>
                        <input
                            type="text"
                            name="os_name"
                            value={formData.os_name}
                            onChange={handleChange}
                            placeholder="Enter OS name (e.g., Ubuntu 22.04, Windows Server 2022)"
                            className={errors.os_name ? "error" : ""}
                        />
                        {errors.os_name && (
                            <span className="error-message">{errors.os_name}</span>
                        )}
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